#!/usr/bin/env python3
"""
NASL nbin Decompiler
====================
Converts compiled .nbin bytecode back to readable NASL pseudocode.

Requires nasl_vm.py in the same directory (or sys.path).

Usage:
    python3 nasl_decompiler.py <file.nbin> [options]

Options:
    --raw         Show raw instruction listing alongside decompiled output
    --functions   Show function boundaries
    --verbose     Show extra annotation comments
"""

import sys
import struct
import zlib
from pathlib import Path
from collections import defaultdict

try:
    from .nasl_vm import NbinFile, OPCODES, ADDR_MODES, VALUE_TYPES
except ImportError:
    # fallback for direct script execution
    sys.path.insert(0, str(Path(__file__).parent))
    from nasl_vm import NbinFile, OPCODES, ADDR_MODES, VALUE_TYPES

# ── Builtin function ID → name mapping ────────────────────────────────────────
# Ground truth: extracted from /opt/nessus/bin/nasl registration table at
# ELF VMA 0x00ee2cc0 via RELA relocation parsing.  564 entries, 100% coverage.
# Format: builtin_index (= func_id & 0x0fffffff) → name
BUILTIN_NAMES = {
    0x001: "script_name",
    0x002: "script_version",
    0x003: "script_timeout",
    0x004: "script_description",
    0x005: "script_copyright",
    0x006: "script_summary",
    0x007: "script_category",
    0x008: "script_family",
    0x009: "script_dependencie",
    0x00a: "script_dependencies",
    0x00b: "script_require_keys",
    0x00c: "script_require_ports",
    0x00d: "script_require_udp_ports",
    0x00e: "script_exclude_keys",
    0x00f: "script_add_preference",
    0x010: "script_get_preference",
    0x011: "script_get_preference_file_content",
    0x012: "script_get_preference_file_location",
    0x013: "script_id",
    0x014: "script_cve_id",
    0x015: "script_bugtraq_id",
    0x016: "script_xref",
    0x017: "get_preference",
    0x018: "safe_checks",
    0x019: "replace_kb_item",
    0x01a: "set_kb_item",
    0x01b: "get_kb_item",
    0x01c: "get_kb_fresh_item",
    0x01d: "get_kb_list",
    0x01e: "security_warning",
    0x01f: "security_note",
    0x020: "security_hole",
    0x021: "scanner_add_port",
    0x022: "scanner_status",
    0x023: "scanner_get_port",
    0x024: "open_sock_tcp",
    0x025: "open_sock_udp",
    0x026: "open_priv_sock_tcp",
    0x027: "open_priv_sock_udp",
    0x028: "recv",
    0x029: "recv_line",
    0x02a: "send",
    0x02b: "close",
    0x02c: "join_multicast_group",
    0x02d: "leave_multicast_group",
    0x02e: "get_source_port",
    0x02f: "cgibin",
    0x030: "is_cgi_installed",
    0x031: "http_open_socket",
    0x032: "http_head",
    0x033: "http_get",
    0x034: "http_post",
    0x035: "http_delete",
    0x036: "http_put",
    0x037: "http_close_socket",
    0x038: "get_host_name",
    0x039: "get_host_ip",
    0x03a: "same_host",
    0x03b: "get_host_open_port",
    0x03c: "get_port_state",
    0x03d: "get_tcp_port_state",
    0x03e: "get_udp_port_state",
    0x03f: "islocalhost",
    0x040: "islocalnet",
    0x041: "get_port_transport",
    0x042: "this_host",
    0x043: "this_host_name",
    0x044: "string",
    0x045: "raw_string",
    0x046: "strcat",
    0x047: "display",
    0x048: "ord",
    0x049: "hex",
    0x04a: "hexstr",
    0x04b: "strstr",
    0x04c: "ereg",
    0x04d: "ereg_replace",
    0x04e: "egrep",
    0x04f: "eregmatch",
    0x050: "match",
    0x051: "substr",
    0x052: "insstr",
    0x053: "tolower",
    0x054: "toupper",
    0x055: "crap",
    0x056: "strlen",
    0x057: "split",
    0x058: "chomp",
    0x059: "int",
    0x05a: "stridx",
    0x05b: "str_replace",
    0x05c: "make_list",
    0x05d: "make_array",
    0x05e: "keys",
    0x05f: "max_index",
    0x060: "sort",
    0x061: "unixtime",
    0x062: "gettimeofday",
    0x063: "localtime",
    0x064: "mktime",
    0x065: "open_sock_kdc",
    0x066: "start_denial",
    0x067: "end_denial",
    0x068: "dump_ctxt",
    0x069: "typeof",
    0x06a: "exit",
    0x06b: "rand",
    0x06c: "usleep",
    0x06d: "sleep",
    0x06e: "isnull",
    0x06f: "defined_func",
    0x070: "forge_ip_packet",
    0x071: "get_ip_element",
    0x072: "set_ip_elements",
    0x073: "insert_ip_options",
    0x074: "dump_ip_packet",
    0x075: "forge_tcp_packet",
    0x076: "get_tcp_element",
    0x077: "set_tcp_elements",
    0x078: "dump_tcp_packet",
    0x079: "tcp_ping",
    0x07a: "forge_udp_packet",
    0x07b: "get_udp_element",
    0x07c: "set_udp_elements",
    0x07d: "dump_udp_packet",
    0x07e: "forge_icmp_packet",
    0x07f: "get_icmp_element",
    0x080: "forge_igmp_packet",
    0x081: "send_packet",
    0x082: "pcap_next",
    0x083: "send_capture",
    0x084: "MD2",
    0x085: "MD4",
    0x086: "MD5",
    0x087: "SHA",
    0x088: "SHA1",
    0x089: "RIPEMD160",
    0x08a: "HMAC_MD2",
    0x08b: "HMAC_MD5",
    0x08d: "HMAC_SHA1",
    0x08f: "HMAC_RIPEMD160",
    0x090: "dh_generate_key",
    0x091: "bn_random",
    0x092: "bn_cmp",
    0x093: "dh_compute_key",
    0x094: "rsa_public_decrypt",
    0x095: "bf_cbc_encrypt",
    0x096: "bf_cbc_decrypt",
    0x097: "dsa_do_verify",
    0x098: "pem_to_rsa",
    0x099: "pem_to_dsa",
    0x09a: "rsa_sign",
    0x09b: "dsa_do_sign",
    0x09c: "pread",
    0x09d: "find_in_path",
    0x09e: "fread",
    0x09f: "fwrite",
    0x0a0: "unlink",
    0x0a1: "get_tmp_dir",
    0x0a2: "file_stat",
    0x0a3: "file_open",
    0x0a4: "file_close",
    0x0a5: "file_read",
    0x0a6: "file_write",
    0x0a7: "file_seek",
    0x0ac: "prompt",
    0x0ad: "get_local_mac_addrs",
    0x0ae: "func_has_arg",
    0x0af: "socket_get_error",
    0x0b0: "big_endian",
    0x0b1: "socket_ready",
    0x0b2: "socket_negotiate_ssl",
    0x0b3: "socket_pending",
    0x0b4: "fill_list",
    0x0b5: "zlib_compress",
    0x0b6: "zlib_decompress",
    0x0b7: "fork",
    0x0b8: "bsd_byte_ordering",
    0x0b9: "inject_packet",
    0x0ba: "get_local_mac_addr",
    0x0bb: "get_gw_mac_addr",
    0x0bd: "prompt_password",
    0x0be: "disable_all_plugins",
    0x0bf: "enable_plugin_family",
    0x0c0: "disable_plugin_family",
    0x0c1: "enable_plugin_id",
    0x0c2: "disable_plugin_id",
    0x0c3: "nasl_str2intarray",
    0x0c4: "rm_kb_item",
    0x0c5: "get_host_raw_ip",
    0x0c6: "this_host_raw",
    0x0c7: "aes_cbc_encrypt",
    0x0c8: "aes_cbc_decrypt",
    0x0c9: "tripledes_cbc_encrypt",
    0x0ca: "tripledes_cbc_decrypt",
    0x0cb: "file_is_signed",
    0x0cc: "bind_sock_tcp",
    0x0cd: "bind_sock_udp",
    0x0ce: "sock_accept",
    0x0cf: "make_path",
    0x0d0: "start_trace",
    0x0d1: "stop_trace",
    0x0d2: "rsa_public_encrypt",
    0x0d3: "rsa_private_encrypt",
    0x0d4: "rsa_private_decrypt",
    0x0d5: "bn_dec2raw",
    0x0d6: "bn_raw2dec",
    0x0d7: "bn_hex2raw",
    0x0d8: "bn_raw2hex",
    0x0d9: "tcp_scan",
    0x0da: "socketpair",
    0x0db: "syn_scan",
    0x0dc: "platform",
    0x0dd: "xmlparse",
    0x0de: "preg",
    0x0df: "pgrep",
    0x0e0: "pregmatch",
    0x0e1: "udp_scan",
    0x0e2: "preg_replace",
    0x0e3: "get_global_kb_list",
    0x0e4: "set_global_kb_item",
    0x0e5: "get_global_kb_item",
    0x0e6: "open_sock2",
    0x0e7: "mutex_lock",
    0x0e8: "mutex_unlock",
    0x0e9: "uint",
    0x0ea: "aes_ctr_encrypt",
    0x0eb: "aes_ctr_decrypt",
    0x0ec: "set_mem_limits",
    0x0ed: "report_xml_tag",
    0x0ee: "script_set_attribute",
    0x0ef: "script_end_attributes",
    0x0f0: "datalink",
    0x0f1: "link_layer",
    0x0f2: "sendto",
    0x0f3: "recvfrom",
    0x0f4: "bpf_open",
    0x0f5: "bpf_close",
    0x0f6: "bpf_next",
    0x0f7: "bn_add",
    0x0f8: "bn_sub",
    0x0f9: "bn_mul",
    0x0fa: "bn_sqr",
    0x0fb: "bn_div",
    0x0fc: "bn_mod",
    0x0fd: "bn_nnmod",
    0x0fe: "bn_mod_add",
    0x0ff: "bn_mod_sub",
    0x100: "bn_mod_mul",
    0x101: "bn_mod_sqr",
    0x102: "bn_exp",
    0x103: "bn_mod_exp",
    0x104: "bn_gcd",
    0x105: "readdir",
    0x106: "ssl_accept",
    0x107: "resolv",
    0x108: "open_sock_proxy",
    0x109: "get_peer_name",
    0x10a: "nessus_get_dir",
    0x10b: "rename",
    0x10c: "get_sock_name",
    0x10d: "shutdown",
    0x10f: "aes_cfb_encrypt",
    0x110: "aes_cfb_decrypt",
    0x111: "routethrough",
    0x112: "socket_set_timeout",
    0x113: "file_mtime",
    0x114: "mkdir",
    0x115: "rmdir",
    0x116: "ssl_accept2",
    0x117: "gzip_compress",
    0x118: "deflate_compress",
    0x11a: "wait",
    0x11b: "getpid",
    0x11c: "query_report",
    0x11d: "can_query_report",
    0x11e: "xslt_apply_stylesheet",
    0x11f: "platform_ptr_size",
    0x120: "kill",
    0x121: "nasl_level",
    0x122: "SHA224",
    0x123: "SHA256",
    0x124: "SHA512",
    0x125: "HMAC_SHA224",
    0x126: "HMAC_SHA256",
    0x127: "HMAC_SHA512",
    0x128: "query_scratchpad",
    0x129: "ssl_accept3",
    0x12a: "ssl_get_peer_name",
    0x12b: "pem_to_rsa2",
    0x12c: "pem_to_dsa2",
    0x12d: "cfile_open",
    0x12e: "file_fstat",
    0x12f: "cfile_stat",
    0x130: "mktime_tz",
    0x131: "gettimezones",
    0x132: "getlocaltimezone",
    0x133: "report_error",
    0x134: "security_low",
    0x135: "security_critical",
    0x136: "ipsort",
    0x137: "numsort",
    0x138: "bind_sock_tcp6",
    0x139: "bind_sock_udp6",
    0x13a: "security_report",
    0x13b: "nasl_base64_decode",
    0x13c: "nasl_base64_encode",
    0x13d: "get_var",
    0x13e: "set_var",
    0x13f: "get_global_var",
    0x140: "set_global_var",
    0x141: "htmlparse",
    0x143: "bzip2_compress",
    0x144: "bzip2_decompress",
    0x145: "db_open",
    0x146: "db_close",
    0x147: "db_query",
    0x148: "db_query_foreach",
    0x149: "jpeg_image",
    0x14a: "buffer_pick",
    0x14b: "security_report_with_attachments",
    0x14f: "db_copy",
    0x150: "load_db_master_key_cli",
    0x151: "is_user_root",
    0x152: "dump_interfaces",
    0x153: "untar_plugins",
    0x154: "mkcert",
    0x155: "get_cert_dname",
    0x156: "mkdir_ex",
    0x157: "chmod",
    0x158: "typeof_ex",
    0x159: "new",
    0x15a: "delete",
    0x15b: "tickcount",
    0x15c: "serialize",
    0x15d: "deserialize",
    0x15e: "socket_get_secure_renegotiation_support",
    0x15f: "SHA384",
    0x160: "HMAC_SHA384",
    0x161: "insert_element",
    0x162: "delete_element",
    0x163: "fork_ex",
    0x164: "abort",
    0x165: "nasl_environment",
    0x166: "equals",
    0x167: "db_open2",
    0x168: "close_handle",
    0x169: "open_sock_ex",
    0x16a: "socket_negotiate_ssl_ex",
    0x16b: "mutex_get_info",
    0x16c: "pem_to_pub_rsa",
    0x16d: "ssl_validate",
    0x16e: "db_passwd2key",
    0x16f: "tar_files",
    0x171: "stack_dump",
    0x172: "gettime",
    0x173: "event_add",
    0x174: "event_remove",
    0x177: "append_element",
    0x178: "contains_element",
    0x179: "format",
    0x17a: "db_open_ex",
    0x17b: "random",
    0x17d: "ssl_get_error",
    0x17e: "ssl_set_alpn_protocols",
    0x17f: "ssl_get_alpn_protocol",
    0x180: "trim",
    0x181: "ssl_get_session_key",
    0x182: "rules_validate_target",
    0x183: "rules_validate_plugin",
    0x184: "get_preference_file_content",
    0x185: "get_fork_perf",
    0x186: "sched_dump",
    0x187: "inject_host",
    0x188: "report_tag_internal",
    0x189: "send_file",
    0x18a: "recv_file",
    0x18b: "is_sock_open",
    0x18c: "file_stat_ex",
    0x18d: "system_log_register",
    0x18e: "system_log",
    0x18f: "system_log_count",
    0x190: "system_log_empty",
    0x191: "get_host_fqdn",
    0x192: "recv_until_boundary",
    0x193: "db_dump",
    0x194: "file_hash",
    0x195: "rsa_generate",
    0x196: "bn_mod_inverse",
    0x197: "ecc_scalar_multiply",
    0x198: "ecc_curve_details",
    0x199: "crypto_hash",
    0x19a: "crypto_mac",
    0x19b: "crypto_encrypt",
    0x19c: "crypto_decrypt",
    0x19d: "crypto_verify_signature",
    0x19e: "rsa_encrypt_ex",
    0x19f: "rsa_decrypt_ex",
    0x1a0: "is_type",
    0x1a1: "length",
    0x1a2: "contains_key",
    0x1a3: "strjoin",
    0x1a4: "capitalize",
    0x1a5: "convert",
    0x1a6: "merge_arrays",
    0x1a7: "format_ex",
    0x1a8: "metric_state",
    0x1a9: "metric_event",
    0x1aa: "query_inventory",
    0x1ab: "code_coverage",
    0x1ac: "encoding_identify",
    0x1ad: "encoding_convert",
    0x1af: "socket_negotiate_ssl2",
    0x1b0: "crypto_random",
    0x1b1: "encoding_convert_ex",
    0x1b2: "db_query_transaction",
    0x1b3: "tar_open",
    0x1b4: "tar_next",
    0x1b5: "tar_untar",
    0x1b6: "tar_reset",
    0x1b7: "exec_script",
    0x1b8: "script_parent_id",
    0x1b9: "script_context",
    0x1ba: "script_get_children",
    0x1bb: "function_override",
    0x1bc: "engine_diag",
    0x1bd: "file_exists",
    0x1be: "winreg_deletevalue",
    0x1bf: "get_proxy_for_url",
    0x1c0: "file_is_signed_ex",
    0x1c1: "function_name",
    0x1f5: "xsd_validate",
    0x1f6: "schematron_validate",
    0x1f7: "xmldsig_verify",
    0x1f8: "xmldsig_sign",
    0x1f9: "xslt_filter",
    0x1fa: "report_xml_tag2",
    0x1fb: "get_local_ifaces",
    0x1fc: "gzip_deflate_init",
    0x1fd: "gzip_deflate",
    0x1fe: "gzip_deflate_end",
    0x1ff: "make_list2",
    0x200: "localtime_tz",
    0x201: "gzip_inflate_init",
    0x202: "gzip_inflate",
    0x203: "gzip_inflate_end",
    0x204: "ssl_accept4",
    0x205: "get_host_report_name",
    0x206: "set_socket_option",
    0x207: "get_socket_option",
    0x208: "create_plugin_db",
    0x20a: "recv_ex",
    0x20b: "get_env_var",
    0x20c: "ssl_accept5",
    0x20d: "db_open3",
    0x20e: "set_default_see_enc_mode",
    0x211: "db_attach",
    0x212: "db_detach",
    0x213: "rsa_sign_ex",
    0x214: "reverse_resolv",
    0x215: "get_host_ip_ex",
    0x216: "modify_element_shr",
    0x217: "modify_element_cow",
    0x218: "pread_ex",
    0x219: "gzip_deflate_set_dictionary",
    0x21a: "gzip_inflate_set_dictionary",
    0x21b: "report_error_ex",
    0x21c: "resummarize_plugin",
    0x21d: "set_plugin_progress",
    0x21e: "set_host_progress",
    # ── Server/daemon-only builtins (0x403–0x45b) ──────────────────────────
    0x403: "server_delete_user",
    0x406: "server_feed_type",
    0x407: "server_generate_token",
    0x408: "server_validate_token",
    0x409: "server_delete_token",
    0x40a: "server_get_plugin_list",
    0x40f: "server_scan_list",
    0x410: "server_list_reports",
    0x411: "server_report_get_host_list",
    0x41a: "server_scan_ctrl",
    0x41b: "server_report_delete",
    0x41d: "server_restart",
    0x41e: "server_import_nessus_file",
    0x420: "server_get_load",
    0x423: "server_user_exists",
    0x426: "socket_redo_ssl_handshake",
    0x427: "socket_reset_ssl",
    0x42c: "server_get_status",
    0x42d: "server_master_unlock",
    0x432: "server_loading_progress",
    0x433: "server_query_report",
    0x439: "server_untar_plugins",
    0x43a: "server_plugin_search_attributes",
    0x43e: "server_report_has_audit_trail",
    0x43f: "server_report_has_kb",
    0x440: "server_report_regenerate",
    0x441: "server_report_search_attributes",
    0x445: "server_report_scan_errors",
    0x446: "report_mk_filter",
    0x44a: "server_set_global_preferences",
    0x44f: "server_report_export",
    0x450: "server_report_import",
    0x453: "server_generate_dot_nessus",
    0x455: "server_token_update",
    0x456: "file_md5",
    0x457: "server_launch_scan",
    0x458: "server_insert_policy",
    0x459: "server_set_dynamic_rules",
    0x45a: "server_set_master_password",
    0x45b: "server_needs_master_password",
    # ── Windows agent builtins (0x7d0–0x80b) ──────────────────────────────
    0x7d0: "winreg_openkey",
    0x7d1: "winreg_queryinfokey",
    0x7d2: "winreg_queryvalue",
    0x7d3: "winreg_enumvalue",
    0x7d4: "winreg_enumkey",
    0x7d5: "winreg_getkeysecurity",
    0x7d6: "winreg_createkey",
    0x7d7: "winreg_setvalue",
    0x7d8: "winfile_localpath",
    0x7d9: "winfile_create",
    0x7da: "winfile_read",
    0x7db: "winfile_write",
    0x7dc: "winfile_size",
    0x7dd: "winfile_delete",
    0x7de: "winfile_versioninfo",
    0x7df: "winfile_versioninfo_ex",
    0x7e0: "winfile_securityinfo",
    0x7e1: "winfile_findfirst",
    0x7e2: "winfile_findnext",
    0x7e4: "winwmi_connectserver",
    0x7e5: "winwmi_execquery",
    0x7e6: "winwmi_getnextelement",
    0x7e7: "winwmi_getobject",
    0x7e8: "winwmi_spawninstance",
    0x7e9: "winwmi_execmethod",
    0x7ec: "winlsa_open_policy",
    0x7ed: "winlsa_query_info",
    0x7ee: "winlsa_query_domain_info",
    0x7ef: "winlsa_lookup_sids",
    0x7f0: "winlsa_lookup_names",
    0x7f1: "winlsa_enumerate_accounts",
    0x7f4: "winsvc_open_manager",
    0x7f5: "winsvc_open",
    0x7f6: "winsvc_enum_status",
    0x7f7: "winsvc_control",
    0x7f8: "winsvc_create",
    0x7f9: "winsvc_start",
    0x7fa: "winsvc_delete",
    0x7fb: "winsvc_query_status",
    0x7fc: "winsvc_get_displayname",
    0x7fd: "winsvc_query_security",
    0x800: "winnet_get_server_info",
    0x801: "winnet_get_wksta_info",
    0x802: "winnet_enum_sessions",
    0x803: "winnet_enum_shares",
    0x804: "winnet_enum_wksta_users",
    0x805: "winnet_enum_servers",
    0x806: "winnet_get_user_groups",
    0x807: "winnet_get_user_local_groups",
    0x808: "winnet_get_local_group_members",
    0x809: "winnet_get_group_users",
    0x80a: "winnet_get_user_info",
    0x80b: "winnet_get_user_modals",
}

# CMP opcode → comparison operator string (from nasl_vm.py OPCODES)
CMP_OPS = {
    0x03: "==",   # CMP_EQ
    0x0b: "<",    # CMP_LT
    0x0c: "<=",   # CMP_LE
    0x0d: ">",    # CMP_GT
    0x0e: ">=",   # CMP_GE
    0x2b: "!=",   # CMP_NE
}

# Negation of each CMP operator (for simplifying !(A op B))
_NEGATE_OP = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _simplify_condition(cond: str) -> str:
    """Simplify !(A op B) → A negop B."""
    import re
    m = re.fullmatch(r'!\((.+)\s(==|!=|<|<=|>|>=)\s(.+)\)', cond)
    if m:
        lhs, op, rhs = m.group(1), m.group(2), m.group(3)
        return f"{lhs} {_NEGATE_OP[op]} {rhs}"
    return cond

# Arithmetic opcode → operator string (from nasl_vm.py OPCODES)
ARITH_OPS = {
    0x02: "+",    # ADD
    0x0f: "&",    # AND (bitwise)
    0x10: "|",    # OR  (bitwise)
    0x11: "^",    # XOR
    0x12: "~",    # NOT (bitwise, unary)
    0x13: "-",    # SUB
    0x14: "*",    # MUL
    0x15: "/",    # DIV
    0x16: "%",    # MOD
    0x17: "**",   # POW
    0x18: "<<",   # SHL
    0x19: ">>",   # SHR
    0x1a: ">>",   # SAR (arithmetic shift right)
    0x29: "-",    # NEG (unary negation)
}


def fmt_builtin(func_id: int) -> str:
    """Return readable name for a builtin function ID."""
    idx = func_id & 0x0fffffff
    name = BUILTIN_NAMES.get(idx)
    if name:
        return name
    if (func_id & 0xf0000000) == 0xf0000000:
        return f"builtin_{idx:#x}"
    return f"fn_{func_id:#x}"


class NaslDecompiler:
    """
    Decompiles NASL nbin bytecode to readable pseudocode.

    Strategy:
    1. Parse all TLV sections (symbol tables, bytecode)
    2. Identify function blocks (FRAME_END positions + TLV 0x0c offsets)
    3. For each block: recover control flow, reconstruct expressions
    4. Emit NASL-like pseudocode with proper indentation
    """

    def __init__(self, path: str, verbose: bool = False):
        self.nb = NbinFile(path)
        self.nb.load()
        self.verbose = verbose
        self.sym = self.nb.symtable()
        self.insns = self.nb.instructions()
        self.n = len(self.insns)
        self._fid_to_name: dict[int, str] = {}   # fid → function name
        self._fid_to_start: dict[int, int] = {}  # fid → start insn index
        self._block_ranges: list[tuple[int, int, str]] = []  # (start, end, name)
        self._parse_func_table()
        self._identify_blocks()

    # ── Symbol resolution ──────────────────────────────────────────────────────

    def resolve_sym(self, key: int) -> str:
        """Look up a key in the symbol table."""
        return self.sym.get(key, f"sym_{key}")

    def fmt_operand(self, mode: int, operand: int) -> str:
        """Format an operand as NASL-like expression."""
        # Inline literal modes 0x00–0x0d
        if 0x00 <= mode <= 0x0d:
            if mode == 0x00: return "NULL"
            if mode == 0x01: return "TRUE" if operand else "FALSE"
            if mode == 0x02:                                    # data/immediate value
                if operand == 0: return "NULL"
                v = operand if operand < 0x80000000 else operand - 0x100000000
                return str(v)
            if mode == 0x03:                                    # signed int
                # Interpret as signed 32-bit
                v = operand if operand < 0x80000000 else operand - 0x100000000
                return str(v)
            if mode == 0x04: return f"{operand}"               # unsigned int
            if mode == 0x05: return "TRUE" if operand else "FALSE"
            if mode == 0x08:
                # INT_HASH: function ID (builtin, object method, or user function)
                if (operand & 0xf0000000) == 0xf0000000:
                    return fmt_builtin(operand)
                if (operand & 0xff800000) == 0x800000:
                    # Object method slot ID → look up in TLV 0x0c table
                    slot = operand & 0x7fffff
                    return self._fid_to_name.get(operand, f"method_{slot}")
                # User-defined function: fid → look up by function ID
                name = self._fid_to_name.get(operand)
                if name:
                    return name
                return f"func_{operand:#x}"
            if mode == 0x0c:
                # FREF: function reference (inline) — treat like ihash
                if (operand & 0xf0000000) == 0xf0000000:
                    return fmt_builtin(operand)
                if (operand & 0xff800000) == 0x800000:
                    slot = operand & 0x7fffff
                    return self._fid_to_name.get(operand, f"method_{slot}")
                name = self._fid_to_name.get(operand)
                if name:
                    return name
                return f"func_{operand:#x}"
            if mode == 0x0d:
                # AELEM: array element — usually accumulator/result reference
                return "__acc__" if operand == 0 else f"aelem_{operand}"
            if mode in (0x09, 0x0b, 0x0e, 0x0f):
                # String literal: operand is a symtable index
                name = self.sym.get(operand)
                return repr(name) if name else f"str_pool[{operand}]"
            if mode == 0x0a:
                # Runtime frame reference (usually negative offset)
                signed = operand if operand < 0x80000000 else operand - 0x100000000
                return f"__tmp{signed}__"
            return f"({ADDR_MODES.get(mode, f'm{mode:02x}')}:{operand:#x})"

        # Memory/runtime modes
        if mode == 0x14: return "__acc__"         # stack/accumulator
        if mode == 0x15: return f"arg_{operand}"  # local variable by frame index
        if mode == 0x16:                           # global register (local var in frame)
            # Map common registers to readable names
            if operand == 0x1f: return "__ret__"  # r31 = return value register
            return f"loc_{operand}"
        if mode == 0x17:
            # KEY: index into string pool (symtable)
            name = self.sym.get(operand)
            return name if name else f"key_{operand}"
        if mode == 0x18:
            # INT_KEY: integer key (also string pool index in most cases)
            name = self.sym.get(operand)
            return name if name else f"ikey_{operand}"
        if mode == 0x19:
            # DEREF: runtime variable slot — NOT a symtable lookup
            if (operand & 0xf0000000) == 0xf0000000:
                return fmt_builtin(operand)
            # Variable slot index in the current function scope
            # Use signed interpretation for negative slot offsets
            signed = operand if operand < 0x80000000 else operand - 0x100000000
            if signed < 0:
                return f"upval[{signed}]"  # negative = closure/upvalue
            return f"v{operand}"
        if mode == 0x1a: return "this"
        if mode == 0x1b: return "self"

        # String value types (runtime only, not standard ADDR_MODES)
        if mode in (0x10, 0x11):  # STRING_SHORT / STRING_HEAP
            name = self.sym.get(operand)
            return repr(name) if name else f"str_pool[{operand}]"

        # High-bit modes: modifier flags in upper bits, base type in low 5 bits.
        # Empirically confirmed per-mode semantics:
        #   0xc9 (base 0x09), 0xcb (base 0x0b), 0xce (base 0x0e), 0xcf (base 0x0f),
        #   0xd1 (base 0x11) → symtable string references
        #   0xca (base 0x0a) → signed runtime frame reference (negative offsets)
        #   0xcc (base 0x0c) → function reference (handled via base mode recurse)
        #   0xcd (base 0x0d) → null/unused operand marker
        if mode > 0x1b:
            base = mode & 0x1f
            # Null/unused marker
            if base == 0x0d:
                return "NULL"
            # String literal via symtable
            if base in (0x09, 0x0b, 0x0e, 0x0f, 0x10, 0x11):
                name = self.sym.get(operand)
                return repr(name) if name else f"str_pool[{operand}]"
            # Recurse with base mode (handles func refs, ints, DEREF, etc.)
            return self.fmt_operand(base, operand)

        return f"{ADDR_MODES.get(mode, f'm{mode:02x}')}:{operand:#x}"

    # ── Block identification ───────────────────────────────────────────────────

    def _parse_func_table(self):
        """Parse TLV 0x0c (function definition table) to extract two mappings:

        1. func_id → qualified name  (plain user-function CALL dispatch path 3)
           Format confirmed by Ghidra analysis of FUN_00257900 / FUN_00257750:
             [4BE: count]
             per entry:
               [4B: 00 00 00 0d marker][4BE: func_id][2BE: name_len][name bytes]
               followed by parameter sub-blocks (variable length)
           Entries are found by scanning for the 00 00 00 0d marker with
           sanity checks on func_id and name to reject false positives.

        2. slot_id (0x00800000|n) → method name  (CALL dispatch path 2)
           Slot IDs are embedded within parameter sub-blocks of each entry
           (type-8 sub-blocks: [1B type=8][1B name_len][name bytes] per item;
           type-3 sub-blocks carry slot IDs as [4BE slot_id] values).
           These are mapped via a secondary backward-scan after the primary
           marker-based pass so that method resolution remains correct even
           when parameter sub-block layouts vary.
        """
        raw_0c = self.nb._raw_sections.get(0x0c, b'')
        if not raw_0c:
            return

        _VALID_NAME_CHARS = frozenset(
            'abcdefghijklmnopqrstuvwxyz'
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            '0123456789_:.+@-'
        )

        n = len(raw_0c)
        if n < 4:
            return

        count = struct.unpack('>I', raw_0c[0:4])[0]
        # Sanity-cap count to avoid scanning forever on corrupt data
        if count == 0 or count > 0x4000:
            count = 0x4000

        found = 0
        i = 4
        while i < n - 10 and found < count:
            # Look for the per-entry marker: 00 00 00 0d
            if raw_0c[i:i+4] != b'\x00\x00\x00\x0d':
                i += 1
                continue

            if i + 10 > n:
                break

            func_id  = struct.unpack('>I', raw_0c[i+4:i+8])[0]
            name_len = struct.unpack('>H', raw_0c[i+8:i+10])[0]

            # Reject obviously invalid entries
            if func_id == 0 or name_len < 2 or name_len > 128:
                i += 1
                continue
            if i + 10 + name_len > n:
                i += 1
                continue

            name_bytes = raw_0c[i+10:i+10+name_len]
            try:
                name = name_bytes.decode('ascii')
            except (UnicodeDecodeError, ValueError):
                i += 1
                continue

            if not all(c in _VALID_NAME_CHARS for c in name):
                i += 1
                continue

            # Confirmed valid entry — record func_id → name
            self._fid_to_name[func_id] = name
            found += 1
            # Advance past [marker(4)][func_id(4)][name_len(2)][name(name_len)]
            i = i + 10 + name_len

        # Secondary pass: pick up slot IDs (0x00800000|n) from sub-blocks.
        # These appear as big-endian uint32 values anywhere in 0x0c data.
        # We scan the whole section and do a backward name-scan for each hit.
        off = 0
        while off + 4 <= n:
            v = struct.unpack('>I', raw_0c[off:off+4])[0]
            if (v & 0xff800000) == 0x800000 and (v & 0x7fffff) < 256:
                slot_id = v
                if slot_id not in self._fid_to_name:
                    # Scan backward past NUL padding for the preceding name
                    name_end = off
                    while name_end > 0 and raw_0c[name_end - 1] == 0:
                        name_end -= 1
                    name_start = name_end
                    while name_start > 0 and 32 <= raw_0c[name_start - 1] < 127:
                        name_start -= 1
                    if name_end - name_start >= 3:
                        candidate = raw_0c[name_start:name_end].decode('ascii', errors='replace')
                        # Require qualified name (has '::') or long enough plain identifier
                        if '::' in candidate or (candidate.replace('_', '').isalnum() and len(candidate) >= 5):
                            self._fid_to_name[slot_id] = candidate
            off += 1

    def _identify_blocks(self):
        """Find function block boundaries from FRAME_END positions.

        Block structure:
          - Each block starts at: 0 (first block) or frame_end+1
          - Each block ends at: frame_end instruction (inclusive)
          - The last block may have no FRAME_END (ends at last instruction)
          - Function ID: fid = N - block_start  (same encoding as jump targets)
        """
        frame_ends = [i for i, ins in enumerate(self.insns) if ins.opcode == 0x33]

        if not frame_ends:
            # Only one block (no functions)
            fid = self.n  # main block fid = N - 0 = N
            self._fid_to_name[fid] = "main"
            self._fid_to_start[fid] = 0
            self._block_ranges.append((0, self.n - 1, "main"))
            return

        # Build block list: (start, end)
        starts = [0] + [fe + 1 for fe in frame_ends]
        ends   = frame_ends + [self.n - 1]

        for i, (start, end) in enumerate(zip(starts, ends)):
            fid = self.n - start
            # Check if this is the main block (block 0, first block)
            if i == 0:
                block_name = "main"
            else:
                # Look up name from class method table, else use fid
                block_name = self._fid_to_name.get(fid, f"func_{fid:#x}")

            self._fid_to_name[fid] = block_name
            self._fid_to_start[fid] = start
            self._block_ranges.append((start, end, block_name))

    def jump_target(self, src_op: int) -> int:
        """Compute jump target instruction index.

        VM sets PC = N - src_op, then DECREMENTS before fetching.
        Effective next instruction = (N - src_op) - 1.
        """
        return self.n - src_op - 1

    def fid_to_name(self, fid: int) -> str:
        """Resolve a user function ID to its name."""
        return self._fid_to_name.get(fid, f"func_{fid:#x}")

    # ── Instruction classification ─────────────────────────────────────────────

    def is_cmp(self, idx: int) -> bool:
        return self.insns[idx].opcode in CMP_OPS

    def is_jump(self, idx: int) -> bool:
        return self.insns[idx].opcode in (0x04, 0x05, 0x06)

    def is_call(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x07

    def is_slot(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x32

    def is_ret(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x08

    # ── Expression reconstruction ──────────────────────────────────────────────

    def fmt_call(self, call_idx: int) -> str:
        """Legacy helper — not used in main decompile_block path."""
        ins = self.insns[call_idx]
        func_name = self.fmt_operand(ins.src_mode, ins.src_op)
        return f"{func_name}()", call_idx + 1

    # ── Core decompiler ────────────────────────────────────────────────────────

    def _build_slots(self, pending_slots: list) -> list[str]:
        """Convert pending SLOT list to argument strings.

        Each entry is (val, name, is_named) where is_named is True only when the
        original SLOT instruction had dst_mode=0x17 (KEY) or 0x18 (INT_KEY) — the
        only modes that encode a genuine NASL named-argument key.  DEREF (0x19),
        INT (0x03), STACK (0x14), NULL (0x00), etc. all indicate positional / ODD-
        count slots and must NOT be treated as named-arg names even if their
        formatted string happens to look like an identifier.
        """
        args = []
        for entry in pending_slots:
            val, name, is_named = entry if len(entry) == 3 else (entry[0], entry[1], False)
            # Skip null/empty filler slots (NULL NULL padding in positional calls)
            if (val == "NULL" or val == "") and (name == "NULL" or name == ""):
                continue
            if val == "NULL":
                continue
            if is_named:
                args.append(f"{name}:{val}")
            else:
                args.append(val)
        return args

    def _has_loopback_in_range(self, lo: int, hi: int) -> bool:
        """Return True if there is a CJMP/JNZ/JZ in [lo..hi-1] targeting >= hi."""
        for idx in range(lo, hi):
            ins = self.insns[idx]
            if ins.opcode in (0x04, 0x05, 0x06) and ins.src_mode == 0x08:
                t = self.jump_target(ins.src_op)
                if t >= hi:
                    return True
        return False

    def decompile_block(self, start: int, end: int, func_name: str = "main") -> list[str]:
        """Decompile a single function block [start..end] to lines of code.

        VM executes instructions HIGH→LOW (PC decrements each cycle).
        Argument-passing convention (observed in Ghidra FUN_0026b180):
          - SLOT (0x32): pushes (value, name) pair — named argument
          - SETVAR (0x09): pushes value — positional argument
          - Both accumulate before CALL; CALL consumes all pending args
        File order [SLOT, SETVAR, CALL] at indices [i+2, i+1, i] means
        execution order is SLOT first, SETVAR second, CALL third (HIGH→LOW).
        """
        lines = []
        indent = 0

        def emit(line: str):
            lines.append("  " * indent + line)

        # Track open conditional blocks: stack of (close_at, label)
        # close_at = instruction index where we emit "}" (before processing that insn)
        open_blocks: list[tuple[int, str]] = []

        # Pending args: accumulate SLOT/SETVAR before CALL
        # Each entry: (val_expr, name_expr, is_named)
        # is_named=True only when SLOT dst_mode is KEY (0x17) or INT_KEY (0x18)
        pending_slots: list[tuple[str, str, bool]] = []

        # Pending CMP: set by CMP opcode, consumed by next JZ/JNZ/CJMP
        pending_cmp: tuple[str, int] | None = None  # (condition_text, cmp_opcode)

        def flush_pending_slots_as_comment():
            for val, name, _ in pending_slots:
                emit(f"// slot: {name}={val}")
            pending_slots.clear()

        # Iterate HIGH→LOW: execution order mirrors VM
        i = end
        while i >= start:
            ins = self.insns[i]
            op = ins.opcode

            # ── Close any blocks whose close target we've reached ───────────
            while open_blocks and open_blocks[-1][0] == i:
                open_blocks.pop()
                indent = max(0, indent - 1)
                emit("}")

            # ── FRAME_END (0x33) / FUNC_INIT (0x2c) / NOP (0x00) ───────────
            # FRAME_END is the function prologue (highest index, executes first)
            # FUNC_INIT is the function epilogue (lowest index, executes last)
            if op in (0x33, 0x2c, 0x00):
                i -= 1
                continue

            # ── SLOT (0x32): argument push ──────────────────────────────────
            # dst_mode=0x17 (KEY) or 0x18 (INT_KEY) → genuinely named arg
            # All other dst modes (DEREF 0x19, INT 0x03, NULL 0x00, etc.) are
            # either the ODD-count marker, a positional value, or a variable
            # reference — never a named-arg key.
            if op == 0x32:
                val     = self.fmt_operand(ins.src_mode, ins.src_op)
                name    = self.fmt_operand(ins.dst_mode, ins.dst_op)
                is_named = ins.dst_mode in (0x17, 0x18)
                pending_slots.append((val, name, is_named))
                i -= 1
                continue

            # ── SETVAR (0x09) ───────────────────────────────────────────────
            # When dst_mode==0x02 (discard/control) and src is a small even int:
            # this is the arg-count marker pushed by NASL VM before CALL.
            # It tells CALL how many items were pushed to the arg stack (N_slots*2).
            # Skip it — it is NOT an actual argument.
            # Otherwise treat as a positional arg.
            if op == 0x09:
                if ins.dst_mode == 0x02:
                    # arg-count marker — skip
                    i -= 1
                    continue
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "", False))
                i -= 1
                continue

            # ── PUSH_ARG (0x30): positional argument ───────────────────────
            if op == 0x30:
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "", False))
                i -= 1
                continue

            # ── SET_NAMED (0x31) ───────────────────────────────────────────
            # When dst_mode==0x02 (control/discard), this is function frame
            # setup machinery emitted at the top of each block — skip it.
            if op == 0x31:
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "__named__", False))
                i -= 1
                continue

            # ── CALL (0x07): consume all pending args ───────────────────────
            if op == 0x07:
                fn = self.fmt_operand(ins.src_mode, ins.src_op)
                args = self._build_slots(pending_slots)
                pending_slots.clear()
                pending_cmp = None
                if args:
                    emit(f"{fn}({', '.join(args)});")
                else:
                    emit(f"{fn}();")
                i -= 1
                continue

            # ── CMP opcodes: store condition, wait for JZ/JNZ/CJMP ─────────
            if op in CMP_OPS:
                flush_pending_slots_as_comment()
                cmp_sym = CMP_OPS[op]
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)
                pending_cmp = (f"{lhs} {cmp_sym} {rhs}", op)
                i -= 1
                continue

            # ── NOT (0x24): invert condition flag ───────────────────────────
            if op == 0x24:
                if pending_cmp is not None:
                    cond, cop = pending_cmp
                    pending_cmp = (f"!({cond})", cop)
                i -= 1
                continue

            # ── JZ/JNZ/CJMP: consume pending CMP and open block ────────────
            if op in (0x04, 0x05, 0x06):
                flush_pending_slots_as_comment()
                target = self.jump_target(ins.src_op)  # = N - src_op - 1

                if pending_cmp is not None:
                    condition, _ = pending_cmp
                    pending_cmp = None

                    # JZ   fires when condition_reg==0 (condition FALSE)
                    #      → if-body runs when condition TRUE
                    # JNZ  fires when condition_reg!=0 (condition TRUE)
                    #      → if-body runs when condition FALSE → negate
                    # CJMP fires when condition_reg!=0 (same as JNZ, confirmed Ghidra)
                    #      → if-body runs when condition FALSE → negate
                    if op == 0x04:    # JZ
                        cond_text = condition
                    else:             # JNZ (0x05) or CJMP (0x06)
                        cond_text = f"!({condition})"

                    # Simplify !(A op B) → A negop B
                    cond_text = _simplify_condition(cond_text)

                    # In HIGH→LOW: target < i means target is at a lower index
                    # (forward in execution = "after the if-body" = normal if)
                    # target > i means loop-back (while loop)
                    if start <= target < i:
                        # Check if there's a loop-back jump inside the body [target+1..i-1]
                        is_while = self._has_loopback_in_range(target + 1, i)
                        if is_while:
                            emit(f"while ({cond_text}) {{")
                        else:
                            emit(f"if ({cond_text}) {{")
                        open_blocks.append((target, "while" if is_while else "if"))
                        indent += 1
                    elif target > i:
                        # Loop-back jump (end of while body jumping up)
                        emit(f"// loop-back: {['JZ','JNZ','CJMP'][op-4]} → [{target}]")
                    else:
                        emit(f"// branch out of block: {['JZ','JNZ','CJMP'][op-4]} → [{target}]")
                else:
                    # Standalone jump without preceding CMP
                    j_name = {0x04: "JZ", 0x05: "JNZ", 0x06: "CJMP"}[op]
                    target = self.jump_target(ins.src_op)
                    if start <= target < i:
                        emit(f"if (__flag__) {{  // {j_name} → [{target}]")
                        open_blocks.append((target, j_name))
                        indent += 1
                    else:
                        emit(f"// {j_name} → [{target}]")
                i -= 1
                continue

            # ── MOV (0x01): assignment ──────────────────────────────────────
            # GDB-confirmed operand semantics (HIGH→LOW VM):
            #   src_mode/src_op = DESTINATION (LHS variable to write to)
            #   dst_mode/dst_op = SOURCE value (RHS — integer literal, string pool, etc.)
            # This is counter-intuitive but matches the wire format.
            if op == 0x01:
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)  # destination var
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)  # source value
                # src_mode 0x02 = discard (write to nowhere) — skip
                if ins.src_mode == 0x02:
                    i -= 1
                    continue
                # Skip if LHS is the accumulator (internal VM temp)
                if ins.src_mode == 0x14:
                    i -= 1
                    continue
                # dst_mode 0x02 = discard/null source → skip (no-op assignment)
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                emit(f"{lhs} = {rhs};")
                i -= 1
                continue

            # ── RET (0x08) ─────────────────────────────────────────────────
            if op == 0x08:
                flush_pending_slots_as_comment()
                pending_cmp = None
                if ins.src_mode == 0x00:
                    emit("return;")
                else:
                    val = self.fmt_operand(ins.src_mode, ins.src_op)
                    emit(f"return {val};")
                i -= 1
                continue

            # ── Arithmetic / bitwise ─────────────────────────────────────────
            # GDB-confirmed: src_mode/src_op = LHS (modified variable, destination)
            #                dst_mode/dst_op = RHS (operand value, source)
            if op in ARITH_OPS:
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)  # modified var
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)  # operand value
                op_str = ARITH_OPS[op]
                # src_mode 0x02 = discard → skip
                if ins.src_mode == 0x02:
                    i -= 1
                    continue
                # dst_mode 0x02 = discard/null → skip
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                if op == 0x29:
                    emit(f"{lhs} = -{rhs};")
                elif op == 0x12:
                    emit(f"{lhs} = ~{rhs};")
                else:
                    emit(f"{lhs} {op_str}= {rhs};")
                i -= 1
                continue

            # ── CONCAT (0x22, 0x23) ─────────────────────────────────────────
            # GDB-confirmed: op=0x22 sm=DEREF[loop_var] dm=data(0) = loop post-increment
            # When dm=data(0), emit lhs++ (for-loop/while-loop increment pattern).
            # Otherwise emit lhs += rhs (string/value concatenation).
            if op in (0x22, 0x23):
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)
                if ins.dst_mode == 0x02:  # data(0) → post-increment pattern
                    emit(f"{lhs}++;")
                else:
                    rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)
                    emit(f"{lhs} += {rhs};")
                i -= 1
                continue

            # ── INCR (0x2f) / DECR (0x37) ───────────────────────────────────
            if op == 0x2f:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}++;")
                i -= 1
                continue
            if op == 0x37:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}--;")
                i -= 1
                continue

            # ── FOREACH (0x2d) ───────────────────────────────────────────────
            if op == 0x2d:
                flush_pending_slots_as_comment()
                pending_cmp = None
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"foreach {dst} ({src}) {{")
                open_blocks.append((start, "foreach"))
                indent += 1
                i -= 1
                continue

            # ── ITER_NEXT (0x34) ────────────────────────────────────────────
            if op == 0x34:
                i -= 1
                continue

            # ── THROW (0x26) / TRY (0x27) / CATCH (0x28) ───────────────────
            if op == 0x26:
                flush_pending_slots_as_comment()
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                emit(f"throw {val};")
                i -= 1
                continue
            if op == 0x27:
                flush_pending_slots_as_comment()
                emit("try {")
                indent += 1
                i -= 1
                continue
            if op == 0x28:
                emit("} catch {")
                i -= 1
                continue

            # ── TYPECHECK (0x2a) ─────────────────────────────────────────────
            if op == 0x2a:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"// typeof({src}) check → {dst}")
                i -= 1
                continue

            # ── INCLUDE (0x25) ──────────────────────────────────────────────
            if op == 0x25:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                emit(f'include("{src}");')
                i -= 1
                continue

            # ── LOAD_KEY (0x1b) / STORE_KEY (0x1c) ──────────────────────────
            if op == 0x1b:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = {src}[key];")
                i -= 1
                continue
            if op == 0x1c:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}[key] = {src};")
                i -= 1
                continue

            # ── LOAD_IDX (0x1d) / STORE_IDX (0x1e) ──────────────────────────
            if op == 0x1d:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = {src}[idx];")
                i -= 1
                continue
            if op == 0x1e:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}[idx] = {src};")
                i -= 1
                continue

            # ── PUSH_SCOPE (0x20) / NEW_OBJ (0x21) ──────────────────────────
            # PUSH_SCOPE is stack-frame setup machinery; skip silently.
            if op == 0x20:
                i -= 1
                continue
            if op == 0x21:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = new {src}();")
                i -= 1
                continue

            # ── LOAD_ACC (0x1f) ─────────────────────────────────────────────
            if op == 0x1f:
                i -= 1
                continue

            # ── POP (0x0a) ──────────────────────────────────────────────────
            if op == 0x0a:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                if dst != "__acc__":
                    emit(f"{dst} = __acc__;")
                i -= 1
                continue

            # ── GETVAR (0x2e) ────────────────────────────────────────────────
            if op == 0x2e:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = getvar({src});")
                i -= 1
                continue

            # ── CMP_REG (0x35) / CMP_REG2 (0x36) ────────────────────────────
            if op in (0x35, 0x36):
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"// cmp_reg({src}, {dst})")
                i -= 1
                continue

            # ── Fallback ─────────────────────────────────────────────────────
            flush_pending_slots_as_comment()
            pending_cmp = None
            mnem = OPCODES.get(op, (f"op{op:02x}", f"op{op:02x}", 0))[0]
            src = self.fmt_operand(ins.src_mode, ins.src_op)
            dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
            emit(f"// {mnem}  {src}  →  {dst}")
            i -= 1

        # Flush any remaining state
        flush_pending_slots_as_comment()

        # Close any remaining open blocks
        while open_blocks:
            open_blocks.pop()
            indent = max(0, indent - 1)
            lines.append("  " * indent + "}")

        return lines

    def decompile(self) -> str:
        """Decompile all function blocks and return complete NASL pseudocode."""
        output = []
        output.append(f"// Decompiled from: {Path(self.nb.path).name}")
        output.append(f"// Total instructions: {self.n}")
        output.append(f"// Symbol table entries: {len(self.sym)}")
        output.append("")

        for start, end, name in self._block_ranges:
            if start >= end:
                continue
            if name == "main" or name.startswith("block_"):
                header = "// === MAIN CODE ==="
            else:
                header = f"function {name}() {{"
            output.append(header)

            block_lines = self.decompile_block(start, end, name)
            for line in block_lines:
                output.append(line)

            if not (name == "main" or name.startswith("block_")):
                output.append("}")
            output.append("")

        return "\n".join(output)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="NASL nbin decompiler")
    p.add_argument("file", help=".nbin file to decompile")
    p.add_argument("--raw", action="store_true", help="Show raw disassembly alongside")
    p.add_argument("--verbose", action="store_true", help="Extra annotation comments")
    p.add_argument("--functions", action="store_true", help="List function blocks")
    p.add_argument("--symtable", action="store_true", help="Dump symbol table")
    args = p.parse_args()

    path = args.file
    if not Path(path).exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    dc = NaslDecompiler(path, verbose=args.verbose)

    if args.symtable:
        print("=== SYMBOL TABLE ===")
        for k, v in sorted(dc.sym.items()):
            print(f"  [{k:5d}] {v!r}")
        print()

    if args.functions:
        print("=== FUNCTION BLOCKS ===")
        for start, end, name in dc._block_ranges:
            print(f"  {name:<30} insns [{start}..{end}] ({end-start+1} insns)")
        print()

    if args.raw:
        print("=== RAW DISASSEMBLY ===")
        for line in dc.nb.disassemble():
            print(" ", line)
        print()

    print("=== DECOMPILED OUTPUT ===")
    print(dc.decompile())


if __name__ == "__main__":
    main()
