#!/usr/bin/env python3
"""Extract IDA evidence for the CMCC RAP/ZIME/SPICE path.

Run with the Python environment that has IDA's ``idapro`` wheel installed:

    IDADIR=/home/demo/tools/idapro-9.3 \
      /home/demo/.local/share/pipx/venvs/ida-pro-mcp/bin/python \
      scripts/ida_extract_spice_zime.py --binary .tmp/ida-inputs/libspice...

The script reads only local binaries and writes a JSON report. It does not read
runtime state files or packet payloads.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import idapro
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc


TARGET_NAMES = [
    "QUIC_create_data_stream",
    "QUIC_set_streams_pay_load_type",
    "QUIC_create_data_channel",
    "QUIC_on_send_data_batch_cb",
    "QUIC_on_send_data_cb",
    "QUIC_send_packets_linux",
    "QUIC_deal_quic_data_send",
    "QUIC_on_channel_data_received_cb",
    "QUIC_on_channel_created_cb",
    "QUIC_engine_set_transport",
    "QUIC_initialize_stream_manage",
    "deal_kcp_sync_ack_cmd",
    "deal_kcp_special_cmd_details",
    "split_ice_deal_spical_cmd_deal_syn",
    "ice_deal_svr_sync_ack",
    "ice_deal_listen_fd",
    "ice_deal_sock",
    "create_fd_session",
    "ice_create_fd",
    "ice_create_udt_session",
    "create_udt_session",
    "init_local_rw_sock_pair_udp",
    "ikcp_send_link_sync",
    "ikcp_update_judge_kcp",
    "ikcp_set_auth_data",
    "ikcp_set_auth_data_res",
    "ikcp_set_auth_head_res",
    "deal_kcp_auth_cmd",
    "split_ice_deal_spical_cmd_deal_auth",
    "ikcp_deal_svr_sync_ack",
    "ikcp_deal_clt_sync_ack",
    "ikcp_deal_link_sync",
    "ikcp_deal_reconnect",
    "ikcp_get_seg_info",
    "ikcp_encode_seg",
    "ikcp_output",
    "ikcp_create",
    "ikcp_set_dest",
    "ice_get_kcp_by_conv",
    "get_thread_kcp",
    "deal_svr_new_session",
    "ice_deal_using_ng",
    "deal_udt_using_cag_uac",
    "deal_udt_using_cag",
    "get_proxy_kcp_dst_ip",
    "get_proxy_kcp_dst_port",
    "get_proxy_type_by_link_type",
    "init_outband_fd_session_bw_ctrl_link_type",
    "reset_sock_bw_ctrl_link_type_by_bw_config",
    "deal_bw_ctrl_sock_link_message",
    "deal_udt_multi_link",
    "deal_udt_multi_tcp_session_init",
    "deal_udt_multi_tcp_socket_error",
    "deal_create_proxy_fd_session",
    "deal_unlinked_unknown_local_data",
    "deal_unlinked_local_data_read",
    "deal_unlinked_outband_head_data",
    "deal_unlinked_outband_local_data",
    "deal_local_link_proxy_create",
    "set_sock_bw_ctrl_type",
    "send_tunnel_link_message",
    "send_tunnel_add_link",
    "set_fd_session_flag",
    "get_thread_proxy_fd_session",
    "deal_kcp_common_data",
    "assign_thread_new_kcp_conv",
    "_udp_output",
    "udt_output",
    "send_udt_data",
    "listen_udp_data",
    "udp_get_local_port",
    "udp_set_dest_addr_info",
    "listen_udp_data_thread",
    "spice_init_udp_thread",
    "split_spice_init_udp_info",
    "spice_init_udp_info",
    "udp_get_tcp_link_info",
    "spice_marshall_msgc_display_init",
    "ZIME_CreateDataEngine",
    "ZIME_Init",
    "ZIME_SetDataExternalTransport",
    "ZIME_CreateDataChannel",
    "ZIME_CreateDataStream",
    "ZIME_SendData",
    "ZIME_ReceiveData",
    "ZIME_DataChannelProcess2",
    "_ZN18ZIMEDataEngineImpl29ZIME_SetDataExternalTransportEP13ZIMETransport",
    "_ZN18ZIMEDataEngineImpl22ZIME_CreateDataChannelEP21_T_ZIMEChannelContextRl",
    "_ZN18ZIMEDataEngineCore17CreateDataChannelEP21_T_ZIMEChannelContextRl",
    "_ZN14ZIMEDataEngine32ZIME_PrepareForCreateDataChannelER24_T_ZIMEPreChannelContext",
    "_ZN18ZIMEDataEngineCore27PrepareForCreateDataChannelER24_T_ZIMEPreChannelContext",
    "_ZN18ZIMEDataEngineImpl21ZIME_CreateDataStreamElRlP18_T_ZIMEStreamParam",
    "_ZN18ZIMEDataEngineCore16CreateDataStreamElRlP18_T_ZIMEStreamParam",
    "_ZN19ZIMEQuicDataChannel12CreateStreamElP18_T_ZIMEStreamParam",
]

STRING_PATTERNS = [
    "SPICE_OUTBAND",
    "QUIC_create_data_stream",
    "CreateDataStream",
    "CreateDataChannel",
    "SetDataExternalTransport",
    "pay_load_type",
    "payload",
    "tunnel",
    "ZTEC",
    "ztec",
    "RAP",
    "rap",
    "8899",
    "get_proxy_kcp_dst_ip",
    "get_proxy_kcp_dst_port",
    "get_proxy_type_by_link_type",
    "sock_link_type",
    "bw_ctrl_link_type",
    "proxy_link_type",
]

LINK_FLAG_OFFSET_PATTERNS = (
    "+0E0h",
    "+0e0h",
    "+0E0",
    "+0xe0",
    "+224",
)

LINK_FLAG_DECOMPILE_PATTERNS = (
    "data_buf[224]",
    "sock_link_type",
    "bw_ctrl_link_type",
    "proxy_link_type",
    "up_bw_ctrl_link_type",
    "down_bw_ctrl_link_type",
)


def hex_ea(ea: int) -> str | None:
    if ea == idaapi.BADADDR or ea is None:
        return None
    return f"0x{ea:x}"


def func_for_ea(ea: int) -> dict[str, Any] | None:
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    return {
        "addr": hex_ea(func.start_ea),
        "end": hex_ea(func.end_ea),
        "name": ida_funcs.get_func_name(func.start_ea),
        "size": func.end_ea - func.start_ea,
    }


def resolve_name(name: str) -> int:
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return ea
    for suffix in ("@plt", "_0", "_1", "_2"):
        ea = ida_name.get_name_ea(idaapi.BADADDR, name + suffix)
        if ea != idaapi.BADADDR:
            return ea
    return idaapi.BADADDR


def collect_imports() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def cb(ea: int, symbol: str, ordinal: int) -> bool:
            name = symbol or f"#{ordinal}"
            if "ZIME" in name or "spice" in name.lower() or "QUIC" in name:
                rows.append({"addr": hex_ea(ea), "name": name, "module": module})
            return True

        ida_nalt.enum_import_names(i, cb)
    return rows


def xrefs_to(ea: int, limit: int = 80) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ref in idautils.XrefsTo(ea):
        caller = func_for_ea(ref.frm)
        rows.append(
            {
                "from": hex_ea(ref.frm),
                "type": str(ref.type),
                "caller": caller,
            }
        )
        if len(rows) >= limit:
            break
    return rows


def xrefs_from_calls(func_ea: int, limit: int = 120) -> list[dict[str, Any]]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    rows: list[dict[str, Any]] = []
    for insn_ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.XrefsFrom(insn_ea, 0):
            if not ref.iscode:
                continue
            target_name = idc.get_name(ref.to) or ida_funcs.get_func_name(ref.to)
            if not target_name:
                target_name = hex_ea(ref.to) or ""
            rows.append(
                {
                    "from": hex_ea(insn_ea),
                    "to": hex_ea(ref.to),
                    "name": target_name,
                    "target_func": func_for_ea(ref.to),
                }
            )
            if len(rows) >= limit:
                return rows
    return rows


def function_strings(func_ea: int, limit: int = 80) -> list[dict[str, Any]]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    strings_by_ea = {s.ea: str(s) for s in idautils.Strings()}
    rows: list[dict[str, Any]] = []
    for insn_ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.DataRefsFrom(insn_ea):
            text = strings_by_ea.get(ref)
            if text is not None:
                rows.append({"from": hex_ea(insn_ea), "string_ea": hex_ea(ref), "text": text[:240]})
                if len(rows) >= limit:
                    return rows
    return rows


def decompile_snippet(func_ea: int, max_chars: int) -> dict[str, Any]:
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return {"ok": False, "error": "decompile returned None"}
        code = str(cfunc)
        return {
            "ok": True,
            "truncated": len(code) > max_chars,
            "code": code[:max_chars],
        }
    except Exception as exc:  # Hex-Rays can fail on individual functions.
        return {"ok": False, "error": str(exc)}


def analyze_function(name: str, max_decompile_chars: int) -> dict[str, Any]:
    ea = resolve_name(name)
    row: dict[str, Any] = {"query": name, "addr": hex_ea(ea)}
    if ea == idaapi.BADADDR:
        row["found"] = False
        return row
    row["found"] = True
    row["function"] = func_for_ea(ea)
    row["xrefs_to"] = xrefs_to(ea)
    func = ida_funcs.get_func(ea)
    if func:
        row["calls_from_function"] = xrefs_from_calls(func.start_ea)
        row["strings_from_function"] = function_strings(func.start_ea)
        row["decompile"] = decompile_snippet(func.start_ea, max_decompile_chars)
    return row


def find_strings() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for s in idautils.Strings():
        text = str(s)
        if any(pattern in text for pattern in STRING_PATTERNS):
            rows.append(
                {
                    "addr": hex_ea(s.ea),
                    "text": text[:240],
                    "xrefs_to": xrefs_to(s.ea, limit=20),
                }
            )
    return rows


def find_link_flag_offset_uses(limit: int = 160) -> list[dict[str, Any]]:
    """Find static clues for proxy_sock->data_buf[224] / sock link flag use.

    This is intentionally conservative: it records disassembly lines that touch
    offset 0xe0/224 and their containing function, then includes a small
    decompiler snippet for the function. It does not inspect runtime state.
    """
    rows: list[dict[str, Any]] = []
    seen_funcs: set[int] = set()
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        hits: list[dict[str, Any]] = []
        for insn_ea in idautils.FuncItems(func.start_ea):
            line = idc.GetDisasm(insn_ea)
            if any(pattern in line for pattern in LINK_FLAG_OFFSET_PATTERNS):
                hits.append({"addr": hex_ea(insn_ea), "disasm": line})
            if len(hits) >= 12:
                break
        if hits:
            row: dict[str, Any] = {
                "function": func_for_ea(func.start_ea),
                "hits": hits,
                "calls_from_function": xrefs_from_calls(func.start_ea, limit=40),
                "strings_from_function": function_strings(func.start_ea, limit=20),
            }
            if func.start_ea not in seen_funcs:
                row["decompile"] = decompile_snippet(func.start_ea, 6000)
                seen_funcs.add(func.start_ea)
            rows.append(row)
            if len(rows) >= limit:
                break
    return rows


def _matching_lines(text: str, patterns: tuple[str, ...], context: int = 3) -> list[str]:
    lines = text.splitlines()
    indexes = [
        index for index, line in enumerate(lines)
        if any(pattern in line for pattern in patterns)
    ]
    selected: list[str] = []
    seen: set[int] = set()
    for index in indexes:
        start = max(0, index - context)
        end = min(len(lines), index + context + 1)
        if selected:
            selected.append("...")
        for line_index in range(start, end):
            if line_index in seen:
                continue
            selected.append(lines[line_index])
            seen.add(line_index)
    return selected


def find_link_flag_decompile_uses(limit: int = 80) -> list[dict[str, Any]]:
    """Scan decompiled functions for IceSocket link flag semantics.

    Unlike the raw 0xe0 offset scan, this favors recovered variable/field names
    such as data_buf[224], sock_link_type and bw_ctrl_link_type.
    """
    rows: list[dict[str, Any]] = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        snippet = decompile_snippet(func.start_ea, 32000)
        if not snippet.get("ok"):
            continue
        code = snippet.get("code", "")
        if not any(pattern in code for pattern in LINK_FLAG_DECOMPILE_PATTERNS):
            continue
        rows.append(
            {
                "function": func_for_ea(func.start_ea),
                "matchedPatterns": [
                    pattern for pattern in LINK_FLAG_DECOMPILE_PATTERNS if pattern in code
                ],
                "context": _matching_lines(code, LINK_FLAG_DECOMPILE_PATTERNS),
                "truncated": snippet.get("truncated"),
                "calls_from_function": xrefs_from_calls(func.start_ea, limit=60),
                "strings_from_function": function_strings(func.start_ea, limit=40),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def segments() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        rows.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": hex_ea(seg.start_ea),
                "end": hex_ea(seg.end_ea),
                "perm": seg.perm,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-decompile-chars", type=int, default=16000)
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    idapro.enable_console_messages(False)
    rc = idapro.open_database(str(binary), run_auto_analysis=True)
    if rc:
        print(f"failed to open database: rc={rc}")
        return 1
    ida_auto.auto_wait()

    try:
        report = {
            "binary": str(binary),
            "input_file": idaapi.get_input_file_path(),
            "imagebase": hex_ea(idaapi.get_imagebase()),
            "segments": segments(),
            "imports": collect_imports(),
            "strings": find_strings(),
            "link_flag_offset_uses": find_link_flag_offset_uses(),
            "link_flag_decompile_uses": find_link_flag_decompile_uses(),
            "functions": [
                analyze_function(name, args.max_decompile_chars) for name in TARGET_NAMES
            ],
        }
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(str(output))
        return 0
    finally:
        idapro.close_database()


if __name__ == "__main__":
    raise SystemExit(main())
