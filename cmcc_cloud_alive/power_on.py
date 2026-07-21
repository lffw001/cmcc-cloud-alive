"""L0 real power-on gate for simple keepalive (mode1 / mode2).

Protocol-required, branch-exclusive:
  - ZTE family (IPv4 / IPv6 / IPv6-raw-ZTEC) → run_material(do_start=True)
    → /cs/cs_startDesktop.action on cagIp:cagPort
  - SCG → get_connect_info (+ wait_vm_ready inside) → CEM open-portal
  - Never cross-branch probe; never silent fall-through to L1 on failure.

Hard success condition: cloud.is_running(status) after boot path.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from . import cloud, core, product_router, scg_route, token, zte_route


# Result kinds (stable contract for main.py)
RESULT_ALREADY_RUNNING = "alreadyRunning"
RESULT_POWERED_ON = "poweredOn"
RESULT_SOFT_FAILURE = "softFailure"
RESULT_HARD_FAILURE = "hardFailure"
RESULT_ROUTE_MISMATCH = "routeMismatch"

_ZTE_SOFT_HINTS = (
    "104",
    "startresultcode=104",
    "启动时间过长",
    "维护",
    "maintenance",
    "maintain",
    "升级",
    "powered off",
    "poweroff",
    "关机",
    "已关机",
    "停机",
    "busy",
    "too many",
)

_ZTE_TOKEN_HINTS = (
    "1000100",
    "token",
    "access_token",
    "unauthorized",
    "鉴权",
    "登录失效",
    "session",
    "expired",
)


def normalize_protocol(protocol: Any) -> str:
    """Normalize user/CLI protocol to ZTE | SCG.

    IPv4 / IPv6 / IPv6-raw-ZTEC all map to the ZTE power-on branch.
    Empty / unknown → empty string (caller returns hardFailure).
    """
    raw = str(protocol or "").strip().upper()
    if not raw:
        return ""
    if raw == "SCG":
        return "SCG"
    # ZTE family aliases
    if raw in ("ZTE", "IPV4", "IPV6", "IPV6-RAW-ZTEC", "RAW-ZTEC", "ZTEC"):
        return "ZTE"
    if "SCG" in raw:
        return "SCG"
    if "ZTE" in raw or "ZTEC" in raw:
        return "ZTE"
    return raw  # pass-through; will hard-fail if not ZTE/SCG


def _result(
    kind: str,
    *,
    status: Any = None,
    protocol: str = "",
    branch: str = "",
    error: str = "",
    detail: Optional[Dict[str, Any]] = None,
    soft: bool = False,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "result": kind,
        "ok": kind in (RESULT_ALREADY_RUNNING, RESULT_POWERED_ON),
        "soft": soft or kind == RESULT_SOFT_FAILURE,
        "protocol": protocol,
        "branch": branch,
        "status": status,
        "error": error or "",
        "detail": detail or {},
    }
    return out


def _is_running_status(status: Any) -> bool:
    try:
        return bool(cloud.is_running(status))
    except Exception:
        return False


def _poll_running(
    target: str,
    state_path: Any,
    *,
    boot_wait: float,
    poll_interval: float = 5.0,
) -> Any:
    """Poll cloud.status until is_running or boot_wait exhausted. Returns last status."""
    deadline = time.time() + max(0.0, float(boot_wait))
    last = None
    while True:
        try:
            last = cloud.status(target, state_path)
        except Exception:
            last = last  # keep previous
        if last is not None and _is_running_status(last):
            return last
        if time.time() >= deadline:
            return last
        time.sleep(max(0.5, float(poll_interval)))


def _classify_zte_error(err_text: str) -> str:
    """Return softFailure | hardFailure | tokenRetry for a ZTE control-plane error string."""
    low = (err_text or "").lower()
    if any(h in low for h in _ZTE_TOKEN_HINTS) or "1000100" in (err_text or ""):
        return "tokenRetry"
    if any(h in low for h in _ZTE_SOFT_HINTS):
        return RESULT_SOFT_FAILURE
    # startResultCode embedded
    if "startresultcode" in low and "104" in low:
        return RESULT_SOFT_FAILURE
    return RESULT_HARD_FAILURE


def _load_firm_auth(target: str, state_path: Any) -> Dict[str, Any]:
    args = core.argparse.Namespace(
        state=state_path,
        user_service_id=cloud.selected_user_service_id(state_path, target),
    )
    return core.get_firm_auth(args)


def _power_on_zte(
    target: str,
    state_path: Any,
    *,
    boot_wait: float,
    timeout: float,
    allow_token_retry: bool = True,
) -> Dict[str, Any]:
    branch = "ZTE"
    try:
        auth = _load_firm_auth(target, state_path)
    except Exception as exc:  # noqa: BLE001
        return _result(
            RESULT_HARD_FAILURE,
            protocol="ZTE",
            branch=branch,
            error="get_firm_auth failed: %s" % exc,
        )

    route = product_router.classify_firm_auth_route(auth)
    if route.kind == product_router.RouteKind.SCG:
        return _result(
            RESULT_ROUTE_MISMATCH,
            protocol="ZTE",
            branch=branch,
            error="protocol=ZTE but firmAuth has scAuthCode (SCG route); refuse cross-branch",
            detail={"routeKind": route.kind.value, "reason": route.reason},
        )

    zte_fields = product_router.extract_zte_fields(auth)
    if not product_router.zte_fields_complete(zte_fields):
        return _result(
            RESULT_HARD_FAILURE,
            protocol="ZTE",
            branch=branch,
            error="ZTE fields incomplete: %s" % route.reason,
            detail={"routeKind": getattr(route.kind, "value", str(route.kind))},
        )

    firm = zte_route.ZTEFirmAuth.from_auth_dict(auth)
    vm_id = firm.vm_id or zte_fields.get("vmId") or ""
    try:
        report = zte_route.run_material(
            firm,
            target_vm_id=vm_id or zte_route.TARGET_VM_ID,
            do_start=True,
        )
    except Exception as exc:  # noqa: BLE001
        kind = _classify_zte_error("%s" % exc)
        if kind == "tokenRetry" and allow_token_retry:
            try:
                token.ensure_token(state_path, relogin=True, force=True)
            except Exception as tok_exc:  # noqa: BLE001
                return _result(
                    RESULT_HARD_FAILURE,
                    protocol="ZTE",
                    branch=branch,
                    error="token re-login failed after ZTE error: %s / %s" % (exc, tok_exc),
                )
            return _power_on_zte(
                target,
                state_path,
                boot_wait=boot_wait,
                timeout=timeout,
                allow_token_retry=False,
            )
        res_kind = RESULT_SOFT_FAILURE if kind == RESULT_SOFT_FAILURE else RESULT_HARD_FAILURE
        return _result(
            res_kind,
            protocol="ZTE",
            branch=branch,
            error="run_material raised: %s" % exc,
            soft=(res_kind == RESULT_SOFT_FAILURE),
        )

    if not getattr(report, "ok", False):
        err = getattr(report, "error", "") or "run_material not ok"
        kind = _classify_zte_error(err)
        if kind == "tokenRetry" and allow_token_retry:
            try:
                token.ensure_token(state_path, relogin=True, force=True)
            except Exception as tok_exc:  # noqa: BLE001
                return _result(
                    RESULT_HARD_FAILURE,
                    protocol="ZTE",
                    branch=branch,
                    error="token re-login failed after material error: %s / %s" % (err, tok_exc),
                    detail=report.to_dict() if hasattr(report, "to_dict") else {},
                )
            return _power_on_zte(
                target,
                state_path,
                boot_wait=boot_wait,
                timeout=timeout,
                allow_token_retry=False,
            )
        res_kind = RESULT_SOFT_FAILURE if kind == RESULT_SOFT_FAILURE else RESULT_HARD_FAILURE
        return _result(
            res_kind,
            protocol="ZTE",
            branch=branch,
            error=err,
            soft=(res_kind == RESULT_SOFT_FAILURE),
            detail=report.to_dict() if hasattr(report, "to_dict") else {},
        )

    # Material OK → poll portal status until running (or timeout)
    status = _poll_running(target, state_path, boot_wait=boot_wait)
    if _is_running_status(status):
        return _result(
            RESULT_POWERED_ON,
            status=status,
            protocol="ZTE",
            branch=branch,
            detail=report.to_dict() if hasattr(report, "to_dict") else {},
        )

    # Material said ok but portal still off → treat as soft (maintenance lag) if hints match
    snap_text = ""
    if isinstance(status, dict):
        snap_text = str(status.get("vmStatusShow") or status.get("vmStatus") or "")
    err = "ZTE material ok but cloud not running after boot_wait=%ss (%s)" % (
        int(boot_wait),
        snap_text or "no status",
    )
    return _result(
        RESULT_SOFT_FAILURE,
        status=status,
        protocol="ZTE",
        branch=branch,
        error=err,
        soft=True,
        detail=report.to_dict() if hasattr(report, "to_dict") else {},
    )


# SCG CEM getConnectInfo can stall on cold boot / platform slow path.
# Per-request budget 120–160s (default 140); limited retries on recoverable errors.
_SCG_CONNECT_TIMEOUT_DEFAULT = 140.0
_SCG_CONNECT_TIMEOUT_MIN = 120.0
_SCG_CONNECT_TIMEOUT_MAX = 160.0
_SCG_CONNECT_ATTEMPTS = 3  # 1 initial + 2 retries on recoverable/timeout


def _scg_connect_timeout(timeout: float) -> float:
    """Clamp SCG control-plane per-request timeout into [120, 160] unless explicitly lower test value."""
    t = float(timeout)
    # Preserve short timeouts used by unit tests (e.g. boot_wait=1 style harnesses).
    if t > 0 and t < _SCG_CONNECT_TIMEOUT_MIN:
        return t
    if t <= 0:
        return _SCG_CONNECT_TIMEOUT_DEFAULT
    return max(_SCG_CONNECT_TIMEOUT_MIN, min(_SCG_CONNECT_TIMEOUT_MAX, t))


def _power_on_scg(
    target: str,
    state_path: Any,
    *,
    boot_wait: float,
    timeout: float,
) -> Dict[str, Any]:
    branch = "SCG"
    try:
        auth = _load_firm_auth(target, state_path)
    except Exception as exc:  # noqa: BLE001
        return _result(
            RESULT_HARD_FAILURE,
            protocol="SCG",
            branch=branch,
            error="get_firm_auth failed: %s" % exc,
        )

    sc_auth_code = product_router.extract_sc_auth_code(auth) or ""
    zte_fields = product_router.extract_zte_fields(auth)
    vm_id = zte_fields.get("vmId") or ""
    if not sc_auth_code:
        # Refuse cross-branch to startDesktop
        return _result(
            RESULT_ROUTE_MISMATCH if product_router.zte_fields_complete(zte_fields) else RESULT_HARD_FAILURE,
            protocol="SCG",
            branch=branch,
            error="protocol=SCG but scAuthCode empty; refuse ZTE startDesktop cross-branch",
        )
    if not vm_id:
        return _result(
            RESULT_HARD_FAILURE,
            protocol="SCG",
            branch=branch,
            error="SCG power-on missing vmId",
        )

    try:
        state = core.load_state(state_path)
        cfg = core.client_config(state)
        device_id = core.profile_device_id(state, cfg)
    except Exception:
        device_id = ""

    req_timeout = _scg_connect_timeout(timeout)
    connect_info: Dict[str, Any] = {}
    last_exc: Optional[BaseException] = None
    last_tags: Dict[str, Any] = {}
    for attempt in range(1, _SCG_CONNECT_ATTEMPTS + 1):
        try:
            # get_connect_info triggers SCG VM boot; wait_vm_ready is inside when needed
            connect_info = scg_route.get_connect_info(
                sc_auth_code,
                vm_id,
                device_id=device_id,
                timeout=req_timeout,
            )
            last_exc = None
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            last_tags = scg_route.classify_scg_soft_failure(exc)
            soft = bool(
                last_tags.get("recoverable") or last_tags.get("platform_maintenance")
            )
            if not soft or attempt >= _SCG_CONNECT_ATTEMPTS:
                return _result(
                    RESULT_SOFT_FAILURE if soft else RESULT_HARD_FAILURE,
                    protocol="SCG",
                    branch=branch,
                    error="get_connect_info failed: %s" % exc,
                    soft=soft,
                    detail={
                        "scgTags": last_tags,
                        "attempts": attempt,
                        "timeout": req_timeout,
                    },
                )
            # Recoverable/timeout: brief backoff then retry
            time.sleep(min(5.0 * attempt, 15.0))
    if last_exc is not None:
        soft = bool(
            last_tags.get("recoverable") or last_tags.get("platform_maintenance")
        )
        return _result(
            RESULT_SOFT_FAILURE if soft else RESULT_HARD_FAILURE,
            protocol="SCG",
            branch=branch,
            error="get_connect_info failed: %s" % last_exc,
            soft=soft,
            detail={
                "scgTags": last_tags,
                "attempts": _SCG_CONNECT_ATTEMPTS,
                "timeout": req_timeout,
            },
        )

    status = _poll_running(target, state_path, boot_wait=boot_wait)
    if _is_running_status(status):
        return _result(
            RESULT_POWERED_ON,
            status=status,
            protocol="SCG",
            branch=branch,
            detail={
                "readyStatus": connect_info.get("readyStatus"),
                "hasScgIp": bool(connect_info.get("scgIp")),
                "hasTraceId": bool(connect_info.get("traceId")),
            },
        )

    snap_text = ""
    if isinstance(status, dict):
        snap_text = str(status.get("vmStatusShow") or status.get("vmStatus") or "")
    return _result(
        RESULT_SOFT_FAILURE,
        status=status,
        protocol="SCG",
        branch=branch,
        error="SCG getConnectInfo ok but cloud not running after boot_wait=%ss (%s)" % (
            int(boot_wait),
            snap_text or "no status",
        ),
        soft=True,
        detail={
            "readyStatus": connect_info.get("readyStatus"),
            "hasScgIp": bool(connect_info.get("scgIp")),
        },
    )


def ensure_powered_on(
    target,
    state_path,
    protocol,
    *,
    boot_wait: float = 180,
    timeout: float = _SCG_CONNECT_TIMEOUT_DEFAULT,
    poll_interval: float = 5.0,  # reserved / documented; used via _poll_running default
) -> Dict[str, Any]:
    """Ensure desktop is powered on using the protocol-correct control-plane path.

    Parameters
    ----------
    target : userServiceId (or selectable target)
    state_path : state file path
    protocol : required — ZTE | SCG (IPv4/IPv6/raw-ZTEC normalize to ZTE)
    boot_wait : seconds to poll cloud.is_running after triggering boot
    timeout : per-request timeout for control-plane calls
        SCG getConnectInfo clamped to 120–160s (default 140) with limited retries.
        Values < 120 are kept as-is for unit tests / deliberate short budgets.

    Returns
    -------
    dict with keys:
      result: alreadyRunning | poweredOn | softFailure | hardFailure | routeMismatch
      ok: bool (True only for alreadyRunning / poweredOn)
      soft: bool
      protocol, branch, status, error, detail
    """
    # Resolve target
    usid = cloud.selected_user_service_id(state_path, target)

    # Status first — already running is a pure no-op (no startDesktop / getConnectInfo)
    try:
        status = cloud.status(usid, state_path)
    except Exception as exc:  # noqa: BLE001
        return _result(
            RESULT_HARD_FAILURE,
            protocol=normalize_protocol(protocol) or str(protocol or ""),
            error="cloud.status failed: %s" % exc,
        )

    if _is_running_status(status):
        return _result(
            RESULT_ALREADY_RUNNING,
            status=status,
            protocol=normalize_protocol(protocol) or str(protocol or ""),
            branch="none",
        )

    p = normalize_protocol(protocol)
    if p == "ZTE":
        return _power_on_zte(usid, state_path, boot_wait=boot_wait, timeout=timeout)
    if p == "SCG":
        return _power_on_scg(usid, state_path, boot_wait=boot_wait, timeout=timeout)

    return _result(
        RESULT_HARD_FAILURE,
        protocol=str(protocol or ""),
        error="protocol required and must be ZTE|SCG (got %r); refuse default connectDesktop" % (protocol,),
    )
