  function unwrapApiError(raw) {
    // BE api_error shape: { ok:false, error:{ code, message, nextStep? } }
    // Also accept flat { code, message } and thrown Error with .payload/.data
    if (!raw || typeof raw !== "object") return { code: "", message: "", nextStep: "" };
    const nested =
      (raw.error && typeof raw.error === "object" && raw.error) ||
      (raw.payload && raw.payload.error && typeof raw.payload.error === "object" && raw.payload.error) ||
      (raw.data && raw.data.error && typeof raw.data.error === "object" && raw.data.error) ||
      null;
    const src = nested || raw;
    const codeRaw = src.code || src.error_code || (!nested && typeof raw.error === "string" ? raw.error : "") || "";
    const code = typeof codeRaw === "string" || typeof codeRaw === "number" ? String(codeRaw) : "";
    const message =
      (typeof src.message === "string" && src.message) ||
      (typeof src.detail === "string" && src.detail) ||
      (typeof src.error_message === "string" && src.error_message) ||
      (typeof raw.message === "string" && raw.message) ||
      "";
    const nextStep =
      src.nextStep ||
      src.next_step ||
      raw.nextStep ||
      raw.next_step ||
      (raw.payload && (raw.payload.nextStep || raw.payload.next_step)) ||
      (raw.data && (raw.data.nextStep || raw.data.next_step)) ||
      "";
    return { code: code, message: message, nextStep: nextStep || "" };
  }

  function humanError(err, fallback) {
    if (!err) return fallback || "操作失败";
    if (typeof err === "string") return err;
    const u = unwrapApiError(err);
    const code = u.code || "";
    const msg = u.message || "";
    const next = u.nextStep || "";
    const map = {
      PROFILE_IN_USE: "该卡片已在保活中，请先停止再启动",
      USID_IN_USE: "该桌面已在另一张卡保活中，请先停止那张卡再启动",
      VALIDATION: "填写有误，请检查账号、密码或配置",
      NOT_FOUND: "账号不存在或已删除",
      UNAUTHORIZED: "未授权，请检查访问令牌",
      FORBIDDEN: "没有权限执行此操作",
      LIVE_DISABLED: "当前环境未开启长期保活，请改用「单轮」或联系管理员",
      LOGIN_FAILED: "登录失败，请检查账号密码",
      AUTH_FAILED: "账号或密码错误",
      AUTH_EXPIRED: "登录会话失效，请重新登录",
      HTTP_401: "登录失败（401）：账号密码错误或会话失效",
      401: "登录失败（401）：账号密码错误或会话失效",
      AUTH_REQUIRED: "需要访问密钥",
      TOKEN_REQUIRED: "需要访问密钥",
      SETUP_REQUIRED: "请先完成首次访问密钥设置",
      TOKEN_INVALID: "访问密钥错误",
      LOGIN_REQUIRED: "请先登录账号",
      DESKTOP_REQUIRED: "请先选择云桌面再启动",
      NETWORK: "网络异常，请稍后重试",
    };
    let base = "";
    if (code && map[code]) {
      base = map[code];
      if (msg && /访问密钥|access token|webui_access_token|CMCC_WEBUI_TOKEN/i.test(msg)) {
        base = "访问密钥错误";
      } else if (msg && code === "AUTH_FAILED" && /4119|账号|密码|短验|扫码/.test(msg)) {
        base = "账号或密码错误（上游已拒绝）";
      }
    } else if (msg && typeof msg === "string") {
      if (/USID_IN_USE/i.test(msg)) base = map.USID_IN_USE;
      else if (/PROFILE_IN_USE/i.test(msg)) base = map.PROFILE_IN_USE;
      else if (/LIVE_DISABLED/i.test(msg)) base = map.LIVE_DISABLED;
      else if (/AUTH_REQUIRED/i.test(msg)) base = map.AUTH_REQUIRED;
      else if (/LOGIN_REQUIRED/i.test(msg)) base = map.LOGIN_REQUIRED;
      else if (/JSON|\{|\}|\[|\]/.test(msg) && msg.length > 120) {
        base = fallback || "服务返回异常，请稍后重试";
      } else base = msg;
    } else {
      base = fallback || "操作失败，请稍后重试";
    }
    if (next) {
      const n = String(next);
      if (base.indexOf(n) < 0) base = base + " · 下一步：" + n;
    }
    return base;
  }

  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign(
      { Accept: "application/json" },
      opts.headers || {}
    );
    const token = getToken();
    if (token) headers.Authorization = "Bearer " + token;
    let body = opts.body;
    if (body != null && typeof body !== "string") {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, {
        method: opts.method || "GET",
        headers: headers,
        body: body,
      });
    } catch (e) {
      const err = new Error("网络异常，请稍后重试");
      err.code = "NETWORK";
      throw err;
    }
    const text = await res.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_) {
        data = { raw: text };
      }
    }
    if (!res.ok) {
      const u = unwrapApiError(data || {});
      const err = new Error(
        humanError(
          data || {},
          "请求失败（" + res.status + "）"
        )
      );
      err.status = res.status;
      err.code = u.code || "";
      err.nextStep = u.nextStep || "";
      err.payload = data;
      err.data = data;
      err.message = humanError(err, err.message);
      throw err;
    }
    return data;
  }

  function statusOf(p) {
    // Prefer live job map (SSE/loadJobs) over stale profile.jobStatus.
    // HARD_GATE multi-card: badge must track real job, not last profiles poll.
    const j = jobOf(p);
    const raw =
      (j && (j.status || j.jobStatus)) ||
      (p && (p.status || (p.job && p.job.status) || p.jobStatus)) ||
      "idle";
    const s = String(raw).toLowerCase();
    if (s === "running" || s === "alive" || s === "starting" || s === "pending")
      return "running";
    if (s === "error" || s === "failed" || s === "fail") return "error";
    if (s === "stopped" || s === "stop" || s === "exited") return "stopped";
    return "idle";
  }

  function statusLabel(st) {
    if (st === "running") return "保活中";
    if (st === "error") return "异常";
    if (st === "stopped") return "已停止";
    return "空闲";
  }

  function protocolLabel(v) {
    /* HARD_GATE#871c: label from value; empty → 未选 */
    const raw = String(v || "").toUpperCase();
    if (!raw) return "未选";
    const u = raw;
    if (u === "ZTE" || u === "ZX" || u === "ZHONGXING") return "中兴";
    return "深信服";
  }

  function clientLabel(v) {
    const c = String(v || "linux").toLowerCase();
    if (c === "windows") return "Windows";
    if (c === "mac") return "Mac";
    return "Linux";
  }

  function modeLabel(v) {
    /* HARD_GATE#718: button/label text forever = 永久 / 单轮 only */
    const m = String(v || "live").toLowerCase();
    if (m === "dry-run" || m === "dryrun" || m === "once" || m === "single") return "单轮";
    return "永久";
  }

  function modeIsOnce(v) {
    const m = String(v || "live").toLowerCase();
    return m === "dry-run" || m === "dryrun" || m === "once" || m === "single";
  }

  /* #848: 永久/单轮都走 LIVE 真子进程；单轮用 once，不再映射 dry-run(FakeBackend) */
  function modeApi(v) {
    return modeIsOnce(v) ? "once" : "live";
  }

  function durationForMode(mode, trafficSec) {
    if (modeIsOnce(mode)) {
      const t = Number(trafficSec || 60);
      return t > 0 ? t : 60;
    }
    return 0;
  }

  function jobOf(p) {
    if (!p) return null;
    // Prefer live job maps (SSE/loadJobs) over embedded profile snapshot —
    // profile.job / stale jobId can lag after multi-card start/stop.
    if (p.id && state.jobsByProfile[p.id]) return state.jobsByProfile[p.id];
    if (p.jobId && state.jobsById[p.jobId]) return state.jobsById[p.jobId];
    if (p.job && typeof p.job === "object") return p.job;
    return null;
  }

