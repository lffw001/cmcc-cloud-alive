  async function loadJobs() {
    try {
      const data = await api("/api/jobs");
      const jobs = (data && data.jobs) || data || [];
      const list = Array.isArray(jobs) ? jobs : [];
      // HARD_GATE#R3: wipe then single-writer rebuild
      state.jobsById = Object.create(null);
      state.jobsByProfile = Object.create(null);
      for (let i = 0; i < list.length; i++) {
        upsertJob(list[i] || {}, { replace: true, force: true });
      }
    } catch (e) {
      logCatch("loadJobs", e);
    }
  }

  async function loadProfiles(forceExpandNone) {
    try {
      await loadJobs();
      const data = await api("/api/profiles");
      /* HARD_GATE#851: never show draft profiles on timeline */
      state.profiles = ((data && data.profiles) || []).filter(function (p) {
        return p && !p.draft && p.draft !== true && p.draft !== 1 && p.draft !== "1";
      });
      for (let i = 0; i < state.profiles.length; i++) {
        ensureDraft(state.profiles[i].id, state.profiles[i]);
      }
      if (forceExpandNone) {
        /* config modal pid kept independently */
      }
      renderCards();
    } catch (e) {
      toast(humanError(e, "列表加载失败"), true);
      pushGlobal("列表加载失败: " + humanError(e), "error");
    }
  }

  async function loadLogs(pid, toastOk) {
    // HARD_GATE#855/#854 LOG_POLL_6S: pull + fingerprint paint; empty API must not erase fresher local SSE buffer
    try {
      const data = await api(
        "/api/profiles/" + encodeURIComponent(pid) + "/logs"
      );
      const lines = (data && data.lines) || [];
      const prev = state.logs[pid] || [];
      const prevFp = logsFingerprint(prev);
      // If backend returns empty but local still has lines and this is not a forced refresh
      // after clear, keep local until next non-empty pull (SSE may be ahead of poll race).
      // Forced toastOk / explicit clear path already zeroed state.logs.
      if (lines.length === 0 && prev.length > 0 && !toastOk) {
        // keep prev; still ensure DOM painted
        applyLogsToDom(pid, false);
        return;
      }
      state.logs[pid] = lines;
    try { patchCardDeskStatus(pid); } catch (_e) { logCatch("catch", _e); }
      const nextFp = logsFingerprint(lines);
      if (toastOk || prevFp !== nextFp) applyLogsToDom(pid, !!toastOk);
      if (toastOk) toast("日志已刷新");
    } catch (e) {
      pushGlobal("[" + pid + "] 日志读取失败: " + humanError(e), "error");
    }
  }

  /** HARD_GATE#R2: one round-trip for many card logs; keeps #854/#855 empty+fingerprint rules. */
  async function loadLogsBatch(pids, toastOk) {
    const ids = (pids || []).filter(Boolean);
    if (!ids.length) return;
    try {
      const q = ids.map(function (x) { return encodeURIComponent(x); }).join(",");
      const data = await api("/api/logs/batch?profileIds=" + q + "&limit=200");
      const bag = (data && data.logs) || {};
      ids.forEach(function (pid) {
        const lines = Array.isArray(bag[pid]) ? bag[pid] : [];
        const prev = state.logs[pid] || [];
        if (!toastOk && (!lines || !lines.length) && prev.length) {
          // empty API must not erase fresher local SSE buffer
          return;
        }
        const prevFp = logsFingerprint(prev);
        state.logs = state.logs || {};
        state.logs[pid] = lines;
        const nextFp = logsFingerprint(lines);
        if (toastOk || prevFp !== nextFp) applyLogsToDom(pid, !!toastOk);
      });
      if (toastOk) toast("日志已刷新");
    } catch (e) {
      pushGlobal("批量日志读取失败: " + humanError(e), "error");
    }
  }

  function logsFingerprint(lines) {
    const arr = lines || [];
    if (!arr.length) return "0";
    const last = arr[arr.length - 1] || {};
    return String(arr.length) + "|" + String(last.at || "") + "|" + String(last.line || "");
  }

  function applyLogsToDom(pid, force) {
    // HARD_GATE#841: paint last-6 (or full modal); never invent blank rows
    if (!pid) return;
    /* HARD_GATE#871: keep 云桌面状态 fresh from log lines */
    try {
      const st = extractDesktopStatusFromLogs(pid);
      if (st) {
        const chip = document.querySelector(
          '.card[data-id="' + pid + '"] [data-desk-status]'
        );
        if (chip && chip.textContent !== st) {
          chip.textContent = st;
          chip.setAttribute("title", st);
        }
      }
    } catch (e) { logCatch("catch", e); }
    const fp = logsFingerprint(state.logs[pid]);
    const panel =
      $('.log-viewport[data-log="' + pid + '"]') ||
      $('.log-box[data-log="' + pid + '"]') ||
      $('[data-log="' + pid + '"]');
    if (panel) {
      if (force || panel.getAttribute('data-log-fp') !== fp) {
        panel.innerHTML = profileLogsHtml(pid);
        panel.setAttribute('data-log-fp', fp);
        // pin latest (defensive even with only 6 rows)
        const pin = function () {
          panel.scrollTop = panel.scrollHeight;
        };
        pin();
        requestAnimationFrame(function () {
          pin();
          requestAnimationFrame(pin);
        });
      }
    }
    const body = $('#log-full-body');
    const modal = $('#log-modal') || $('#log-full-modal');
    const modalPid = modal
      ? String(modal.getAttribute('data-pid') || state.logModalPid || '')
      : '';
    if (
      body &&
      modal &&
      !modal.classList.contains('hidden') &&
      modal.getAttribute('aria-hidden') !== 'true' &&
      modalPid === String(pid)
    ) {
      const mfp = 'full:' + fp;
      if (force || body.getAttribute('data-log-fp') !== mfp) {
        body.innerHTML = profileLogsHtml(pid, { full: true });
        body.setAttribute('data-log-fp', mfp);
        body.scrollTop = body.scrollHeight;
      }
    }
  }

  
  function clearSavedToken(opts) {
    opts = opts || {};
    setToken("");
    state.sseNeedTokenLogged = false;
    if (state.es) {
      try {
        state.es.close();
      } catch (_) { logCatch("catch", _); }
      state.es = null;
    }
    loadSys().then(function () {
      if (state.tokenRequired) {
        pushGlobal("已清除本机令牌 · 需重新填写后才能连接事件流", "error");
      } else {
        connectSSE();
      }
    });
    if (opts.toast !== false) toast("已清除本机令牌");
  }

  async function loadSys() {
    // Prefer public auth status so gate can render even before local token.
    try {
      await refreshAuthStatus();
    } catch (_) { logCatch("catch", _); }
    try {
      const info = await api("/api/system/info");
      if (info) {
        if (typeof info.tokenRequired === "boolean") state.tokenRequired = !!info.tokenRequired;
        if (typeof info.setupRequired === "boolean") state.setupRequired = !!info.setupRequired;
        if (typeof info.authEnabled === "boolean") state.authEnabled = !!info.authEnabled;
        else state.authEnabled = !!state.tokenRequired;
        state.authSource = info.tokenSource || info.authSource || state.authSource || "";
      }
      const el = $("#sys-info");
      if (el) {
        const src = state.authSource ? " · 源:" + state.authSource : "";
        const flag = state.setupRequired
          ? " · 待首次设置"
          : state.authEnabled || state.tokenRequired
            ? " · 鉴权开"
            : " · 鉴权关";
        el.textContent =
          "服务 " +
          ((info && info.service) || "cmcc-cloud-alive") +
          " · v" +
          ((info && info.version) || "?") +
          flag +
          src;
      }
      updateTokenBtn();
    } catch (e) {
      const code = (e && (e.code || (e.error && e.error.code))) || "";
      if (
        e &&
        (e.status === 401 ||
          code === "AUTH_FAILED" ||
          code === "AUTH_REQUIRED" ||
          code === "TOKEN_REQUIRED" ||
          code === "SETUP_REQUIRED")
      ) {
        state.tokenRequired = true;
        state.authEnabled = true;
        if (code === "SETUP_REQUIRED") state.setupRequired = true;
      }
      const el = $("#sys-info");
      if (el) {
        el.textContent = state.setupRequired
          ? "服务 · 待首次设置"
          : state.authEnabled || state.tokenRequired
            ? "服务 · 鉴权开"
            : "服务 · 鉴权关";
      }
    }
    updateTokenBtn();
  }

