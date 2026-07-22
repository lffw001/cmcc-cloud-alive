  /* HARD_GATE#R3 JobStore: single write path for jobs maps + derived profile.job* */
  function _jobRank(st) {
    const s = String(st || "").toLowerCase();
    if (s === "running" || s === "alive" || s === "starting") return 3;
    if (s === "pending") return 2;
    if (s === "error" || s === "failed" || s === "fail") return 1;
    return 0; // stopped/idle/unknown
  }

  /**
   * Only mutator for state.jobsById / state.jobsByProfile.
   * profile.jobStatus / jobId / job are derived here (not independent truth).
   * opts.replace: no merge with prev (full snapshot from /api/jobs)
   * opts.force: always win profile slot (bulk loadJobs)
   */
  function upsertJob(data, opts) {
    opts = opts || {};
    if (!data || typeof data !== "object") return null;
    const jid = data.jobId || data.job_id || data.id || null;
    const pid = data.profileId || data.profile_id || data.accountId || data.account_id || null;
    if (!jid && !pid) return null;

    const prev =
      (jid && state.jobsById[jid]) ||
      (pid && state.jobsByProfile[pid]) ||
      null;
    const merged = opts.replace
      ? Object.assign({}, data)
      : Object.assign({}, prev || {}, data);
    if (jid) {
      merged.id = merged.id || jid;
      merged.jobId = merged.jobId || jid;
      state.jobsById[jid] = merged;
    }
    if (pid) {
      merged.profileId = merged.profileId || pid;
      const prevProf = state.jobsByProfile[pid];
      const sameJob =
        prevProf &&
        String(prevProf.id || prevProf.jobId || "") ===
          String(merged.id || merged.jobId || jid || "");
      if (
        !prevProf ||
        sameJob ||
        _jobRank(merged.status) >= _jobRank(prevProf && prevProf.status) ||
        opts.force
      ) {
        state.jobsByProfile[pid] = merged;
      }
      const chosen = state.jobsByProfile[pid] || merged;
      const pSync = state.profiles.find(function (x) {
        return x && x.id === pid;
      });
      if (pSync) {
        pSync.jobStatus = chosen.status || merged.status || pSync.jobStatus;
        pSync.jobId = chosen.id || chosen.jobId || jid || pSync.jobId;
        if (!pSync.job || typeof pSync.job !== "object") pSync.job = {};
        pSync.job = Object.assign({}, pSync.job, chosen);
      }
    }
    return (pid && state.jobsByProfile[pid]) || merged;
  }

  function resolveUserProtocol() {
    /* HARD_GATE#871c: user choice only — never force SCG globally */
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v == null || v === "") continue;
      var u = String(v).toUpperCase();
      if (u === "ZX" || u === "ZHONGXING") u = "ZTE";
      if (u === "SANGFOR") u = "SCG";
      if (u === "ZTE" || u === "SCG") return u;
    }
    return "ZTE"; /* historical empty-only fallback, not product default force */
  }

  function ensureDraft(pid, p) {
    const job = jobOf(p);
    const protocol =
      resolveUserProtocol(p && p.protocol, p && p.lastOfficialProtocol, p && p.protocolHint, job && job.protocol);
    const mode =
      (p && p.mode) ||
      (job && job.mode) ||
      "live";
    // HARD_GATE#ye4: preserve main/sub account flag from profile (config save/start re-login)
    const isSub =
      !!(p && (p.isSubAccount === true || String(p.loginMode || "").toLowerCase().indexOf("sub") === 0));
    const loginMode = isSub ? "sub" : ((p && p.loginMode) || "main");
    if (!state.drafts[pid]) {
      state.drafts[pid] = {
        displayName: (p && p.displayName) || "",
        username: "",
        password: "",
        protocol: protocol,
        lastOfficialProtocol: protocol,
        clientProfile: (p && p.clientProfile) || "linux",
        mode: mode,
        intervalMin: 5,
        trafficSec: 60,
        durationSec: durationForMode(mode, 60),
        userServiceId: (p && p.userServiceId) || "",
        desktopLabel: (p && p.desktopLabel) || "",
        spuCode: (p && (p.spuCode || p.spu_code)) || "",
        isSubAccount: isSub,
        loginMode: loginMode,
      };
    } else if (p) {
      const d = state.drafts[pid];
      if (!d.displayName && p.displayName) d.displayName = p.displayName;
      if (!d.userServiceId && p.userServiceId) d.userServiceId = p.userServiceId;
      if (!d.desktopLabel && p.desktopLabel) d.desktopLabel = p.desktopLabel;
      if (!d.spuCode && p && (p.spuCode || p.spu_code)) {
        d.spuCode = p.spuCode || p.spu_code;
      }
      if (!d.clientProfile && p.clientProfile) d.clientProfile = p.clientProfile;
      if (p.protocol) {
        d.protocol = p.protocol;
        d.lastOfficialProtocol = p.protocol;
      } else if (job && job.protocol) {
        d.protocol = job.protocol;
        if (!d.lastOfficialProtocol) d.lastOfficialProtocol = job.protocol;
      }
      if (!d.lastOfficialProtocol) d.lastOfficialProtocol = d.protocol || "ZTE";
      if (p.mode) d.mode = p.mode;
      else if (job && job.mode) d.mode = job.mode;
      // keep draft isSub unless profile explicitly changes it
      if (d.isSubAccount == null) d.isSubAccount = isSub;
      if (!d.loginMode) d.loginMode = loginMode;
      if (p.isSubAccount === true || String(p.loginMode || "").toLowerCase().indexOf("sub") === 0) {
        d.isSubAccount = true;
        d.loginMode = "sub";
      }
    }
    if (!state.drafts[pid].lastOfficialProtocol) {
      state.drafts[pid].lastOfficialProtocol = resolveUserProtocol(state.drafts[pid].protocol, state.drafts[pid].lastOfficialProtocol);
    }
    return state.drafts[pid];
  }

  /** Resolve main/sub for re-login from draft + profile (config save/start). */
  function resolveLoginMode(d, p) {
    if (d && (d.isSubAccount === true || String(d.loginMode || "").toLowerCase().indexOf("sub") === 0)) {
      return "sub";
    }
    if (p && (p.isSubAccount === true || String(p.loginMode || "").toLowerCase().indexOf("sub") === 0)) {
      return "sub";
    }
    if (d && d.loginMode) return String(d.loginMode).toLowerCase().indexOf("sub") === 0 ? "sub" : "main";
    return "main";
  }

  // HARD_GATE#global-run-log: FE mirrors backend page log; never sole source of truth
