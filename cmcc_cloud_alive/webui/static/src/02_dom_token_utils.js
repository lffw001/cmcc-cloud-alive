  function $(sel, root) {
    return (root || document).querySelector(sel);
  }

  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function toast(msg, isError) {
    const el = $("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.toggle("error", !!isError);
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(function () {
      el.classList.add("hidden");
    }, 2800);
  }

  function getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY) || "";
    } catch (_) {
      return "";
    }
  }

  function setToken(v) {
    try {
      if (v) localStorage.setItem(TOKEN_KEY, v);
      else localStorage.removeItem(TOKEN_KEY);
    } catch (_) { logCatch("catch", _); }
  }

  function logCatch(tag, e) {
    try {
      if (typeof console !== "undefined" && console.debug) {
        console.debug("[cmcc-webui]", tag, e);
      }
    } catch (_ignore) { logCatch("catch", _ignore); }
  }


  function persistClientProfile(pid, clientProfile) {
    if (!pid) return;
    const v = String(clientProfile || "linux").toLowerCase();
    api("/api/profiles/" + encodeURIComponent(pid), {
      method: "PATCH",
      body: { clientProfile: v },
    })
      .then(function (res) {
        const p = state.profiles.find(function (x) {
          return x.id === pid;
        });
        const finalV =
          (res && res.profile && res.profile.clientProfile) || v;
        if (p) p.clientProfile = finalV;
        if (state.drafts[pid]) state.drafts[pid].clientProfile = finalV;
      })
      .catch(function (err) {
        pushGlobal(
          "[" +
            pid +
            "] 客户端类型保存失败: " +
            ((err && err.message) || err),
          "error"
        );
      });
  }

  function updateTokenBtn() {
    const btn = document.getElementById("btn-token");
    if (!btn) return;
    const has = !!getToken();
    const enabled = !!state.authEnabled || !!state.tokenRequired;
    const need = enabled && !has;
    btn.classList.toggle("is-set", enabled && has);
    btn.classList.toggle("is-need", need);
    if (need) {
      btn.textContent = "设置令牌!";
      btn.title = "需要访问密钥，点击登录或管理";
    } else if (enabled && has) {
      btn.textContent = "令牌✓";
      btn.title = "鉴权已启用 · 点击管理（改密/清本机/关鉴权）";
    } else if (enabled) {
      btn.textContent = "设置令牌";
      btn.title = "服务器鉴权已启用，点击管理密钥";
    } else {
      btn.textContent = "鉴权关";
      btn.title = "服务器鉴权已关闭 · 点击可启用密钥";
    }
  }

