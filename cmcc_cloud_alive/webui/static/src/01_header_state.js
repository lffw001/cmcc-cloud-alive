/* HARD_GATE#845 CARD_H_LOG_CLEAR_GLOBAL */
/* HARD_GATE#834 PAIN_FIX_BATCH */
/* CMCC Alive WebUI — multi-account console */
(function () {
  "use strict";

  const TOKEN_KEY = "cmcc_webui_token";

  const state = {
    profiles: [],
    configPid: null,
    drafts: Object.create(null),
    logs: Object.create(null),
    globalLog: [],
    busy: Object.create(null),
    cardMsg: Object.create(null),
    desktops: Object.create(null),
    jobsById: Object.create(null),
    jobsByProfile: Object.create(null),
    tokenRequired: false,
    setupRequired: false,
    authEnabled: false,
    authSource: "",
    gateMode: "", // "setup" | "login" | ""
    es: null,
    sseNeedTokenLogged: false,
    logModalPid: null,
    logModalReturnFocus: null,
    composer: {
      /* HARD_GATE#871c: composer 初始占位；卡片以用户/档案选择为准，禁止全局强制 */
      protocol: "ZTE",
      clientProfile: "linux",
      mode: "live",
      userServiceId: "",
      desktopLabel: "",
      profileId: "",
    },
    /* HARD_GATE#871: 从日志/桌面列表缓存的云桌面状态文案 */
    desktopStatusByPid: Object.create(null),
  };

