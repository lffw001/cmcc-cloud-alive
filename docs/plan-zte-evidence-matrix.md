# plan_zte_alive 证据矩阵

来源：`/home/demo/桌面/plan_zte_alive/plan.md`

本轮只使用该文件作为候选路线/假设库，不复制其中账号、密码、token、connectStr、
accessToken、cpsid 或任何 auth/local proxy payload。文件本地校验信息：

- 行数：350
- SHA-256：`5bcec05515f11c062958fa810d0deda1fd54b86668e773969bd265828ca2c22c`
- privacy：local

## 执行原则

当前唯一有效 gate 仍是：

`cmd26 local proxy bootstrap -> AUTH_HEAD199 -> same-fd/same-remote ACK-like71 -> AUTH_DATA241`

未拿到 Python live accepted report 前，plan 中涉及 CAG TCP/TLS、mux、raw SPICE、
DISPLAY_INIT、ACK/PONG、native bridge 或 40 分钟 verified-run 的步骤全部暂缓。

## 矩阵

| plan 候选项 | 本仓库证据状态 | 可执行动作 | 与 AUTH gate 的关系 |
|---|---|---|---|
| 产品 route-check / 判断 SCG 或 ZTE | 已落地 `product-route-check` 控制面脱敏报告；依据 `getFirmAuth` 的 `cag*` 与 `scg*` 字段族分类 | 可用 `python3 bin/cmcc_cloud_alive.py --state .tmp/state.json product-route-check --report-file reports/product-route-check.json` 做 fresh 控制面检查 | 只证明控制面材料路线，不证明 71-byte ACK-like |
| fresh CAG material | 已有 `rap-zime-kcp-auth-from-cag`，支持 state-backed fresh fetch 与 explicit material；报告只保存结构摘要 | 仅用于 AUTH gate-only live 或 preflight，不把 material 明文写入报告 | 可为 AUTH_HEAD199/AUTH_DATA241 构造提供输入 |
| local proxy cmd26 bootstrap | 已 live 复现 send160 和 status/control response；四个 native side effects 已有 gate-only state model | 继续围绕 cmd26 后 native readiness/source/session 绑定查缺口 | 是 AUTH_HEAD 前置条件，但当前不足以换来 ACK-like71 |
| CAG TCP/TLS/mux/raw SPICE | 与当前官方 fresh trace 的 AUTH gate 证据链未闭合；没有 Python accepted report | 暂缓，除非 IDA/trace 证明它是 AUTH_HEAD 前的直接缺口 | 当前冻结，避免在未通道处演示后续协议 |
| DISPLAY_INIT / ACK/PONG / 40 分钟 verified-run | 被硬约束冻结 | 不执行 | 必须等 AUTH gate accepted 后恢复 |

## 新增信息

- `product-route-check` 对应官方控制面字段，不对应官方 UDP trace 中的 71-byte ACK-like。
- 它的输出只能回答“当前套餐控制面材料更像 ZTE CAG、SCG、混合还是缺材料”，不能替代
  `authGateAcceptance.authGateOnlyAccepted=true`。
- 当前突破口仍是 `listen_udp_data_thread_ice_deal_sock_loop`，以及它是否影响同 socket
  接收 `AUTH_HEAD` 后的 71-byte ACK-like。
