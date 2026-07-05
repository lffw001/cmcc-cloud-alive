# No-Spin Rules — 治理约束（先于一切，防止 research track 空转）

> 本文件是 cmcc-cloud-alive 项目的"防空转治理宪法"。任何执行 agent 在进入协议实现前必须先读本文，并遵守下列硬规则。违反任一条即视为空转，必须回退。

---

## 规则 1：research track 不阻塞 product route

`rap_zime.py`、`zime_probe.py`、`zime_native_bridge.py` 等 ZIME/逆向探测模块属于 **research track（研究轨）**，仅用于字节级证据采集与协议逆向验证，**不是 product default（产品默认路径）**。

- product route 的默认入口是 `product_router.route_check()` → `zte_route.run()` / `scg_route.run()`。
- research track does not block product route：研究轨的失败、未完成、信号 11 崩溃等一律不影响产品路径推进。产品路径以 B 成品 Go 源码逐行移植为准，不依赖研究轨结论。
- 禁止把研究轨的实验性变体当作产品实现提交。

## 规则 2：route-check 前不跑 live CAG/SCG

no live run before route-check：在 `product_router.route_check()` 判定出 `kind`（scg/zte/error）之前，**禁止**发起任何 live CAG TCP/TLS 连接、SCG 连接、raw SPICE 握手。

- route-check 只读控制面（firmAuth / HTTPS material），不建链、不发字节。
- 只有 `kind != error` 且通过闸门后，才允许进入对应路线的建链阶段。

## 规则 3：ZTE route 先 TCP/TLS，UDP/KCP 只做 fallback

ZTE CAG 外层传输优先走 **TCP/TLS 主路径**（对照 B: `internal/zte/cag_tcp.go` + `cag.go` 的 TLS upgrade）。

- TCP first, UDP fallback：UDP/KCP 仅在 TCP/TLS 主路径失败且具备新证据时作为 fallback 探索，不作为默认。
- 禁止在 TCP/TLS 未跑通前先开 UDP/KCP 变体。

## 规则 4：每次 live run 必须有 stage 字段

任何 live run（建链/握手/保活）的输出 report 必须包含统一 schema：

```
route / stage / ok / error / nextStep
```

- `route`：scg | zte | error
- `stage`：当前阶段标识（如 `zte_get_token`、`cag_tcp_dial`、`raw_main_init`、`display_loop`）
- `ok`：bool
- `error`：失败原因（成功为空），脱敏
- `nextStep`：下一步建议

缺 stage 字段的 report 视为不合格，必须补齐。

## 规则 5：禁止无证据变体实验

no new variant without one new evidence field：禁止凭空臆造新的协议变体/字节偏移/常量。任何新变体必须附带至少一个**新证据字段**（如抓包 hex、B 源码行号偏移、fake server 字节 fixture）。

- 字节偏移/常量/顺序一律以 B 成品 Go 源码为准（fork B，逐行对照）。
- 若 B 源码某处不明确，可登录云电脑客户端抓包逆向验证实际字节流，并将证据记录到 `docs/evidence/`。
- 无证据的变体实验一律回退，不计入产品实现。

---

## 保活范围硬约束（贯穿所有规则）

全程只保活"家庭云电脑畅享版月包"那一个云桌面（vmId）。任何阶段发现误触发其他桌面开机/保活 → 立刻停，回退排查。绝不碰别的云桌面。
