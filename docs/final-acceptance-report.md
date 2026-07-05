# 最终验收报告 — cmcc-cloud-alive

> 日期：2026-07-05
> 项目根：`/home/demo/restore/cmcc-cloud-alive`
> 验收依据：`notes/execution_plan.md` §6 验收门槛（P12 停止点）
> 测试基线：258 tests，全绿

## 验收线总览

plan §6 定义了 8 条验收线（L0, L8-L14）。L1-L7 为中间实现步骤，已被 L8-L13 覆盖，plan 未单独列为验收门槛。

| 验收线 | 原子成功条件 | 状态 |
| --- | --- | --- |
| L0 | route-check 能判断 scg/zte/error | ✅ 通过 |
| L8 | ZTE material 拿 token/list/connectStr | ✅ 通过 |
| L9 | ZTE CAG TCP/TLS 成功 | ✅ 通过 |
| L10 | ZTE CAG mux open link1 | ✅ 通过 |
| L11 | ZTE raw main MAIN_INIT | ✅ 通过 |
| L12 | ZTE raw display DISPLAY_INIT | ✅ 通过 |
| L13 | ZTE 路 120s short keepalive 不断 | ✅ 通过 |
| L14 | product-keepalive --forever verified-run 40min running | ⬜ 未执行 |

**总结**：L0-L13 全部通过（测试覆盖），L14（40 分钟真实环境 live 验证）未执行。

---

## 逐条验收

### L0 — route-check 能判断 scg/zte/error

- **plan ID**：P12-001
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/product_router.py` — `classify_firm_auth_route(auth)` 返回 `zte` / `scg` / `error`
- **测试证据**：
  - `tests/test_cli.py`（13 tests）— CLI 子命令含 `product-route-check`
  - `tests/test_python_modules.py`（127 tests）— 含 product_router 单测
- **live 证据**：commit `f832b2e` — P1-007 live route-check verified, kind=zte
- **备注**：已通过真实 firmAuth 验证路由分类正确

### L8 — ZTE material 拿 token/list/connectStr

- **plan ID**：P12-002
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/zte_route.py` — `run_material()` 获取 token / 云电脑列表 / connectStr
- **测试证据**：`tests/test_python_modules.py`（127 tests）— 含 zte_route material 单测
- **备注**：connectStr 解析为内层 SPICE 连接参数（`zte_connect_params.py`）

### L9 — ZTE CAG TCP/TLS 成功

- **plan ID**：P12-003
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/zte_cag.py` — 外层 CAG TCP/TLS 传输建连
- **测试证据**：`tests/test_zte_cag.py`（34 tests）— CAG TCP/TLS 集成测试
- **备注**：外层 CAG 与内层 SPICE 严格分离（P6: `OuterCAGTarget` / `InnerConnectParams`）

### L10 — ZTE CAG mux open link1

- **plan ID**：P12-004
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/zte_cag_mux.py` + `zte_cag_proxy.py` — CAG mux 多链路 open link1
- **测试证据**：`tests/test_zte_cag_mux_proxy.py`（35 tests）— CAG mux/proxy 集成测试
- **备注**：mux 不通则 raw main 无法发送（P9 依赖 P8）

### L11 — ZTE raw main MAIN_INIT

- **plan ID**：P12-005
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/zte_raw_spice.py` — SPICE main channel MAIN_INIT 握手
- **测试证据**：`tests/test_zte_raw_spice.py`（22 tests）— raw SPICE main 握手测试
- **备注**：raw main 写 link1，依赖 mux（L10）已通

### L12 — ZTE raw display DISPLAY_INIT

- **plan ID**：P12-006
- **状态**：✅ 通过
- **实现**：`cmcc_cloud_alive/zte_raw_spice.py` — SPICE display channel DISPLAY_INIT
- **测试证据**：
  - `tests/test_zte_raw_spice.py`（22 tests）— 含 display channel 测试
  - `tests/test_e2e_zte_keepalive.py`（6 tests）— 端到端含 DISPLAY_INIT
- **备注**：commit `4e0814f` — P12 end-to-end ZTE keepalive integration test (L12+L13)

### L13 — ZTE 路 120s short keepalive 不断

- **plan ID**：P12-007
- **状态**：✅ 通过（测试覆盖，mock 网络）
- **实现**：`cmcc_cloud_alive/zte_route.py` — `run_zte_keepalive_session()` 120s keepalive session loop
- **测试证据**：
  - `tests/test_zte_keepalive_session.py`（4 tests）— 120s keepalive session
  - `tests/test_e2e_zte_keepalive.py`（6 tests）— 端到端 keepalive
- **备注**：⚠️ 测试使用 fake/mock 网络层，非真实 CAG 连接。真实连接稳定性需 L14 live 验证

### L14 — product-keepalive --forever verified-run 40min running

- **plan ID**：P12-008
- **状态**：⬜ 未执行
- **plan 原文**：`product-keepalive --forever` verified-run 40min running — 才算追平成品
- **未执行原因**：需真实网络环境 + 凭据，测试环境无法完成
- **前置条件**：
  - 真实移动云电脑凭据（环境变量传入）
  - 真实 CAG 网络可达
  - verified-run duration >= 2400s（40 分钟），interval = 60s
  - 独立 `power_monitor` 记录完整时间线
- **备注**：代码实现已就绪（CLI `product-keepalive --forever` + `verified-run` 框架 + `power_monitor`），差真实环境执行

---

## SCG 路线补充说明

SCG 路线不在 plan §6 验收线中（plan 验收线针对 ZTE 路线），但已实现：

- **Go binary**：`scg_go/cmcc_keepalive`（从蓝本 fork，含 scg/zte/spice/crypto/chuanyun/cem 内部包）
- **Python shim**：`cmcc_cloud_alive/scg_route.py` — subprocess 调用 Go binary
- **测试**：`tests/test_scg_route.py`（17 tests）
- **CLI 接线**：`product-keepalive` 自动路由到 SCG 时调用 Go binary
- **commit**：`2d82b14` — feat(scg): fork Go keepalive binary + Python subprocess shim
- **live 验证**：未执行（同 L14，需真实环境）

---

## 凭据安全

本报告不含任何明文凭据。凭据通过环境变量 / state 文件传入，文档中仅引用脱敏标识（如 `userServiceId=2663816`）。

凭据扫描：对 docs/ 目录执行敏感凭据关键字 grep，返回空（无残留凭据）。

---

## 结论

```text
L0-L13：全部通过（258 测试覆盖）
L14   ：未执行（需真实环境 40 分钟 live 验证）
SCG   ：代码+测试完成，live 验证未执行

项目协议级保活的代码实现与测试覆盖已完成，
差最后一步真实环境 40 分钟 live 验证 (L14)。
```
