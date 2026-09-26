# Agent BEV Guard — 威胁模型（v0.3）

## 0. 系统 claim（v0.2 修订；v0.3 追加 Step 6 边界，见第 12 节）

> **我们检测并重建 Agent 的未授权数据流。**
> 我们不承诺"防止泄露"，不承诺杜绝一切外传。
> 我们发现和重建行为，不判断主观意图、法律责任或违法性。

```
Covered:
  + unauthorized tool calls（策略拒绝的工具调用）
  + unexpected file access
  + unexpected network egress
  + inconsistent agent telemetry（自报行为与系统观测矛盾）
  + cross-source event reconstruction

Out of scope:
  - 具有合法权限的恶意数据外传（policy/authorization 问题，非 observability 问题；
    留给未来的 policy-aware monitoring）
  - 加密 payload 内容检查（只做归因与体积对账）
  - 监控基础设施自身被攻陷（用哈希链 + 带外存储缓解，不承诺杜绝）
```

## 1. 要保护的资产

| 资产 | 分级 | 例子 |
|------|------|------|
| 本地文件 | confidential | 简历、密钥、笔记、图片 |
| 凭据 | secret | API key、token、ssh key |
| 对话上下文 | confidential | 用户与 Agent 的对话内容 |
| 远端数据集 | internal | 训练数据、数据库 |

## 2. 假想的对手

一个拥有正常工具权限、可被 prompt injection 影响或本身行为失当的
coding/data Agent。它会读写文件、调用工具、访问网络。
对手能力上限：能改写自己产生的日志，不能进入内核态，不能修改带外审计平面。

## 3. 信任边界

```
[不可信] agent 自报日志          ← 只做对照，永不单独作为结论
[弱信任] 工具网关记录            ← 部署在我们控制的代码路径上
[强信任] 内核态传感器            ← Agent 无权限篡改
[最强]   带外 append-only 审计日志 ← 哈希链防篡改，独立存储
```

## 4. 检测目标（in scope）

1. Agent 自报行为与系统观测之间的矛盾（"说没上传，实际有 POST"）。
2. 未授权出口：访问不在 allowlist 的域名/IP。
3. 数据流异常：confidential 文件被读取后 N 秒内出现等量出口流量。
4. 权限异常：以非常规身份/路径访问凭据类文件。

## 5. 明确不做（out of scope）

- **合法通道滥用**（用被授权的 API 外发不该发的内容）——内容级 DLP，另起项目。
- 加密流量的内容检查——只做归因与体积对账，不解密。
- 监控系统自身被 0-day 攻陷——用哈希链 + 带外存储缓解，不承诺杜绝。
- 物理侧信道（摄像头、电磁）。

## 6. 关键设计决定

- 每条事件带 `sensor_privilege` 标签。**该标签是部署时的声明（registry claim），
  不是经过验证的信任根**；融合规则只能将其作为 metadata 加权，不得作为唯一
  信任依据。传感器 attestation / 启动验证是后续里程碑。
- 事件 schema **不含任何 payload/内容字段**：日志本身不能成为泄露通道。
  未来内容级检查只允许增加 content_hash / 脱敏签名 / classification，
  永不存原始数据。这是全系统的核心隐私原则。
- 双时间戳：`ts_wall`（跨源对齐用）+ `ts_mono`（同机因果排序用）。
  **MVP 锁定单机/单 VM**：所有传感器同一 OS 实例内，`ts_mono` 才有效。
  跨机版本需引入 clock_offset + clock_uncertainty，不在本期。
- Actor 主键是 `(pid, pid_start_ts)`，因为 pid 会被复用；`agent_run_id`
  只能由网关注入，内核传感器给不了，所以允许为空。**身份解析是延迟的
  （identity resolution is deferred）**：融合层通过 pid + 时间窗口 +
  process lineage 推断 run 归属；推断结果必须带
  `identity_source ∈ {DIRECT, INFERRED, UNKNOWN}` 与 confidence，
  INFERRED 身分永不作为事实使用。

## 7. 裁决记录（2026-09-26，梦颜）

| # | 风险点 | 裁决 |
|---|--------|------|
| R1 | 双时间戳跨机不可比 | 锁定单机/单 VM MVP，跨机留后续 |
| R2 | agent_run_id 可空 | 接受；推断身份必须带 confidence，分 DIRECT/INFERRED/UNKNOWN |
| R3 | sensor_privilege 静态声明 | MVP 接受，但只是 metadata，不是信任根；后续加 attestation |
| R4 | 不记录 payload | 强烈接受，升格为系统核心隐私原则 |
| R5 | 威胁模型边界 | 接受，claim 改为"检测并重建未授权数据流"（见第 0 节） |

三条固定设计原则：
① `ts_mono` 只做单机排序，不跨机器使用；
② `agent_run_id` 可空，推断身份必须带 confidence；
③ `sensor_privilege` 是声明，不是信任根。

## 8. 已知限制（Step 2 裁决，2026-09-26）

| # | 风险点 | 裁决 |
|---|--------|------|
| R6 | stdio 无 client identity | **已修**：网关是 agent 拉起的子进程，`os.getppid()` 即系统观测的 client pid；initialize 的 clientInfo / `_meta.client_pid` 做交叉核对，声明与观测不一致本身记为取证信号 |
| R7 | run_id 自封 | MVP 接受：run_id 标记为 `gateway_issued` + `run_id_verified=false`，是关联句柄不是认证声明 |
| R8 | notification 型调用 | **协议覆盖边界**：本系统只保证对 request 型 `tools/call` 的拦截与审计；notification 消息与 server 主动 push 透明转发、不审计。不声称"完整 MCP 调用审计" |
| R9 | 无状态策略 | 接受 + 预留：schema 增加 `call_context`（session_id / call_seq / state_ref）扩展点，MVP 不实现累计检测，不引入状态数据库 |
| R10 | 拒绝信息泄露策略边界 | **已钝化**：agent 只收到 `{"error": "denied"}`；reason_code + 详细原因只进审计日志（最小必要原则） |

## 9. Step 3/4 裁决记录（2026-09-26）

| # | 风险点 | 裁决 |
|---|--------|------|
| R11 | 传感器运行环境 | Linux VM（OrbStack/UTM）+ bpftrace，零硬件；"单机 = 单 VM"贴合 R1 |
| R12 | 传感器启动前已在跑的进程 | 接受降级 UNKNOWN（confidence 标记），不强制"先传感器后 agent"；UNKNOWN 是有效状态 |
| R13 | bpftrace 丢事件 | normalize 现在就发 `sensor.health` telemetry（window/events_seen/events_lost/loss_ratio/health）；Step 5 据此降级 negative findings |
| R14 | SEND 字节含协议开销 | 容差可配置（默认 10%），带 reason + protocol 字段；不硬编码 |
| R15 | file.open 无读取字节数 | 保守对账（出口 vs 打开文件大小的上界），read tracing 留高精度模式开关，默认关 |
| R16 | DNS/被动连接 | MVP 只归因主动外连；DNS enrichment 放 Step 3.5；被动 accept 明确 out-of-scope，不产生看起来精确实则错误的 pid |

**Step 4 固定原则：系统允许不确定，但不允许伪造确定性。**
每条事件必须有明确的 identity 状态（DIRECT/INFERRED/UNKNOWN），
而不是必须有 identity。

## 10. Step 4 第二轮裁决（R17–R20，2026-09-26）

| # | 风险点 | 裁决 |
|---|--------|------|
| R17 | EXEC ppid 丢失致 lineage 断链 | **已修**：统一事件 actor 增加 `ppid`；Fusion 建 (pid, pid_start_ts) → ppid 进程树，网关子进程按 exec 时间落窗口归属（CONF_LINEAGE=0.70，INFERRED，永不升级 CONFIRMED） |
| R18 | ISO 字符串比较做窗口判断 | **已修**：这是当前实现正确性 bug（+08:00 与 Z 混用会静默错序），与跨机无关。所有窗口比较走 `ts_to_epoch()` 解析后的 epoch float；`ts_wall` 仅审计展示 |
| R19 | 置信度 0.9/0.7 无 calibration | **保留连续数值，但仅排序/展示**：`identity_confidence` 语义 = heuristic evidence score，非"归属正确的概率"。Step 5 禁止 `if confidence < 0.8: 不告警` 这类硬阈值 |
| R20 | sensor.health >5% 阈值及盲区 | **接受 + 语义写死**：health ∈ {HEALTHY, MINOR_LOSS, DEGRADED, UNKNOWN}；无 window.txt → UNKNOWN；HEALTHY 附带 "necessary-not-sufficient; blindspots=attach,vm-suspend,startup-gap" 声明 |

**Step 5 锁定的告警语义原则：**

> 告警由"规则是否成立"决定，confidence 用于描述证据强弱，
> sensor health 用于描述观测完整性。三者不能混为一个分数。
> 输出为结构化结论（rule / violation / lineage / confidence /
> sensor / evidence / conclusion），不输出单一 risk_score。

## 11. Step 5 第三轮裁决（R21–R24，2026-09-26）

| # | 风险点 | 裁决 |
|---|--------|------|
| R21 | pid 复用导致假因果链 | **已修**：归因键升级为 `(pid, pid_start_ts)`，pid 单独**永不**参与自动因果归属。优先级：same agent_run_id（最强）> same process instance（强）> UNKNOWN。任一方缺 pid_start_ts（无 exec 记录融合）即拒绝归因——宁可 UNKNOWN，不伪造因果链 |
| R22 | 三规则同事件重复告警 | **引擎不聚合**：规则引擎只产原始独立 findings（各带 rule_id/evidence/confidence/health/lineage），incident 归组仅在报告层（core/report.py，union-find 按共享证据/文件/端点/run 归组）。"规则触发三次"与"三次被压成一次"永远可区分 |
| R23 | 文件大小来源 | **接受事后 stat + 语义入事件**：size 带 `size_source ∈ {config_provided, post_event_stat, unavailable}` + observed_ts + best_effort_current_size 语义。文件已删 → size_bytes=null，对账结论 INSUFFICIENT_EVIDENCE，永不伪造 PASS。缺证据 ≠ 没发生 |
| R24 | 规则一 600s 窗口 | **确认**：默认 600s + config 可调；每条 finding 记录实际使用的 window_seconds + start/end，不同窗口实验可复现、可对比 precision/recall |

**Step 5 数据层次（锁定）：**

> Raw Events → Evidence → (Provenance Graph ∥ Consistency Rules) →
> Findings（不聚合）→ [报告层] Incidents → Text / JSON / Graph。
> Finding = 某条规则发现了什么；Evidence = 为什么这么判断；
> Incident = 哪些 findings 属于同一次调查事件。三者严格分开。
> 报告 CLI 在生成前先验证审计日志哈希链，链断则拒绝出报告。

## 12. Step 6 定位（2026-09-26 重新定义）

**研究问题不是"发现未知攻击"，而是：**

> 发现无法由既有行为基线解释的异常 Agent execution，
> 并提供可审计的证据链供进一步调查。

（Agent Behavioral Anomaly Detection + Evidence-Based
Investigation Support，即 triage / investigation support system。）

**系统边界（核心原则，永久锁定）：**

> The system detects and reconstructs behavior; it does not
> determine intent, legality, or culpability.
> （系统负责发现和重建行为，不负责判断主观意图、法律责任或违法性。）

分层职责，中间步骤不得自动跳过：

```text
机器：What happened?            （telemetry 重建 —— Step 1-5）
机器：How unusual was it?       （基线偏离 —— Step 6）
机器：What evidence supports?   （证据链 —— Step 5/6）
人：  Was it authorized?        （授权判断 —— 人工调查）
人：  Was it harmful?           （危害判断 —— 人工调查）
法律体系：Legal consequences?   （违法性 —— 超出系统范围）
```

**具体设计约束：**

- 系统输出 `behavior = unusual / inconsistent_with_baseline`，
  永不输出 `malicious = true`。
- 每条 triage 项固定携带 `legal_status = NOT_DETERMINED`。
- `policy_violation` 字段只能来自 Step 5 已知规则的裁决结果；
  无规则触发时写 UNKNOWN（"没有已知规则命中"≠"合规"），
  永不写 "compliant / none"。
- 异常分值是启发式排序辅助（heuristic ranking aid），
  不是概率，不是 calibrated 阈值——与 R19 同一语义。
- Step 6 的价值是压缩调查面：10,000 runs → N 个"请调查"，
  由人决定是否授权、是否有害、是否涉及法律。
- 合法通道滥用（读取 customer.csv 上传到授权 S3）在基线内
  完全可能"不异常"——异常检测不覆盖授权问题，与第 8 节
  out-of-scope 声明一致。
