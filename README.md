# Agent BEV Guard

Agent 行为的多源证据融合监控（observability + forensics）。
把内核态传感器、工具网关、Agent 自报日志统一到一个事件 schema，
在带外 append-only 审计日志上做跨源一致性检测。

## 路线图

| 步骤 | 内容 | 状态 |
|------|------|------|
| 1 | 威胁模型 + 统一事件 schema + 哈希链审计日志 | done |
| 2 | 工具调用网关（MCP stdio proxy + 策略引擎） | done |
| 3 | 主机传感器（bpftrace 探针 + 归一化器，Linux VM） | done |
| 4 | 实体解析 + 时钟对齐（融合层） | done |
| 5 | Provenance 图 + 一致性规则（part A：图+规则引擎；part B：incident 聚合+报告 CLI） | done |
| 6 | 统计异常检测 + 事件重建 | todo |

## 布局

```
docs/threat-model.md     威胁模型 v0.2（含五项裁决记录与三条固定原则）
schema/event.schema.json 统一事件 JSON Schema
core/events.py           Event 模型 + append-only 哈希链日志 + 身份来源标记
gateway/policy.py        工具调用策略引擎（allow/deny + 参数路径/长度/黑词规则）
gateway/proxy.py         MCP stdio 网关：拦截 tools/call，策略裁决，事件落盘
sensors/bpftrace/*.bt    内核探针：process.exec / file.open / net.connect+egress
sensors/collect.sh       VM 内采集编排（btime 锚点 + 三个探针）
sensors/normalize.py     原始探针输出 → 统一事件（含时钟重建、路径分级、sensor.health telemetry）
core/fusion.py           融合层：process lineage、run 归属（pid+窗口）、身份状态机（DIRECT/INFERRED/UNKNOWN）
core/recon.py            体积对账容差模型（可配置 ratio + reason + protocol，非硬编码）
core/graph.py            Provenance 图：事件 → 节点（run/process/file/endpoint/tool/object）+ 带溯源的边
core/rules.py            一致性规则引擎：R1 机密文件→外发 / R2 自报矛盾 / R3 白名单外连 + 传感器健康耦合
                         （R21：(pid, pid_start_ts) 归因，pid 单独永不参与自动因果归属）
core/report.py           报告层：incident 聚合（union-find，只归组不修改 findings）+ 文本/JSON 渲染
report_cli.py            报告 CLI：哈希链验证 → 规则引擎 → incident 聚合 → report.json/.txt/graph.txt
docs/vm-setup.md         Linux VM 部署指南（OrbStack/UTM）
examples/                示例事件、示例策略、路径分级映射、规则配置、demo 日志与报告
tests/                   每步的 sanity 测试（含端到端 stdio 会话与 CLI 篡改检测）

## 运行

```
python tests/test_events.py     # step 1
python tests/test_gateway.py    # step 2（策略单测 + 端到端网关会话）
python tests/test_sensors.py    # step 3（归一化器，macOS 可跑）
python tests/test_fusion.py     # step 4（融合层 + telemetry + 容差模型）
python tests/test_rules.py      # step 5A（provenance 图 + 规则引擎）
python tests/test_report.py     # step 5B（incident 聚合 + 报告 + CLI 篡改检测）
```

一键复现 demo 报告（原始场景：机密图片被读 → 2.3MB 外发 → agent 自称"没上传"）：

```
python examples/make_demo_log.py examples/demo_events.jsonl
python report_cli.py --log examples/demo_events.jsonl \
    --config examples/rules_config.json --out examples/demo_report
```

内核探针在 Linux VM 内运行，见 `docs/vm-setup.md`。

把真实 Agent 接到网关后面：

```
python gateway/proxy.py \
  --server-cmd "python your_mcp_server.py" \
  --log events.jsonl \
  --policy examples/gateway_policy.json
```

零第三方依赖，Python 3.10+。

## 固定设计原则（2026-09-26 两轮裁决）

1. `ts_mono` 只做单机排序，不跨机器使用（MVP 锁定单机/单 VM）。
2. `agent_run_id` 可为空；推断身份必须带 `identity_source` 与 confidence，
   INFERRED 身份永不作为事实。
3. `sensor_privilege` 是声明，不是信任根。
4. 审计日志永不存 payload，只存行为 metadata（核心隐私原则）。
5. 拒绝对 agent 钝化（`denied`），详细 reason_code 只进审计日志。
6. `run_id` 是 `gateway_issued` + `run_id_verified=false` 的关联句柄，
   不是认证声明；client pid 优先取系统观测值（observed_ppid）。
7. 协议覆盖边界：只保证 request 型 `tools/call` 的拦截与审计。
8. `call_context`（session/call_seq/state_ref）为有状态策略预留，MVP 不实现。
9. **系统允许不确定，但不允许伪造确定性**：每条事件必须有明确的
   identity 状态（DIRECT/INFERRED/UNKNOWN），而不是必须有 identity。
10. 传感器健康是一级 telemetry：`sensor.health` 事件记录窗口、
    events_seen/lost、loss_ratio、health 状态；Step 5 依此降级
    negative findings（absence of evidence ≠ evidence of absence）。
11. 体积对账容差是可配置 policy（ratio/reason/protocol），
    不是系统隐含常数。
12. 因果归因键是 `(pid, pid_start_ts)`，pid 单独永不参与自动归因；
    优先级：same run_id > same process instance > UNKNOWN（宁可不确定，
    不伪造因果链）。
13. 规则引擎只产原始 findings，不做聚合；incident 归组只在报告层
    （report.py）做，"规则触发三次"与"三次压成一次"永远可区分。
14. 文件大小带测量语义（config_provided / post_event_stat /
    unavailable），删失文件不补估计值，对账结论为 INSUFFICIENT_EVIDENCE。
15. 规则窗口默认 600s、可配置，且每条 finding 记录实际使用的窗口值，
    保证不同窗口的实验可复现。
