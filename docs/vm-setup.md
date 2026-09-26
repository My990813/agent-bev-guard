# Linux VM 部署指南（Step 3 传感器）

MVP 锁定单机/单 VM（裁决 R1/R11）。所有组件跑在同一个 Linux 实例内，
`ts_mono` 与 bpftrace 的 `nsecs`（boot 相对时钟）都只在 VM 内有意义。

## 1. 建 VM（macOS 宿主机，零硬件）

任选其一：

- **OrbStack**（推荐，轻量）：`brew install orbstack`，然后 `orb create ubuntu:24.04 agent-bev`
- **UTM**：下载 Ubuntu Server 24.04 arm64 镜像，2 vCPU / 4GB 即可

要求：内核 5.15+（Ubuntu 24.04 是 6.8，满足），BTF 开启（`ls /sys/kernel/btf/vmlinux` 存在即满足）。

## 2. VM 内安装

```bash
sudo apt update && sudo apt install -y bpftrace python3
bpftrace --version   # 确认 >= 0.20
```

把项目同步进 VM（OrbStack 直接 `orb push agent-bev agent-bev-guard/`，
或 `scp -r` / git clone）。

## 3. 运行采集（VM 内，root）

```bash
cd agent-bev-guard
sudo sensors/collect.sh vm_out        # Ctrl-C 停止
```

产出：

```
vm_out/btime.txt      时钟锚点（/proc/stat 的 btime）
vm_out/process.raw    EXEC|pid|ppid|uid|nsecs|filename
vm_out/file.raw       FILE|pid|uid|nsecs|flags|ret|path
vm_out/network.raw    CONNECT|pid|nsecs|saddr|daddr|dport / SEND|pid|nsecs|bytes
```

## 4. 归一化（VM 内，普通用户即可）

```bash
python3 sensors/normalize.py \
  --raw-dir vm_out \
  --log kernel_events.jsonl \
  --classes examples/classification.json
```

输出末尾会打印 `chain ok: True/False`——哈希链必须为 True 才可用于后续融合。

若 CONNECT 的端口看起来错位（如 443 显示成 47873），加 `--bswap-port`。

## 5. 完整链路（同一次会话）

```bash
# 终端 1：传感器
sudo sensors/collect.sh vm_out

# 终端 2：网关（agent 经它访问 MCP server）
python3 gateway/proxy.py --server-cmd "python3 your_mcp_server.py" \
  --log gateway_events.jsonl --policy examples/gateway_policy.json

# 终端 3：agent 正常工作……

# 结束后合并（Step 4 会做实体解析，这里只演示数据汇合）
cat kernel_events.jsonl gateway_events.jsonl > all_events.jsonl
```

## 已知限制（详见 threat-model.md 第 8 节与 step-3 交付说明）

- 传感器脚本无法在 macOS 上验证，进 VM 后首次运行可能需要小调
  （`curtask->real_parent->tgid` 依赖 BTF；dport 字节序见 --bswap-port）。
- bpftrace 缓冲区溢出会丢事件（输出里的 `@lost` 行），高负载时加
  `--bswap` 无关的缓冲参数或降低系统噪音。
- file.open 无读取字节数；net.connect 在被动连接上 pid 是内核任务
  而非属主进程——两者都由 Step 4/5 的融合与对账规则兜底。
