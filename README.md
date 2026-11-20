# ipsec-policy-route-consistency-validator
校验 IPsec 策略、流量选择器和路由转发的一致性

## 概述

主机同时存在直连、隧道和 NAT-T 三条路径，SPD 策略、SAD 安全联盟和路由表
又分别由不同系统下发，容易出现"策略要求加密但路由绕开隧道"、"旧 SA 已删除
但选择器仍然命中"之类的不一致。本工具是一个**离线、只读**的一致性校验器：
把 SPD、SAD、路由、隧道、接口和 NAT-T 状态作为输入数据，针对给定的流量样本
计算每个流量范围实际经过的路径和命中的保护策略，并给出故障原因。

**本工具不修改任何系统策略或系统状态**（不调用 `ip xfrm`、不改路由、不写
内核表项），所有输入均由调用方以 Python 对象或 JSON 提供。

## 运行环境

- Python 3.8.2+，仅使用标准库。

## 功能

- 按 SPD 优先级选择策略，区分 `bypass` / `protect` / `discard` /
  `no-match` / `conflict`（同优先级动作冲突）。
- 将流量样本按策略选择器与路由前缀边界分解为判决一致的子范围，分别输出
  最终动作、关联 SA、路由证据和故障原因。
- 一致性检查：
  - SA 是否完整覆盖选择器（`SA_MISSING` / `SA_SELECTOR_NARROW`）；
  - SA 生命周期（`SA_EXPIRED`，按评估时刻 `now` 判断）；
  - 策略要求加密但路由绕开隧道（`TUNNEL_BYPASS`）、bypass 流量却走进
    隧道（`UNEXPECTED_TUNNEL`）；
  - 隧道下一跳 / 远端端点可达性、接口状态
    （`NEXT_HOP_UNREACHABLE` / `TUNNEL_ENDPOINT_UNREACHABLE` /
    `INTERFACE_DOWN`）；
  - NAT 边界与 SA 封装方式（`NATT_MISMATCH`：存在 NAT 边界但 SA 未使用
    UDP-4500 封装）；
  - 出站 / 入站 protect 策略对称性（`ASYMMETRIC_POLICY`）。
- 引擎无状态、不缓存结论：每次 `validate(sample, now)` 都重新读取 SA
  生命周期与 NAT-T 状态，SA 过期或 NAT 边界变化后再次调用即得到新结论。

## 使用

### 命令行

```sh
python -m ipsec_validator examples/scenario.json
```

场景 JSON 包含 `now`、`sample`、`policies`、`sas`、`routes`、`tunnels`、
`interfaces` 字段，格式见 `examples/scenario.json`。任一范围存在故障时
退出码为 1。

### Python API

```python
from ipsec_validator import Selector, Validator
from ipsec_validator.report import format_verdicts

validator = Validator(policies, sas, routes, tunnels, interfaces)
verdicts = validator.validate(
    Selector(src="10.0.0.0/24", dst="10.1.0.0/16", direction="outbound"),
    now=1_000_000.0,
)
print(format_verdicts(verdicts, now=1_000_000.0))
```

## 测试

```sh
python -m unittest
```

测试覆盖：多策略优先级、隧道旁路、单向（非对称）策略、NAT-T、SA 过期 /
删除、重叠选择器分解、隧道端点与接口可达性。

## 目录结构

- `ipsec_validator/model.py` — SPD/SAD/路由/隧道/接口数据模型
- `ipsec_validator/prefix.py` — 前缀与端口区间分解
- `ipsec_validator/engine.py` — 一致性校验引擎（无状态、不缓存）
- `ipsec_validator/report.py` — 结果格式化
- `ipsec_validator/loader.py` — JSON/dict 输入加载
- `tests/test_validator.py` — 单元测试
