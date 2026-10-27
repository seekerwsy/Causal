# 2026-09-30 有界研究审查指南

本轮入口是[现行有界开发协议](../graph-guided-discovery-protocol.md)，研究身份为 `semantic-discovery-development-20260930`。正式协议仍为 `SPECIFIED_DRAFT`。本指南重放已经保存的开发结果和独立核验，不调用 Qwen，也不消耗保留任务。

七阶段的证据路径如下。表示阶段从 `source-audit/completed/panel.json` 到每案 `panel-prepared` 的来源单元和 TSG；优先化阶段从全部机会到双盲 `panel-review-analysis`；假设冻结阶段保存六字段类别、P/N 版本及 `generation-gate`；干预与随机化阶段仅在已暴露 Case 82 保存十二项真实请求；测量阶段保存 Case 82 独立观察以及四个历史案例的一百四十八项统一重测；结果组装阶段保留全部原分配与任务等权；推断与报告阶段保存训练类别、CPU结构消费者以及[本轮结果](2026-09-30-goal-result.md)。O/V 生成在前瞻精度门槛停止，因此没有 O/V 分配结果或效果估计。

建议按以下顺序阅读十个核心文件：

1. [有界开发协议](../graph-guided-discovery-protocol.md)：任务角色、七阶段、资源和统计规则。
2. [研究结果](2026-09-30-goal-result.md)：实际证据、逐案例归因和剩余限制。
3. [生成前辨别力](2026-09-30-prospective-power-audit.md)：二十五个百分点解释间隔、共享请求与停止推导。
4. [来源审计](2026-09-30-source-frame-audit.md)：结果盲来源框、独立任务和谱系限制。
5. [语义准备与统计实现](../../src/development/semantic_discovery.py)：来源约束、双盲分析、训练、请求权重和区间。
6. [独立测量边界](../../src/development/panel_measurement.py)：真实观察、有限端点和未知保留。
7. [Case 82 实际开发生成分析](../../src/development/case82_development.py)：冻结请求与逐请求结果连接。
8. [CPU消费者实现](../../src/development/structure_policy_cpu.py)：矩阵、政策拟合和结果汇总。
9. [CPU搜索后端](../../src/development/structure_policy_cpu.R)：FCI/JCI背景与GFCI调用。
10. [CPU独立复算](2026-09-30-structure-policy-verify.py)：条件检验、拟合、价值和配置核验。

工作目录为仓库根目录，已配置的 Python 3.12 环境可执行以下只读核验。各入口读取冻结文件并拒绝身份或算术不一致；不重新运行结构搜索或模型服务。

```powershell
.venv\Scripts\python.exe -m pytest tests/test_semantic_discovery.py docs/experiments/2026-09-30-structure-policy-tests.py -q
.venv\Scripts\python.exe docs/experiments/2026-09-30-structure-policy-verify.py
.venv\Scripts\python.exe docs/experiments/2026-09-30-training-learning-verify.py
.venv\Scripts\python.exe docs/experiments/2026-09-30-training-uniform-verify.py
.venv\Scripts\python.exe docs/experiments/2026-09-30-case82-verify.py
```

正式草稿的离线 smoke 与独立结果核验仍按[仓库审查指南](../reviewer-guide.md)运行。该 smoke 是 `NON_CLAIM_TEST_ARTIFACT`，不承担本轮效果结论。
