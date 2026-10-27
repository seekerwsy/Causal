# JCI 与任务等权 Ridge：审阅与复现

本指南用于复现已完成的 [jci-ridge-development-20260930](2026-09-30-jci-ridge-comparison-plan.md) 有界开发研究及其冻结证据。当前活动研究及审阅入口见 [受控研究执行记录](2026-09-30-controlled-semantic-execution.md)。正式协议保持 `SPECIFIED_DRAFT`。本指南中的复算命令使用已保存的真实请求与结果，无须访问模型服务。

## 核心阅读顺序

1. [有界协议](2026-09-30-jci-ridge-comparison-plan.md)：研究问题、随机化、估计量、预算及结论边界。
2. [实际任务](../../data/method/jci-ridge-20260930/experiment-qualified-inputs/tasks.json)：24项来源、完整 TSG、政策、状态、测量合同及 H/E 身份。
3. [阶段实现](../../src/development/jci_ridge.py)：`assemble_training`、`analyze_training`、`freeze_evaluation`、`report_evaluation`。
4. [R 图搜索](../../src/development/structure_policy_cpu.R)：共享骨架、背景约束与定向。
5. [共同学习器](../../src/development/graph_guided_decisions.py)：`TaskEqualRidge` 与 `fit_task_equal_ridge`。
6. [真实代码生成](../../src/development/source_generation.py)：`run_jci` 的分配、传输、代码提取与测量调用。
7. [程序观察器](../../src/measurement/command_execution.py)：真实工具、普通功能见证、有限攻击探针与标签。
8. [核心检查](2026-09-30-jci-readiness-tests.py)：表示、随机化、CI、学习器、物理请求与结果组装边界。
9. [独立结果复算](2026-09-30-jci-result-verifier.py)：不调用生产 CI、Ridge 或区间计算函数的独立验证。
10. [启动与执行依据](2026-09-30-jci-readiness.md)：来源范围、独立语义审查、98项真实控制、环境及实际执行证据。

## 七个阶段及文件

以下路径以 `data/method/jci-ridge-20260930`（输入）和 `results/jci-ridge-20260930`（结果）为根目录。

| 阶段 | 冻结输入 | 实际输出 |
| --- | --- | --- |
| 表示 | `source-check`、`reviewed-twenty-seven`、`command-final-inputs` | `experiment-qualified-inputs/tasks.json`；`command-final-qualified` 的98项控制 |
| 优先排序 | `training-requests.json`、`structure-subsamples.json`、176项训练结果 | `analysis/graph-*` 的202次搜索；`analysis/analysis` 的共享 Ridge、支持和选择 |
| 假设冻结 | 训练拟合结果及剩余预算 | `evaluation-decisions` 的动作、符号、136项请求、合并系数和精度 |
| 干预与随机化 | 全文、永久三槽映射、独立种子 | `training`、`evaluation` 各请求的 `assigned`、`request.json`、`response.json` |
| 测量 | 冻结调用合同及同一观察器 | 各请求的代码、`measurement-request.json`、`measurement.json` |
| 结果组装 | 全部分配及原始测量 | 各请求的 `result`；阶段 `summary`；报告 `observations.json`、`cases.json` |
| 推断与报告 | 冻结选择和实际评价结果 | `report` 的主比较、发现价值、逐案效果、成本；`verification` 的独立复算 |

Prompt TSG 边表达语义。主因果图仅含 C、三个通过覆盖检查的 X、Y；生成代码参与独立测量。全部分配保留 ITT 分母，未知和语法无效结果分别记载；基础设施缺失保持缺失。主要端点是有限观察下可评价安全代码产出，完整功能与完整联合成功没有获得验证。

C 为独立随机选择的永久政策槽，每次同时独立抽取训练任务与生成种子。空槽映射基线全文；同一全文被再次抽中时实际重新生成。结构表使用96项随机混合请求，任务总体数量仍为16。完整训练的176项请求用于共同 Ridge。

## 支持环境与命令

工作目录为仓库根目录。Python 3.12，依赖由 `pyproject.toml` 的 `jci-study` 固定。图搜索实测使用 Windows R 4.3.1、pcalg 2.7.12；R 路径为 `D:/R/R-4.3.1/bin/x64/Rscript.exe`，包目录为 `.codex-runtime/r-lib`。纯结果独立复算不调用 R。

```powershell
py -3.12 -m venv .codex-runtime/jci-reviewer-venv
.codex-runtime/jci-reviewer-venv/Scripts/python.exe -m pip install -e ".[jci-study]"
.codex-runtime/jci-reviewer-venv/Scripts/python.exe -m pytest docs/experiments/2026-09-30-jci-readiness-tests.py -q
```

完整训练分析复现执行202次真实图搜索和共享 Ridge；输出目录须尚未存在：

```powershell
.codex-runtime/jci-reviewer-venv/Scripts/python.exe -m prompt_mechanism_study.development.jci_ridge analyze-training --prepared data/method/jci-ridge-20260930/experiment-qualified-inputs --training results/jci-ridge-20260930/training --output .codex-runtime/jci-reviewer-analysis
```

从保存的真实评价结果重新计算主比较、逐案效果和成本：

```powershell
.codex-runtime/jci-reviewer-venv/Scripts/python.exe -m prompt_mechanism_study.development.jci_ridge report-evaluation --prepared data/method/jci-ridge-20260930/experiment-qualified-inputs --decisions data/method/jci-ridge-20260930/evaluation-decisions --evaluation results/jci-ridge-20260930/evaluation --output .codex-runtime/jci-reviewer-report
.codex-runtime/jci-reviewer-venv/Scripts/python.exe docs/experiments/2026-09-30-jci-result-verifier.py --phase completed-jci --inputs data/method/jci-ridge-20260930/experiment-qualified-inputs --results results/jci-ridge-20260930 --decisions data/method/jci-ridge-20260930/evaluation-decisions --report .codex-runtime/jci-reviewer-report --output .codex-runtime/jci-reviewer-verification
```

独立验证检查312项实际传输与测量标签、全部任务的折内 Ridge、2104条 CI 查询、202次 PAG、冻结选择、共享请求抵消、逐案效果、发现价值及实际服务关闭与成本。该检查复算保存的程序证据；真实工具观察的适用范围由98项控制及有限探针合同限定。

模型服务的原始调用环境分别保存在 `service-training/frozen` 和 `service-evaluation/frozen`，停止记录在对应 `stopped` 中。观察器原文、Dockerfile 和镜像身份保存在 `command-final-qualified`。训练分析的执行时程序副本位于 `analysis` 根目录，报告自身记录实际报告程序 SHA256。重新计算的 CPU 时间可以变化；科学结果、请求身份和预定随机数须一致。

完整测量镜像保存为 `results/jci-ridge-20260930/measurement-image.tar.gz`，SHA256 为 `04cd366b31563ba741ab8662ea836df62f363c8e57b0932ef7b31e27cff80311`。在支持 Linux Docker 的环境执行 `docker load --input results/jci-ridge-20260930/measurement-image.tar.gz`，获得原始镜像 `sha256:45ff9ac28f50665ab8bd1f85ed6023779c8107fb6970d283bfcd90fd7187694e`。实际控制复现命令见启动记录。该镜像保持本轮环境的真实限制，包括 `/work` 的 `noexec`；J011/J013 的测量适配问题须结合结果报告解释。

## 审阅材料范围

审阅使用上述活动输入、真实结果、资格控制、必要的总体/有限机制检查及代码。来源数据保持外部基准任务身份，评价任务也保留来源准备暴露；不能解释为实际开发者原始请求总体或完全未见任务验证。既往方法尝试、服务器管理记录、中间准备包和其他数据集不属于本轮默认审阅路径。
