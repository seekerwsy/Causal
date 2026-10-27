# JCI 方向信息与政策价值的已暴露材料比较

本项研究使用 controlled-semantic-20260930 已暴露的 D=400 项任务和 E=400 项任务，
完成八项预定训练/CAL 划分、216 次真实 FCI 结构搜索，以及四项主要收益比较。
证据身份为 `POST_HOC_EXPOSED_DIRECTION_COMPARISON`。新增模型调用、随机结果观测
和受保护任务使用量均为零。正式协议保持 `SPECIFIED_DRAFT`。

输入配置为 [`direction-plan.json`](../../data/method/jci-sharing-20261014/direction-plan.json)，
SHA256 为 `9cb67285c340418613410165f8c912088fe600437494a1832d768c198b18cba2`。
[冻结方案](2026-10-14-jci-direction-comparison-plan.md)规定了全部划分、学习器、
比较和推断规则。结果位于 [`results/jci-direction-comparison-20261014`](../../results/jci-direction-comparison-20261014)。

## 七阶段与方向信息的作用

| 阶段 | 实际执行 |
| --- | --- |
| 表示 | 保留原来源要求状态 W、准备状态 X、互斥上下文 C 和独立结果 Y。TSG 语义关系及生成代码结构均不提供因果箭头。 |
| 优先化 | 每项划分运行完整训练图及八项 80% 任务子样本图，分别执行 FCI-time、JCI12、JCI123，共 216 次 FCI。 |
| 假设冻结 | 结果产生前固定八项划分、物理请求抽取、模型及收缩网格、基线候选和四项主要比较。原材料及既有研究结果已暴露。 |
| 干预与随机化 | 每项任务固定抽取一个原物理请求，选择基线或一项表达政策。全部划分复用相同请求，本项研究未产生新模型结果。 |
| 测量 | 保留原安全产出、有限功能、Oracle 支持及完整终止状态。政策身份为 local、example、reference。 |
| 结果组装 | 每项划分使用 200 项训练、200 项 CAL。校准选择后评价全部 400 项 E 任务；同一任务对八项选择等权平均。 |
| 推断与报告 | 按原家族重抽取完整 E 任务，全部划分结果随任务共同移动。四项主要比较使用 5000 项任务 bootstrap 和 Bonferroni 描述区间。 |

消费者实际读取 `pcalg::pag2anc` 返回的确定非祖先判定。
设共同预测效果为 d_i(W)，八项训练子样本的非祖先频率为 s_i，
政策分数为 `d_i(W)*(1-strength*s_i)`。未知祖先关系保留候选。
模型选择允许不编辑；频率及条件独立非拒绝只提供可校准的收缩建议。

直接收缩、直接 CI、直接下界、FCI-time、JCI12、JCI123 和方向消融各有
50 项模型/强度配置及一项保留基线候选。共同参考有十项模型及同一基线候选。
全部方法共用完整属性和目标分解表示、Ridge 网格、任务子样本、配对差值和 CAL 目标。
直接候选合集含 164 项候选，作为预算较大的补充对照。

方向消融读取同一批 JCI123 图，只使用 Ci 与 Y 是否相邻；其模型、收缩和校准预算
均与祖先判定消费者相同。直接 CI 使用 `Ci ⟂ Y | C_minus_i`，与结构方法共用条件检验
数据和随机查询流。三种 FCI 各运行 72 次，方向消融复用图形。
条件检验缓存由三种结构方法共同使用，运行耗时不能解释为各方法单独执行的计算成本。

## 主要收益比较

下表单位为百分点，方向为 JCI123 减比较方法。描述区间同时覆盖预定的四项比较。
每项比较的分母为 400 项评价任务，每项任务首先对八项划分等权平均。

| 比较方法 | 安全产出收益差 | 描述区间 | 不同动作的位置数 / 3200 |
| --- | ---: | --- | ---: |
| 直接收缩 | 0.0000000 | [0，0] | 0 |
| 直接 CI | +0.0078125 | [0，+0.0312500] | 10 |
| FCI-time | 0.0000000 | [0，0] | 0 |
| 共同参考 | 0.0000000 | [0，0] | 0 |

JCI123、FCI-time、直接收缩及共同参考在全部八项划分中选择相同动作。
直接 CI 在一项划分中采用 0.75 的收缩强度，导致十项任务位置的动作变化。
相对直接 CI 的收益差来自这些选择，区间包含零。本研究未建立 JCI 的独立收益增量。
动作相同对应的 `[0,0]` 描述区间表示保存选择的逐任务结果完全相同，不能解释为
真实政策效果为零或一般情况下的方法等价证明。

## 安全、功能和测量支持

数值为相对全部采用原基线的变化，单位为百分点。编辑任务数是八项划分的平均值。
第一行各方法在全部任务位置选择相同动作，其余方法单独报告。

| 方法 | 平均编辑任务数 / 400 | 安全产出变化 | 有限功能变化 | Oracle 支持变化 |
| --- | ---: | ---: | ---: | ---: |
| 共同参考、直接收缩、FCI-time、JCI12、JCI123、方向消融 | 273.750 | −0.2968750 | −1.0625000 | −0.3984375 |
| 直接 CI | 273.750 | −0.3046875 | −1.0468750 | −0.4062500 |
| 直接下界 | 259.000 | −0.3125000 | −0.8906250 | −0.4453125 |
| 直接候选合集 | 261.875 | −0.2734375 | −0.9375000 | −0.4062500 |

全部方法的平均安全产出和有限功能变化均为负值。CAL 的选择目标仅使用原安全产出，
这些结果不支持功能保持或安全与功能联合改善。Oracle 支持变化单独保留，
不能将原安全产出变化直接解释为潜在软件安全性的变化。

## 因果方向为何没有改变动作

| 查询或决策 | 观察结果 |
| --- | ---: |
| JCI123 与 FCI-time 的 PAG 不同 | 72 / 72 组图形比较 |
| 政策上下文到 Y 的祖先判定不同 | 0 / 72 组图形比较 |
| 祖先判定与邻接消融的最终动作不同 | 0 / 3200 项任务位置 |
| JCI123 校准选择非零收缩强度 | 0 / 8 项划分 |

每项划分中，FCI-time、JCI12、JCI123 对三项政策提供的非祖先频率均为 `[1,1,1]`。
因此，强度小于一时，全部政策分数乘以相同的正数，排序及正负保持不变；
强度等于一时，全部分数为零，对应共同候选中的保留基线动作。
这些结构建议没有增加共同参考之外的动作，CAL 均选择零收缩强度。

PAG 的变化没有提供政策祖先查询上的额外区分；方向消融也没有失去可观察的决策价值。
这一结果定位了本项材料中的具体限制：方向信息已经进入消费者，但目标查询及政策
收缩建议在方法之间相同。有限样本的确定非祖先输出仍是估计图的判定，
本研究没有独立资格证据将其解释为真实政策无效。

## 任务依赖与证据范围

八项划分复用 D=400 和 E=400，不能视为八项独立实验或 3200 项独立评价任务。
主要估计量对应八项冻结学习结果的等权策略混合。区间仅描述已暴露 E 任务的
家族内重抽取变动，未重新抽取训练总体，不能提供确认性覆盖保证。

E 属于原有四项家族；本研究没有新的家族迁移或自然任务证据。
local、example、reference 保留其表达政策身份，不能扩大解释为完整 Atomic 安全要求。
原失败与未知测量沿用冻结端点，全部 400 项评价任务保留。
确认性 assigned-arm ITT、条件修饰效应规则及正式协议状态均保持原有边界。

## 输出与实现对应

| 输出 | 实现函数 | 保存字段 |
| --- | --- | --- |
| 原请求、划分及原政策差值 | `experiment.jci_policy.historical_data` | `splits/*/result.json` 的 `training`、`calibration`、`evaluation`、`source_hashes` |
| FCI 图形与祖先判定 | `discovery.jci_policy.discover_contexts`、`jci_policy.R` | `learned.graphs[].results.*.{pag,ancestry,context_ancestry}` |
| 直接 CI 与共同条件检验 | `ConditionalPermutation.query` | `learned.graphs[].direct_context_p`、`queries` |
| 共同拟合、收缩、校准与动作 | `discovery.jci_policy.learn_policies` | `learned.{candidates,choices,outputs,nonancestry_support}` |
| 安全、功能与支持的任务值 | `experiment.jci_policy.run_historical` | `panels.*.assignments` |
| 任务平均值、主要比较及区间 | `experiment.jci_policy.summarize_exposed_direction` | `summary/result.json` 的 `method_values`、`primary_comparisons`、`task_values` |
| 方向查询和消融诊断 | 同一汇总函数 | `summary/result.json` 的 `graph_diagnostics` |
| 独立来源、数值及完整分母核验 | `verification.jci_policy.verify_exposed_direction` | `verification/result.json` |

## 环境与复现

环境为 Windows、Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、
R 4.3.1 和 pcalg 2.7.12。执行使用 `.test-tmp/jci-reviewer-env` 的 Python 3.12 环境；
R 包位于 `.codex-runtime/r-lib`。输入和科学执行源码身份保存在 `inputs/identity.json`，
科学执行源码存档为 `source.zip`。

从仓库根目录使用尚未存在的输出目录执行以下命令；全部方法使用同一冻结配置。

```powershell
$env:OPENBLAS_NUM_THREADS='1'
$env:OMP_NUM_THREADS='1'
python -m prompt_mechanism_study study jci-sharing results/NEW_DIRECTION_RUN --joint-policies --historical-only --plan data/method/jci-sharing-20261014/direction-plan.json --rscript D:/R/R-4.3.1/bin/x64/Rscript.exe
python -m prompt_mechanism_study study verify-jci-sharing results/NEW_DIRECTION_RUN --joint-policies
```

默认 reviewer 路径通过 108 项检查，已有联合研究与约束拟合各通过五项专项检查。
本项三项专项检查分别通过，覆盖固定请求与来源绑定、代表性划分和完整独立重算。
完整核验状态为 `verified`：重算 720 项模型拟合，检查 8704 项条件检验的原任务列联表、
统计量和 p 值表达式，核对 400 个原终止请求，并重算全部候选选择、完整任务分母、
主要收益差和 bootstrap 区间。记录位于 `verification/result.json`，核验源码 SHA256 为
`30cb775d3ba7161f740d4550f491e1d38c7e9872437bddef519c1e92b30e191c`。

阅读顺序为：本报告、冻结方案、`direction-plan.json`、`src/discovery/jci_policy.py`、
`src/discovery/jci_policy.R`、`src/experiment/jci_policy.py`、`src/verification/jci_policy.py`、
`tests/development/test_jci_direction.py`。
