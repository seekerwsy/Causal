# JCI 条件共享与政策校准实验结果

## 研究范围与执行身份

用户于 2026-10-14 授权针对 JCI 适配方法并运行探究。本次完成四种预定结构机制、两个任务数量、每项十六个独立重复，共 128 个计算重复；每个重复同时比较两种变量视图及两种结构方法。计算部分实际执行 512 次 FCI，历史代码分析执行 12 次 FCI，另执行 768 项广义后门准则查询。新增模型调用为零。

正式协议保持 `SPECIFIED_DRAFT`。计算研究身份为 `AUTHORIZED_BOUNDED_METHOD_DEVELOPMENT`；历史分析身份为 `POST_HOC_EXPOSED_ORIGINAL_ENDPOINT_REANALYSIS`；共享分量校准身份为 `POST_HOC_EXPOSED_CALIBRATION_TARGET_CHECK`。全部计算使用明确的 Bernoulli 结构方程模型，历史分析读取已冻结的真实生成结果。它们均未提供新的自然任务确认性证据。

冻结配置为 [`plan.json`](../../data/method/jci-sharing-20261014/plan.json)，SHA-256 为 `20ccb99f9c89c625f138729b2d0b211ff6245971209bf3ee69a89dd91d1233c2`。完整设计见[实验方案](2026-10-14-jci-sharing-plan.md)。结果根目录为 [`results/jci-sharing-20261014`](../../results/jci-sharing-20261014)。

## 七阶段适配

| 阶段 | 本次实现与科学边界 | 保存位置 |
| --- | --- | --- |
| 表示 | W1 表示初始要求状态，W2 表示作用条件或潜在属性的代理，W3 表示背景属性；X 表示准备完成的提示要求状态。分别比较包含和省略 X 的视图。Prompt TSG 的语义关系不直接转为因果关系。 | 每个 `cells/*/result.json` 的 `training`、`calibration` |
| 优先化 | 时间背景 FCI 与增加随机分配 JCI12 约束的 FCI 使用共同条件检验。通过 m-separation 提出来源属性集合及其子集，完整属性集合保留为参考。 | `views.*.structure` |
| 假设冻结 | 冻结机制、数量、独立重复、CI 检验、共享容忍、正则化和阈值网格；训练任务与 CAL 任务分离。 | `inputs/plan.json`、`inputs/identity.json` |
| 干预与随机化 | A 表示分配到基线或要求状态改变。F 在结果产生前决定编辑是否完成；相同提示共用结果。结构搜索每项任务只选取一个分配结果，全部分配任务进入价值计算。 | `a`、`fidelity`、`outcomes`、`task_ids` |
| 测量 | 计算研究独立抽取 Bernoulli 结果；历史研究保留原安全产出、有限功能、覆盖及失败状态。代码及代码结构不进入主结构图。 | `delta`、历史 `policies` 与 `panels` |
| 结果组装 | Ridge 同时拟合共享部分 g(W_S) 和环境差异 h_E(W)。CAL 评价候选动作，选择后在保留环境 E=3 精确求和。 | `calibration_candidates`、`choices`、`values` |
| 推断与报告 | 按独立计算重复进行成对汇总；两种视图共享同一批任务，分别报告。历史结果及校准研究按其探索性身份报告。 | `summary/result.json`、`historical/result.json`、`calibration-revision/summary/result.json` |

每个训练环境与 CAL 环境分别有 128 或 512 项独立任务，环境编号为 0、1、2；每个分配组包含八次结果抽样。八次生成不会增加独立任务数。保留环境编号为 3，真实价值对八种 W 状态及未观察的 F、U 积分。原始计算配置的三个主要比较为 JCI checked 相对完整属性参考、直接效果检验和时间背景方法的增量，共 48 项同时比较。

## 原冻结消费者的结果

下表报告保留环境中的收益相对全部采用基线的变化，单位为百分点。数值为十六个独立重复的平均值。两种变量视图的结果相同。

| 机制 | 每个环境的任务数 | 完整属性参考 | JCI checked | JCI unchecked |
| --- | ---: | ---: | ---: | ---: |
| baseline_shift | 128 | +12.0000 | 0.0000 | +9.2500 |
| baseline_shift | 512 | +12.0000 | 0.0000 | +1.5000 |
| scope_sign | 128 | +12.0000 | 0.0000 | +12.0000 |
| scope_sign | 512 | +12.0000 | 0.0000 | +12.0000 |
| effect_shift | 128 | −6.2250 | 0.0000 | −5.2875 |
| effect_shift | 512 | −7.2000 | 0.0000 | −6.0000 |
| proxy_shift | 128 | −4.7133 | 0.0000 | −3.2148 |
| proxy_shift | 512 | −6.2922 | 0.0000 | −2.0625 |

直接效果检验、时间背景 checked 与 JCI checked 均选择了全部保留基线，因此收益为零。该数值描述动作选择，真实政策效果仍可以为正或为负。JCI checked 相对时间背景 checked 和直接效果检验的全部成对差值为零；原统计汇总中相应区间均为 `[0,0]`。这项相等关系限于本次确定的机制与消费者。

原冻结结果保存在 `summary/result.json` 的 `groups[].mean_gains` 和 `groups[].comparisons`。完整属性参考与 unchecked 在效果方向变化、代理关系变化时均出现负收益，训练环境中的改善未能保证保留环境中的改善。

## 结构信息与共享资格诊断

### 定向信息没有改变当前共享集合

| 变量视图 | JCI 与时间背景 PAG 不同的重复数 | 充分集合不同的重复数 | 候选集合不同的重复数 |
| --- | ---: | ---: | ---: |
| pretreatment | 38 / 128 | 0 / 128 | 0 / 128 |
| prompt_state | 128 / 128 | 0 / 128 | 0 / 128 |

本实现从同一条件独立搜索结果添加定向约束，再以 m-separation 作为共享集合消费者。因果图的定向细化保留相同的条件独立结构时，同一 Markov 等价类内的分离查询给出相同答案。保存的充分集合、候选集合和最终动作逐项验证了这一限制。增加准备完成状态 X 后，定向变化仍未传递到共享集合。

额外使用 `pcalg::backdoor` 对保存的 PAG 查询总分配效果 A→Y，以及包含 X 时的 X→Y。两种方法各自在 pretreatment 中通过 90/128 项 A 查询，在 prompt_state 中通过 119/128 项 A 查询及 89/128 项 X 查询。768 项查询中的成对识别状态差异为零。该检查涉及估计图上的广义后门准则；图估计误差、支持条件及其他识别途径仍在其范围之外。随机分配本身提供的 ITT 身份保持独立。

### 资格检验的精度不足

按真实结构方程检查，baseline_shift 与 scope_sign 的 64 个计算重复存在满足冻结容忍的共享集合；全部 128 个重复的样本资格检验均没有集合通过。effect_shift 与 proxy_shift 的真实效果变化超出该容忍。

资格检验同时覆盖来源属性的省略效果差异和环境效果差异。计算研究每次使用 309 项冻结比较，误差容忍为 0.10，错误率为 0.05，使用 Bonferroni t 区间，任何来源状态少于四项任务时保留支持不足。N=512 时，各重复的区间半宽中位数平均为：baseline_shift 0.1856、scope_sign 0.1859、effect_shift 0.1801、proxy_shift 0.2301，均大于容忍范围。N=128 时对应数值为 0.5713、0.5573、0.5405、0.7163。

这些结果支持“当前任务数量与检验族无法证实共享”的解释。原有 unknown、unresolved 和支持不足状态全部保留；误差容忍、错误率及检验族保持冻结值。近似 t 区间的行为也限制了该诊断可承担的保证。

诊断证据位于 `diagnostics/result.json` 的 `graph_counts`、`cells[].exact_qualified`、`cells[].observed_qualified`、`cells[].interval_radius_median`、`causal_queries`。

## 共享分量的校准结果

新环境只部署 g(W_S)，环境差异 h_E(W) 在未知环境中为零。因此，校准研究直接用独立 CAL 任务评价 g 的动作价值，并让完整属性参考参与共同选择。共享资格继续单独报告；选择完整属性参考的 `sharing_qualified` 保持 false。

该研究在读取原结果后执行，冻结身份为 `POST_HOC_EXPOSED_CALIBRATION_TARGET_CHECK`。全部任务、结果、结构、拟合系数、资格阈值与检验族复用原记录，新增随机观测和模型调用均为零。原结果完整保留。

| 机制 | 每个环境的任务数 | 完整属性参考 | JCI checked | JCI unchecked |
| --- | ---: | ---: | ---: | ---: |
| baseline_shift | 128 | +12.0000 | +12.0000 | +12.0000 |
| baseline_shift | 512 | +12.0000 | +12.0000 | +12.0000 |
| scope_sign | 128 | +12.0000 | +12.0000 | +12.0000 |
| scope_sign | 512 | +12.0000 | +12.0000 | +12.0000 |
| effect_shift | 128 | −7.2000 | −7.2000 | −7.2000 |
| effect_shift | 512 | −7.2000 | −7.2000 | −7.2000 |
| proxy_shift | 128 | −5.2938 | −5.2938 | −5.2938 |
| proxy_shift | 512 | −5.8484 | −5.8484 | −5.9594 |

直接效果检验和时间背景 checked 与 JCI checked 的动作、收益相同。两种变量视图仍给出相同结果。稳定机制中收益恢复到 +12 个百分点；效果方向变化和代理关系变化保留负收益。g 的部署目标校准改善了特定机制中的选择，却没有建立 JCI 的独立增量或跨环境可靠性。

这些数值位于 `calibration-revision/summary/result.json` 的 `groups[].mean_gains`；对应选择、完整属性参考身份与保留环境价值位于 `calibration-revision/cells/*/result.json`。

## 真实历史代码结果

分析使用 controlled-semantic-20260930 中已暴露的 D=400 项任务，按家族和冻结散列划分为训练 200 项、CAL 200 项；E=400 项任务仅用于此项配置的评价。E 的任务属于原有家族，该分析不提供新家族迁移证据。local、example、reference 表达政策沿用原测量定义，不能据此扩大为完整 Atomic 安全要求的效果。

| 消费者 | 编辑任务数 / 400 | 原安全产出变化，百分点 | 有限功能变化，百分点 | 测量支持变化，百分点 |
| --- | ---: | ---: | ---: | ---: |
| 完整属性参考 | 174 | +0.5625 | +0.1250 | +0.7500 |
| JCI unchecked | 157 | +0.6250 | −0.9375 | +0.7500 |
| 直接效果 checked | 0 | 0.0000 | 0.0000 | 0.0000 |
| 时间背景 checked | 0 | 0.0000 | 0.0000 | 0.0000 |
| JCI checked | 0 | 0.0000 | 0.0000 | 0.0000 |

两种视图相同。全部消费者的分母均为 400 项任务。JCI unchecked 的有限功能降低与安全产出变化共同保留；该分析没有建立安全和功能联合改善，也没有确认性的效果结论。

结构样本位置的原终止状态分别为 local 400 项 returned，example 399 项 returned 与 1 项 generation_failed，reference 397 项 returned 与 3 项 generation_failed。不同政策位置可能读取同一物理请求，因此这些计数表示分析位置。失败请求直接读取冻结终止记录及其安全产出，全部留在指定分母内。相同全文候选的预测收益固定为零。

来源身份见 `historical/result.json` 的 `source_hashes`，动作及逐任务变化见 `panels.*.*.assignments`，汇总见 `panels.*.*`。新校准研究当前覆盖计算结果；历史表保留其原冻结消费者身份。

## 实现位置与证据对应

| 科学输出 | 实现函数 | 原始字段 | 汇总函数或位置 |
| --- | --- | --- | --- |
| 固定边缘条件检验 | `ConditionalPermutation.query` | `views.*.structure.queries` | 独立核验重算 Pearson 统计量与 p 值表达式 |
| JCI / 时间背景结构及充分集合 | `StructureBackend.search` 与 `jci_sharing.R` | `structure.results.*.{pag,mag,sufficient,proposals}` | `diagnose_jci_sharing` |
| 共享资格 | `qualification` | `qualification.*` | `summarize` 与 `diagnose_jci_sharing` |
| 原消费者价值 | `fit_effect_model`、`select_models`、`exact_value` | `calibration_candidates`、`choices`、`values` | `summarize` |
| g 的校准价值 | `recalibrate_shared_component` | 校准目录的 `choices`、`values` | `recalibrate_saved_sharing` |
| 历史原测量的选择价值 | `historical_reanalysis` | `policies`、`panels.*.*.assignments` | `historical_reanalysis` 的任务等权均值 |
| 独立数值检查 | `verify_jci_sharing` | `verification/result.json` | 独立设计矩阵、特征分解求解和有限状态求和 |

## 环境与复现

执行环境为 Windows、Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、R 4.3.1、pcalg 2.7.12、jsonlite 2.0.0。R 包位于仓库的 `.codex-runtime/r-lib`。计算任务使用真实 pcalg FCI；Python 独立核验使用特征分解重算生产实现中由 scikit-learn Ridge 求得的系数。

从仓库根目录安装 `.[dev,selectors,languages,analysis]`。新增输出目录可以执行完整的同配置开发研究，然后执行已保存结果的共享分量校准：

```powershell
python -m prompt_mechanism_study study jci-sharing .test-tmp/jci-reproduction --plan data/method/jci-sharing-20261014/plan.json --rscript D:/R/R-4.3.1/bin/x64/Rscript.exe
python -m prompt_mechanism_study study jci-sharing .test-tmp/jci-reproduction --plan data/method/jci-sharing-20261014/plan.json --rscript D:/R/R-4.3.1/bin/x64/Rscript.exe --recalibrate-saved
```

输入身份变化时，已冻结目录拒绝接续和覆盖。`--limit 1` 可以执行预定代表性重复，随后以相同实现继续同一目录。原冻结计算及分析实现分别保存在 `source-initial.zip`、`source-after-analysis.zip`；`analysis-amendment/result.json` 关联各自源码身份。当前实现生成新目录时保留同一科学计算规则；运行耗时等执行信息独立产生。

检查已保存实验的入口为：

```powershell
$env:OPENBLAS_NUM_THREADS = '1'
$env:OMP_NUM_THREADS = '1'
python -m prompt_mechanism_study study verify-jci-sharing results/jci-sharing-20261014
```

结构诊断入口为 `study diagnose-jci-sharing OUTPUT --rscript PATH`。该命令读取已保存图并执行广义后门查询，其结果另行保存于 `diagnostics`。

现有单一 reviewer 路径继续使用 `study smoke OUTPUT` 与 `study verify-result OUTPUT`。在干净的 Python 3.12 环境中，reviewer smoke 完成 10 项任务、40 项分配，并通过独立核验；其结果包散列为 `3872ac2ba1c81fe5fb7573f66dd5947d2f976fade5448bb5bb30c5aa7bb38be3`。默认测试与显式加入的 JCI 开发检查共同通过 108 项测试。JCI 开发检查覆盖有限状态表示、真实计算抽样、任务分离、相同输入的零效果、独立正则化解、精确策略价值、条件检验及 g 的校准。

已保存实验的独立核验状态为 `verified`：检查全部 128 个计算重复，独立重算 9,228 个模型拟合、8,996 项条件检验的统计量与 p 值表达式，以及 128 项共享分量校准结果；原汇总与历史请求核对均通过。记录位于 `verification/result.json`，核验实现 SHA-256 为 `1af3350ecaff8eb4c38faad918adfb1261bf1630101f7ebe2ddbc014060ced2f`。

阅读本次研究可依次查看以下十项文件：

1. 本报告。
2. [冻结方案](2026-10-14-jci-sharing-plan.md)。
3. [`data/method/jci-sharing-20261014/plan.json`](../../data/method/jci-sharing-20261014/plan.json)。
4. [`src/discovery/jci_sharing.py`](../../src/discovery/jci_sharing.py)。
5. [`src/discovery/jci_sharing.R`](../../src/discovery/jci_sharing.R)。
6. [`src/experiment/jci_sharing.py`](../../src/experiment/jci_sharing.py)。
7. [`src/verification/jci_sharing.py`](../../src/verification/jci_sharing.py)。
8. [`src/verification/jci_sharing_diagnostics.py`](../../src/verification/jci_sharing_diagnostics.py)。
9. [`src/verification/jci_queries.R`](../../src/verification/jci_queries.R)。
10. [`tests/development/test_jci_sharing.py`](../../tests/development/test_jci_sharing.py)。
