# 来源上下文 JCI 完整机制实验

## 完整结果

全部 176 次运行已经执行，独立验证状态为 `VERIFIED`，核对 391,296 个拟合模型和 54,561 项条件检验。验证器 SHA256 为 `3a8792cdbcdbd2b2193dd66a723114f47ea612c44a9a0966031909b19d6fae87`。十一种机制均未达到预定主要组件门槛，全部校正区间包含零。下表的方差差值为直接方法减去 JCI；负的改善比例表示精度下降。

| 机制 | 方差改善 | 校正区间（方差差值） | 两批次均改善 | 达到预定门槛 | 平均确认数量差 |
| --- | ---: | --- | --- | --- | ---: |
| irrelevant_context | 0.40% | [-0.0000296, 0.0001583] | 是 | 否 | +0.0000 |
| confounded_proxy | 0.01% | [-0.0003374, 0.0003416] | 否 | 否 | +0.1250 |
| multi_target | 0.77% | [-0.0000064, 0.0002504] | 是 | 否 | +0.0000 |
| all_relevant | 0.36% | [-0.0003487, 0.0004592] | 否 | 否 | +0.0000 |
| weak_context | 0.13% | [-0.0000432, 0.0000852] | 否 | 否 | +0.0000 |
| cancellation | -1.49% | [-0.0010252, 0.0005573] | 否 | 否 | +0.0000 |
| no_shift | 0.58% | [-0.0000775, 0.0002604] | 是 | 否 | +0.0000 |
| unobserved_attribute | 0.88% | [-0.0002052, 0.0004827] | 是 | 否 | +0.0625 |
| proxy_mechanism_change | -0.06% | [-0.0003377, 0.0003181] | 否 | 否 | -0.0625 |
| source_spillover | 0.61% | [-0.0001233, 0.0003152] | 是 | 否 | +0.0000 |
| outcome_shift | 0.57% | [-0.0001017, 0.0002789] | 是 | 否 | -0.0625 |

每种方法共提名 352 个确认位置。JCI 确认 268 个，其中正向 179 个、负向 89 个；直接子集方法确认 267 个，其中正向 182 个、负向 85 个；真实查询方法确认 267 个；骨架消融确认 265 个。各方法在本轮声明模型下均没有错误方向或未超过实际效应阈值的确认。这些计数不建立独立确认增益，也不建立真实代码安全保证。

1,408 张来源图形中，1,348 张可评价，60 张支持不足并保留未知。JCI 与骨架消融在 704 项假设中有 197 项选择不同模型；JCI 与直接方法有 388 项选择不同模型。176 次学习运行中，两者有 154 次提名相同的候选集合，22 次不同。方向信息确实影响了学习过程，当前结果仍未建立可靠的精度收益。

## 改善空间与损失分解

下表使用已保存的真值风险进行隔离诊断，所有百分比均以直接方法平均方差为分母。可观测最优预测器积分掉潜在 U 与不可见 X；目录最优模型只能在本轮已经拟合的共同候选中选择。目录选择使用真值，仅作诊断，实际方法不能访问。

| 机制 | 可观测最优改善空间 | 已拟合目录最优改善空间 | 真实查询实际改善 | JCI 选择损失 | JCI 候选限制损失 |
| --- | ---: | ---: | ---: | ---: | ---: |
| irrelevant_context | 7.91% | 2.66% | 0.35% | 2.19% | 0.07% |
| confounded_proxy | 8.16% | 2.89% | -0.01% | 2.64% | 0.24% |
| multi_target | 7.88% | 2.74% | 0.80% | 1.38% | 0.58% |
| all_relevant | 8.07% | 2.73% | 0.82% | 2.26% | 0.12% |
| weak_context | 8.22% | 3.01% | 0.28% | 2.80% | 0.08% |
| cancellation | 7.95% | 2.71% | 0.31% | 3.99% | 0.21% |
| no_shift | 7.76% | 2.55% | 0.27% | 1.66% | 0.30% |
| unobserved_attribute | 6.30% | 2.67% | 0.53% | 1.64% | 0.15% |
| proxy_mechanism_change | 8.38% | 2.83% | 0.24% | 2.72% | 0.18% |
| source_spillover | 8.33% | 3.10% | 0.76% | 2.35% | 0.14% |
| outcome_shift | 9.08% | 3.86% | 0.39% | 3.11% | 0.18% |

本轮已拟合目录中，即使事后为每项假设选择真值最优候选，每种机制的平均改善也只有 2.55% 至 3.86%，均低于 5% 门槛。这一数值限定于本轮已生成的候选及预算；它说明当前目录内的选择方法没有足够的实际改善空间，不能据此推断其他预测器、任务分布或预算下的理论极限。

JCI 候选限制损失为 0.07% 至 0.58%，选择损失为 1.38% 至 3.99%。直接方法获得完整共同目录，其候选限制损失为零。JCI 的收益等于直接方法的选择损失，减去 JCI 的选择损失与限制损失。结构建议有时降低选择噪声，限制候选同时可能排除更好的拟合结果。抵消机制中，JCI 选择损失为 3.99%，高于直接方法的 2.71%，同时增加约 0.21% 限制损失，对应总体方差增加 1.49%。

真实来源查询与总体独立信息图形在本轮得到相同的实际风险；它们通过当前消费者的改善为 −0.01% 至 +0.82%。因此，当前缺口同时涉及预测候选和独立校准选择，不能全部归因于有限样本的结构发现错误。

查询诊断还保留了来源信息的边界。弱上下文机制产生 2,576 个 `supported` 掩码记录，其中 1,484 个没有获得真实来源图形支持；关键属性缺失机制的对应数量为 80 和 56。代理机制改变时，500 个建议中有 248 个不满足真实目标环境分离；结果机制改变时，504 个建议均不满足该分离。这里统计的是重复出现的候选掩码记录，存在相关性，不能解释为独立错误率或正式多重检验结果。来源上下文分离仍需目标数据检验，不能认证未知环境中的稳定性。

Graph 独立表示比较保持 `BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS`。当前模拟没有独立参考判断、分别测得的 Graph/Flat 属性表，也没有真实编辑上下文的语义资格、结果重叠和功能性保留证据。本轮没有建立 Graph 表示收益、自然任务迁移收益或正式安全策略改进。

## 执行设计

用户于 2026-10-31 授权执行完整配置。实验使用 `configs/jci-directional-validation.json`，十一种预定机制、两个独立种子批次、每批八次重复，共 176 次完整学习运行、704 项假设。每项假设使用来源任务 1,024 项、目标拟合任务 32 项、独立目标校准任务 32 项、独立目标排序任务 64 项。每项假设另外使用 32,768 项独立配对模拟任务进行双侧确认；每种方法从四项假设提名两项，使用相同逻辑确认预算。

主要对照为同一 Ridge 预测器、同一候选目录和相同数据预算的直接子集选择 `direct_search`。JCI 逐处理臂发现来源图形，查询来源上下文条件分离，限制共享预测候选；全部方法保留完整目标属性修正，并通过独立目标校准选择模型。目标随机化残差修正估计效应。真实查询、总体独立信息图形与骨架消融作为隔离诊断。

证据身份为 `NON_CLAIM_SOURCE_CONTEXT_QUERY_SIMULATION`，正式声明权限为 `false`。本轮执行声明的概率模型，模型服务调用数量为零。结果不构成真实代码模型、安全 Oracle 或自然任务上的效果证据。

## 预定精度规则

主要组件家族 alpha 为 0.01，覆盖十一种机制相对直接子集方法的比较。每种机制包含十六次完整学习重复，使用配对近似 t 区间，并进行整个家族的校正。通过条件同时要求：平均相对效应方差降低至少 5%、校正区间下界大于零、两个独立批次均改善。

确认家族 alpha 为 0.03，覆盖每次重复中的四项假设。效应区间完全超过 +0.04 或低于 −0.04 时确认相应方向。确认数量差异作为描述性诊断，未用于主要组件通过判定。负效应确认说明发现有害修改，不能计为安全加固收益。

## 复现环境与命令

本研究的命令在该研究保存的源码归档中执行。当前活动方法已采用平均结果学习，不能使用当前验证器重新解释本研究的冻结记录。

执行根目录为 `/home/wsy/work/prompt-mechanism-study/inputs/jci-framework`。Python 环境为该目录的 `.codex-runtime/directional-correction-venv`，使用 Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、NetworkX 3.7、R 4.1.2 和 pcalg 2.7.12。R 路径为 `/usr/bin/Rscript`，设置 `OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`；临时文件位于执行根目录的 `.codex-runtime/directional-correction-tmp`。

完整原始结果目录为 `/home/wsy/work/prompt-mechanism-study/results/jci-source-context-full-parallel-20261031`。以下命令使用新目录复现：

```text
python -m pytest -q --rscript=/usr/bin/Rscript
python -m prompt_mechanism_study study jci-directional-validation results/NEW_FULL --plan configs/jci-directional-validation.json --rscript /usr/bin/Rscript --workers 8
python -m prompt_mechanism_study study verify-jci-directional-validation results/NEW_FULL --workers 8
python data/method/jci-source-context-full-20261031/build-report.py results/NEW_FULL results/NEW_FULL_REPORT
```

八个进程只改变运行调度。四次参考运行在排除 R 耗时字段后，任务、图形、查询、全部模型、估计、确认和汇总逐项相同。全部 48 项默认检查通过，包含并行结果生成与独立验证。数值一致性记录为 `data/method/jci-source-context-full-20261031/reference-equivalence.json`，实际检查日志为同目录的 `tests.log`。

冻结源码另存 `results/jci-source-context-full-20261031-source.zip`，SHA256 为 `4e95431095fb9a0e2504eed508a76468f35d82d032b1f95c3994402496d0ff78`。原始配置文件 SHA256 为 `cffa8f5a87e26674e7cf8d5a106fe3cfef9286ddc14acc5d3a723b116a4aae88`。输入、总体诊断、汇总及独立验证的紧凑记录位于 `data/method/jci-source-context-full-20261031`，各个冻结部分保留原始 manifest。

## 结果字段与计算位置

| 科学输出 | 冻结输入与实现 | 保存字段及表格路径 |
| --- | --- | --- |
| 主要 JCI 精度比较 | `inputs/plan.json`；`context_validation.run_directional_validation` 汇总完整学习重复 | `summary/result.json: rows[].comparisons[]`；`build-report.py` 生成 `comparisons.csv`、`comparisons.md` |
| 正、负确认数量 | `_directional_cell` 的冻结提名与独立 `confirmation` 数据 | `cells/*/result.json: decisions`；汇总 `methods[].mean_confirmed_*` |
| 可观测最优方差 | `directional_transfer.observable_optimal_variance` 积分不可见状态 | `hypotheses[].information.observable_optimal_effect_variance`；`derived.json` |
| 候选限制与选择损失 | `catalog_risks`、`query_information`；不重新拟合模型 | `hypotheses[].information.groups`；`derived.json: rows[].methods` |
| 来源查询与目标分离的差异 | `oracle/result.json` 的隔离真实图形诊断；`learned.context_queries` | `derived.json: rows[].query_counts`；记录候选数量，不解释为错误率检验 |
| 独立核对 | `verification.directional_transfer.verify_directional` 独立生成任务、求解预测模型并重算统计量 | `verification/result.json`，保留执行源码与验证器 SHA256 |

`build-report.py` 只读取已通过验证的冻结目录，不新增结果、不改变判定规则，也不选择新的惩罚参数。真实结构诊断沿用当前消费者，不能解释为所有因果结构方法的理论上界。
