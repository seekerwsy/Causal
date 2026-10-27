# 受控语义干预研究结果

研究身份：`controlled-semantic-20260930`。来源、主语义输入、完整发现分析、评价前决策及全部合成评价结果均已执行并独立核验。本文依据[冻结方案](2026-09-30-controlled-semantic-interventions.md)和[完整结果包](../../results/controlled-semantic-20260930/report/manifest.json)报告 H1–H11 及实际成本；H12 因事前自然资格集合为空保持未执行。[独立验证](../../results/controlled-semantic-20260930/verification/verification.json)状态为 `PASSED_CONTROLLED_MAIN_REPORT`。

## 固定任务与来源资格

主面板包含 400 项合成发现任务 D 和 400 项独立合成评价任务 E。每个家族分别包含 100 项 D 任务和 100 项 E 任务。任务身份由操作家族、两个查询、路径投影和集合运算共同确定；两套表达、初始语义状态及提示编辑共享原任务身份。

| 操作家族 | D 任务数 | D 查询组合模板数 | E 任务数 | E 查询组合模板数 |
| --- | ---: | ---: | ---: | ---: |
| find 文件检索 | 100 | 7 | 100 | 8 |
| grep 文本查询 | 100 | 7 | 100 | 8 |
| tar 归档操作 | 100 | 7 | 100 | 8 |
| git 版本管理查询 | 100 | 7 | 100 | 8 |
| 合计 | 400 | 28 | 400 | 32 |

模板身份沿用 `controlled_tasks.candidate_catalog` 中的家族及查询组合；完整功能组合另外包含投影和集合运算。实际纳入的每个角色、家族各有 100 个不同完整功能组合，D/E 的查询组合模板按生成前规则分离。任务范围限定于 Python 和四个真实工具，观察外部输入触发的非预期额外命令执行。合成蓝图提供功能合同与测量参考，Qwen 的安全效果由实际代码观察取得。

冻结任务的初始状态支持如下。各状态分别按任务计数，数值为状态一的任务数；每个角色总数为 400。

| 角色 | local 状态一 | example 状态一 | reference 状态一 |
| --- | ---: | ---: | ---: |
| D | 86 | 296 | 99 |
| E | 102 | 285 | 109 |

自然来源审查覆盖事前固定的全部 419 项。296 项为 `OUTSIDE_TASK_SCOPE`，123 项为 `UNKNOWN_IDENTITY`；实际合格自然任务为零。未知身份记录保存阻止取得独立资格的必要功能见证及独立审查，未完成的其他参照关系继续保留未比较身份。[自然合同与开发参照指纹](../../data/method/controlled-semantic-20260930/natural-preparation/natural-contract-fingerprints.json)共保存 425 条记录；[既有功能合同参照指纹](../../data/method/controlled-semantic-20260930/natural-preparation/reference-contract-fingerprints.json)包含 2165 项任务及 2164 个近重复组，完整参照范围另包含当前六项开发任务，共 2171 项身份。两份文件分别保持 `b761cdf9…131a009` 和 `e51e9a77…746af1da` 的 SHA-256 身份，并包含在生成前冻结的自然准备包中。

三项自然政策集合均在 D 结果出现前冻结为空。发现选择器提名 `local` 后，原集合保持为空，H12 保存 `NATURAL_POLICY_SET_EMPTY`。自然模型生成次数为零，原多重检验位置保留。本研究尚未取得自然任务迁移效果。

## 表示准备与语义资格

Codex 准备表示、目标绑定和全文编辑；Qwen2.5-Coder-32B-Instruct 仅生成代码。D 使用 TSG 流程；E 的 Raw、Rich-Flat、TSG 分别由隔离实例准备。每个准备位置包含同一任务的三项 Atomic 政策及两套表达，独立语义检查在模型生成前完成。目标或表达未通过、未知或未提交的位置已经映射 B，全部位置保留在原分母中。

| 角色与流程 | 政策位置数 | 通过 | 失败 | 未知 | 映射 B 的位置数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| D / TSG | 1200 | 1145 | 54 | 1 | 55 |
| E / Raw | 1200 | 1179 | 18 | 3 | 21 |
| E / Rich-Flat | 1200 | 1158 | 36 | 6 | 42 |
| E / TSG | 1200 | 1092 | 99 | 9 | 108 |
| 合计 | 4800 | 4574 | 207 | 19 | 226 |

该表直接按[冻结任务](../../data/method/controlled-semantic-20260930/experiment-qualified-inputs/tasks.json)的 `policies[flow][j].review.status` 分组，并核对 `semantic_qualified` 与 `execution_mapping`。三个 E 流程的政策位置分母均为 1200，未使用通过检查的位置筛选评价任务。TSG 的合格位置数量在这一实际准备批次中低于 Raw 和 Rich-Flat；后续代码价值比较保留这种准备结果。

E 的三个流程沿用相同 `gpt-6.1-sol`、`high` 配置，每实例一次准备调用、最多 12000 个输出 token，并接受一次独立检查。此前六项 D 准备和前三项检查保留 Astra 的实际身份，授权配置保存于[模型政策](../../data/method/controlled-semantic-20260930/main-model-policy.json)。全部实际准备和额外实例由 `preparation-attempts.json` 记录；缺失 token 计量保持未知。调用配置与输出上限支持本轮资源规则的可检查性，完整资源效率结论还需要完整计量。

上述证据对应作者辅助的表示、绑定和编辑流程。该准备设计使用共同任务来源、共同政策说明及隔离实例，结论范围限定于本轮三项给定政策；自动抽取准确率与开放候选搜索效果需要各自的评价。

## 发现阶段的实际观察

D 完成 7890 条物理生成请求，保留 8000 条逻辑分配。其中覆盖部分包含 4000 条逻辑条件分配，随机混合部分包含 4000 条实际独立请求。失败位置映射及完整相同请求的共享按生成前规则执行。4000 条混合请求独立随机分配任务、五值 context 和表达版本，单独用于主 CI 数据；覆盖请求用于任务等权效果组装。

| D 物理请求状态与安全标签 | 数量 | 主要安全产出 Y |
| --- | ---: | --- |
| 返回代码，secure | 5676 | 1 |
| 返回代码，insecure | 99 | 0 |
| 返回代码，unknown | 1961 | 0 |
| 返回代码，invalid | 135 | 0 |
| generation_failed，unknown | 19 | 0 |
| 合计 | 7890 | 全部分配保留 |

物理请求的代码有效数量为 7736，Oracle 支持数量为 5769，实际直接违规数量为 99，有限普通功能通过数量为 2322。全部 7890 条请求的完整功能资格仍为未知，不能据有限见证给出完整安全且完整功能的联合成功结论。表中计数是请求级诊断；主要政策效果继续按任务等权和表达等权计算。模型代码不可评价的 Y=0 保留其 unknown 标签，基础设施缺失沿原规则单独处理。

发现阶段的方向规范化共同效果为：

| 政策 | 状态一减状态零的 D 共同效果 | 百分点 |
| --- | ---: | ---: |
| local | -0.07341666666666667 | -7.341667 |
| example | -0.02137202380952381 | -2.137202 |
| reference | -0.00837202380952381 | -0.837202 |

数值来自 `canonical-effects.json`，采用每任务先计算条件与表达均值，再乘 `1-2Z` 并对 400 项任务等权平均的冻结规则。这些发现结果用于选择政策和预测方向；独立评价结果见 H1–H11。

## 结构差异与评价前选择

FCI-time 与 JCI12-FCI 使用同一 4000 条混合观察、同一查询结果和随机子流。完整面板各执行一次搜索，100 份 80% 无放回子样本分别执行两种搜索，共 202 次。全部搜索完成，FCI 与 JCI 的统计未确定数量均为零，结构计算为 84.8225 CPU 秒。独立验证从冻结输入复算 6784 条 CI 查询及全部图结果。

完整面板的 PAG 端点为：

| 关系 | FCI-time | JCI12-FCI |
| --- | --- | --- |
| C 与 X_local | C ↔ X_local | C → X_local |
| C 与 X_example | C ↔ X_example | C → X_example |
| C 与 X_reference | C ↔ X_reference | C → X_reference |
| V 与 Y | V ○→ Y | V → Y |

JCI 背景改变了 context 的端点方向。三个目标 X 在两种方法的 100 份预定子样本中取得的全定向 Y 祖先支持均为 0/100。该结果没有提供三个 X 的定向祖先支持；其解释继续受设计、变量语义、Markov、faithfulness 和背景知识约束。Prompt TSG 边保留来源语义，PAG 结构另由实际结果和背景知识取得。

| 政策 | FCI 支持 | JCI 支持 | RD 评分 | FCI 评分 | JCI 评分 |
| --- | ---: | ---: | ---: | ---: | ---: |
| local | 0 | 0 | 0.07341666666666667 | 0.07341666666666667 | 0.07341666666666667 |
| example | 0 | 0 | 0.02137202380952381 | 0.02137202380952381 | 0.02137202380952381 |
| reference | 0 | 0 | 0.00837202380952381 | 0.00837202380952381 | 0.00837202380952381 |

RD、FCI、JCI 均选择 `local`，冻结方向均为 -1；六种支持置换也分别选择同一政策和方向，每种保留六分之一权重。结构端点发生变化，冻结评分与选择保持相同。评价前 H7、H8、H9 的合并物理系数全部抵消，非零系数数量和固定半宽均为零。这是同一冻结选择规则的代数性质；该面板无法通过这些恒等动作比较提供 JCI 决策增量证据。

辅助 Ridge 使用规定的 16 个特征、任务等权标签和固定五折。各 lambda 的任务等权验证误差如下，最小值对应 lambda=0.1。

| lambda | 验证均方误差 |
| --- | ---: |
| 0.01 | 0.06117200512455941 |
| 0.1 | 0.06103397258005197 |
| 1 | 0.06107195979968641 |
| 10 | 0.06269532113266235 |
| 100 | 0.06345131772790316 |

Ridge 的留出选择价值为 0.0275，描述性固定面板区间为 [-0.03175656796165491, 0.0867565679616549]，区间包含零。该辅助结果来自 `selector-values.json` 的 `Ridge`，保留原任务、方向和物理系数。context-modifier 确认性推断状态为 `BLOCKED`：精确任务分配、联合 bootstrap 和多重检验规则尚未前瞻性冻结，当前研究不执行该推断。

## 独立评价与十二项主要比较

E 的冻结分配为 9216 条物理请求、17600 条逻辑分配，包含 8000 条 TSG 主条件和 9600 条 Raw／Rich-Flat 目标条件；共同 B、S 和其他满足共享身份的请求引用同一实际观察。评价前选择于 2026-10-04 14:03:34 UTC 冻结，随后才启动 E 代码生成。

全部 9216 条评价请求已经执行并保存，最终模型服务于 2026-10-05 06:51:52 UTC 实际停止。八条独立测量基础设施失败使用原代码和冻结环境恢复观察，各自通过独立核验，原基础设施未知文件完整保留；第四、六条恢复观察的安全标签为 unknown，第五条为 insecure，三条主要安全产出均为 0。第四、五条有限功能检查失败，第六条有限功能检查通过；第七、八条安全产出均为 1，有限功能检查通过，完整功能均保持未知。两段模型初始化失败没有产生新增生成请求。服务及执行证据见[执行记录](2026-09-30-controlled-semantic-execution.md)；E 观察没有用于修改选择、系数、方向或研究规则。完整独立验证核对全部请求、八份恢复观察、汇总与报告。

| 比较 | 点估计 | 固定面板区间 | 状态与解释 |
| --- | ---: | --- | --- |
| H1：TSG local，状态一减状态零 | -0.03875 | [-0.09800656796165491, 0.020506567961654905] | COMPLETE，包含零 |
| H2：TSG example，状态一减状态零 | -0.0025 | [-0.06175656796165491, 0.0567565679616549] | COMPLETE，包含零 |
| H3：TSG reference，状态一减状态零 | -0.00875 | [-0.06800656796165491, 0.050506567961654904] | COMPLETE，包含零 |
| H4：TSG local 相对 S，方向规范化 | -0.039375 | [-0.10149276167038467, 0.022742761670384665] | COMPLETE，包含零 |
| H5：TSG example 相对 S，方向规范化 | 0.005625 | [-0.05649276167038467, 0.06774276167038466] | COMPLETE，包含零 |
| H6：TSG reference 相对 S，方向规范化 | -0.003125 | [-0.06524276167038466, 0.05899276167038466] | COMPLETE，包含零 |
| H7：JCI 减 RD | 0 | [0, 0] | COMPLETE，相同选择的物理系数抵消 |
| H8：JCI 减 FCI | 0 | [0, 0] | COMPLETE，相同选择的物理系数抵消 |
| H9：JCI 减六种支持置换均值 | 0 | [0, 0] | COMPLETE，相同选择的物理系数抵消 |
| H10：共同 RD 选择价值，TSG 减 Raw | -0.0075 | [-0.038558880835192336, 0.023558880835192333] | COMPLETE，包含零 |
| H11：共同 RD 选择价值，TSG 减 Rich-Flat | -0.005625 | [-0.03459479545145546, 0.023344795451455465] | COMPLETE，包含零 |
| H12：自然迁移 | 未取得 | 未取得 | unexecuted，NATURAL_POLICY_SET_EMPTY |

全部比较保留双侧 alpha=0.05/12。实际区间按合并后的物理请求系数、独立随机组和 `log(480)` 计算；后分配符合度、生成状态和测量支持均不筛选任务分母。请求级固定面板区间覆盖本轮冻结任务、准备结果、提示全文及有限表达分布；任务总体、准备随机性、模板外推及观察器系统误差需要独立证据。

H1–H3 的冻结半宽为 0.059256567961654905，H4–H6 为 0.062117761670384665，H10 为 0.031058880835192332，H11 为 0.028969795451455463。H7–H9 半宽均为零；这些恒等选择没有提供方法增量或算法普遍等效的证据。八份恢复测量纳入后，已执行比较的端点缺失数量为零，`completion_bounds` 均为 [点估计, 点估计]；安全 unknown 继续按冻结端点贡献 Y=0。

H1 的负向点估计为 -3.875 个百分点，其区间包含零。H10、H11 的点估计分别为 -0.75、-0.5625 个百分点，区间同样包含零，本面板没有建立 TSG 的正向增量。RD、FCI、JCI 和支持置换的方向加权选择价值均为 0.03875，描述性区间为 [-0.020506567961654905, 0.09800656796165491]。冻结方向为 -1，正的方向加权价值表示与预测的安全产出下降方向一致，不能解释为安全改善。

## 评价观察与条件诊断

| E 物理请求状态与安全标签 | 数量 | 主要安全产出 Y |
| --- | ---: | --- |
| 返回代码，secure | 6753 | 1 |
| 返回代码，insecure | 43 | 0 |
| 返回代码，unknown | 2299 | 0 |
| 返回代码，invalid | 107 | 0 |
| generation_failed，unknown | 14 | 0 |
| 合计 | 9216 | 全部分配保留 |

`observations.json` 保存上述全部物理结果，代码有效为 9095，Oracle 支持为 6789，直接违规为 43，有限普通功能通过为 3101；全部 9216 条均未取得完整功能结果，其中 9095 条保存 unknown，121 条无有效代码或生成失败保存 null。14 条生成失败均保留原分配，未重新生成。安全未知、代码有效性、有限功能及完整功能分别保存，不能据 Y 或有限功能见证报告完整联合成功。

下表按 `cases.json` 的 `conditions.mean` 与 `conditions.versions.mean` 对 400 项任务等权平均。数值为安全产出比例；每条件保留 1600 条逻辑分配，每表达保留 800 条。共同 B、S 在各流程中使用相同实际请求，表中分别显示一次。

| 流程／条件 | 两套表达均值 | 表达一均值 | 表达二均值 |
| --- | ---: | ---: | ---: |
| 共同 B | 0.744375 | 0.77875 | 0.71 |
| TSG / local | 0.718125 | 0.73875 | 0.6975 |
| TSG / example | 0.740625 | 0.76375 | 0.7175 |
| TSG / reference | 0.735625 | 0.7575 | 0.71375 |
| 共同 S | 0.745 | 0.775 | 0.715 |
| Raw / local | 0.710625 | 0.72375 | 0.6975 |
| Raw / example | 0.738125 | 0.76125 | 0.715 |
| Raw / reference | 0.73875 | 0.76625 | 0.71125 |
| Rich-Flat / local | 0.70875 | 0.7275 | 0.69 |
| Rich-Flat / example | 0.73 | 0.7525 | 0.7075 |
| Rich-Flat / reference | 0.735625 | 0.76125 | 0.71 |

原状态翻转后的 TSG local 相对 B 的实际均值差为 -0.02625。该描述性差值按本面板的初始状态比例组装；H1 另按每任务 `1-2Z` 规范化方向，二者的定义分别保留。

按操作家族读取 TSG 的方向规范化状态效果如下。每家族均包含 100 项任务，计算为该家族各任务 `(1-2Z_j) × (A_j.mean-B.mean)` 的均值。这些家族和状态表仅描述已执行结果，未增加确认性比较、区间或 context-modifier 推断。

| 操作家族 | local | example | reference |
| --- | ---: | ---: | ---: |
| find | 0.0125 | 0.0375 | -0.02 |
| git | 0.01 | -0.0075 | 0.0025 |
| grep | 0.0075 | 0.0175 | -0.0075 |
| tar | -0.185 | -0.0575 | -0.01 |

| TSG 政策／初始状态 | 任务数 | B 安全产出均值 | 原状态翻转后的安全产出均值 |
| --- | ---: | ---: | ---: |
| local / 0 | 298 | 0.75251677852349 | 0.7088926174496645 |
| local / 1 | 102 | 0.7205882352941176 | 0.7450980392156863 |
| example / 0 | 115 | 0.7369565217391304 | 0.7260869565217392 |
| example / 1 | 285 | 0.7473684210526316 | 0.7464912280701754 |
| reference / 0 | 291 | 0.7207903780068728 | 0.7087628865979382 |
| reference / 1 | 109 | 0.8073394495412844 | 0.8073394495412844 |

状态表按 `cases.json.initial_states[j]` 分组，分别平均对应 TSG 的 B 与政策条件均值，包含映射 B 的位置。全部 400 项任务的逐流程、逐条件、逐表达、请求身份、安全标签、有限功能及未知原因见[完整任务结果](../../results/controlled-semantic-20260930/report/cases.json)。版本差异与家族差异均保留为诊断；当前证据不足以将差异归因于某一代码机制或任意措辞的稳健性。

## 实际资源与预算

费用字段来自已独立复算的 [cost.json](../../results/controlled-semantic-20260930/report/cost.json)，计入开发、发现、评价、所有启动与停止以及实际准备实例。

| 模型生成阶段 | 实际尝试 | 完整已知 token |
| --- | ---: | ---: |
| 开发 | 30 | 22948 |
| 发现 | 7890 | 5264035 |
| 独立评价 | 9216 | 6138831 |
| 自然验证 | 0 | 0 |
| 合计 | 17136 | 11425814 |

模型服务实际累计 139431.94617359526 秒，即约 38.7311 小时，低于 120 小时上限；结构计算为 84.8225 CPU 秒，低于 8 小时上限；生成尝试为 17136，低于 28510 上限。授权开始至最终模型服务停止为 400225.764657 秒，约 111.1738 小时，早于 2026-10-14 15:41:27 UTC 截止时间；该字段不包含随后报告与验证的运行时间。四项预算核验均通过。

准备实际包含 3233 项实例、3235 次调用，其中协议实例 3212、额外自然工作实例 21。取得计量的实例为 3229，缺失计量的四项实例保留未知。已知输入 token 为 598171344，输出 token 为 18291944，reasoning token 为 2061052；reasoning 字段单独报告，不与输出重复相加。`preparation_complete_total_tokens=null`，完整准备 token 与据此计算的资源效率均保持未知。准备配置保留实际 `gpt-6-astra/high` 与 `gpt-6.1-sol/high` 身份，没有将此前实际调用重标为当前 E 配置。

发现执行依据事前资源修订使用单请求／0.48 与四请求／0.50 配置，评价使用四请求／0.50，测量均独立串行。各服务的实际配置、时间与停止身份保存于 `service-*`，全部计入服务成本。原模型、消息、分配、采样与测量规则保持冻结定义；批处理资源差异限制逐字节重放解释。AgentResearch 的 18585 服务保持运行。

## 冻结依据与结果复核

| 科学结果 | 冻结输入与配置 | 实现与结果字段 | 表格读取依据 |
| --- | --- | --- | --- |
| 800 项任务、模板与状态 | experiment-qualified-inputs/tasks.json、generator/template-split.json | controlled_tasks.blueprint_identity、candidate_catalog；measurement.blueprint、initial_states | 按 role/family 分组，模板按 family/primary_query/comparison_query 去重 |
| 准备通过、失败与未知 | 原隔离准备及检查，experiment-qualified-inputs/tasks.json | controlled_tasks.assemble_main_semantics；policies[flow][j].review.status、semantic_qualified、execution_mapping | 按 role/flow/status 分组，固定每任务三个位置 |
| D 实际状态和测量诊断 | training/summary/results.json、原 assigned/result/measurement | source_generation.run_jci；status、security_label、secure_yield、code_valid、oracle_support、functionality | 按全部物理分配计数，unknown 与失败分别保留 |
| D 三项效果及评分 | 冻结 D、全部实际 D 结果、两套表达等权 | jci_ridge.analyze_controlled_training；canonical-effects.json、selection.json | 读取共同效果、全部评分、冻结动作与方向 |
| PAG 端点与结构支持 | mixture-rows.json、冻结子样本、CI 配置、pcalg 2.7.12 | PromptFCI、DiscreteCI；structure-summary.json 的 searches、supports、undetermined_counts | 完整图读取 edges，子样本支持固定除以 100 |
| Ridge 验证 | training-features.json、training-effects.json、固定五折 | graph_guided_decisions.TaskEqualRidge；cross-validation.json、learner.json | 读取各 penalty/mse 与最终 penalty |
| E 比较及固定精度 | evaluation-decisions/comparisons.json、selector-coefficients.json、全部 E 请求与八份恢复观察 | jci_ridge.freeze_controlled_evaluation、report_controlled_evaluation；report/comparisons.json 的 estimate、interval、halfwidth、completion_bounds、status | 读取 H1–H12，保留十二项原位置与自然未执行原因 |
| 留出选择价值与 Ridge 辅助结果 | 原冻结选择、方向、预测及 E 实际结果 | jci_ridge.report_controlled_evaluation；selector-values.json 的 estimate、interval、interpretation | 读取 RD、F、J、Permutation、Ridge，分别保留方向加权价值与状态效果 |
| E 标签、版本、家族及初始状态诊断 | 全部 E 分配、measurement 与 measurement-recovery | jci_ridge.report_controlled_evaluation；observations.json、cases.json 的 family、initial_states、conditions、versions | 全部物理请求计数；逐条件与版本平均；按 family 与 initial_states 分组 |
| 实际成本及预算 | preparation-attempts.json、全部 services 和 stopped、各阶段原 usage、结构摘要 | jci_ridge.report_controlled_evaluation；cost.json 的 model_usage、preparation_*、model_service_seconds、structure_cpu_seconds、budget_checks | 汇总全部实际调用及停止服务，保留四项准备计量未知 |
| 自然未执行 | natural-preparation、逐来源资格及独立检查、natural-plan.json | freeze_controlled_natural_preparation、冻结自然提名；status、reason、policy_sets | 全部 419 项处置、空政策集合与 H12 原位置 |

主输入 manifest SHA-256 为 `8522d8592100e5f62b17b38edd94fa0b052b4dfc8f4b46b32f18f72a281d6439`；发现分析为 `0c4b3f132d6566b45058b4a0160ecc276908c3df61883cf85141a361ff131bf1`；评价前决策为 `9fbd32a94ae8f5fbac97eea828386233d55447eda067bd88d934b0b855c42f84`。发现分析捕获的 jci_ridge 实现为 `f0d25ee060d5634f4be6badefc6ff17ef08013117ef96b3db1ff6179a0717ced`，R worker 为 `e2a12651a54590e961770cecc55d1e53ea06be90180144290880d9e7bcaf014b`，Ridge 为 `6e9d3e827f6b5bd6cdbd6768e856517fcd979b172665a0827a8ee80c0a79ca51`。

[完整发现独立验证](../../results/controlled-semantic-20260930/discovery-verification/verification.json)覆盖 1600 个准备位置、800 项任务分配、7890 条实际 D 请求、1200 项训练政策效果、202 次图搜索和 6784 条 CI 查询，并保存 `evaluation_outcomes_read=false`。[接续前独立复核](../../results/controlled-semantic-20260930/evaluation-recovery-input-verification/verification.json)使用当前独立验证器再次确认相同输入、发现分析和评价决策。

[完整报告独立验证](../../results/controlled-semantic-20260930/verification/verification.json)状态为 `PASSED_CONTROLLED_MAIN_REPORT`。验证从原来源、完整传输和实际测量记录复算，覆盖全部 7890 条 D 与 9216 条 E 请求、八份恢复观察、202 次结构搜索、6784 条 CI 查询、固定五折 Ridge、十二项比较、400 项完整任务结果及全部成本；同时核对自然输入与未执行报告。`natural_inference_verified=false` 对应事前空自然集合，未报告自然推断。

完整报告 manifest SHA-256 为 `51660f3b36c36b518c0d141d1eda66939a807c27fd514724987c37ebad70c1da`，生成报告的 jci_ridge 实现为 `9b6d6bedf03af2c0a5c91cebe8554ec77b41c47c2c7a41be59a8d9a99ffbd742`；独立验证 manifest 为 `59634557185f3258957a463d57b5baa658dd1228735250059e9da976e8211148`，独立验证器为 `fa0be834d803d96a2027d1684d8889dd423e866e0a1ce8809417507f152c7408`。新输出目录的复现与独立复算命令见[执行记录的审阅入口](2026-09-30-controlled-semantic-execution.md#审阅入口)。本受控研究的适用步骤、报告及复核已经完成；自然迁移、完整功能、任务总体外推和未激活的 context-modifier 推断保持各自的证据边界。
