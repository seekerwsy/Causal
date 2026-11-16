# 自然来源属性比较结果

## 执行状态与主要指标

本轮已完成48个新公开问题、16个上下文组、每个问题三个固定查询的全部比较。来源参考有130/144个已知位置，14个未知位置对两种方法均记零。两种方法的288个位置及全部32份首次匿名评审已经固定，独立核验状态为 `VERIFIED`，核验范围为 `full_results`。研究定义见[固定设计](2026-11-01-tsg-source-attribute-design.md)，来源覆盖见[参考结果](2026-11-01-tsg-source-attribute-reference-results.md)。

| 主要指标 | Graph | 强平面表示 | Graph减去平面表示 | 双侧精确概率 | 预定收益成立 |
| --- | --- | --- | --- | --- | --- |
| 来源作用准确率 | 119/144，82.64% | 127/144，88.19% | −5.56个百分点 | 0.5 | 否 |
| 完整命题绑定 | 94/144，65.28% | 126/144，87.50% | −22.22个百分点 | 0.0009765625 | 否 |

来源作用准确率要求参考已知、实际表示和引文有效、消费者输出状态与参考一致。完整命题绑定进一步要求绑定有效，且两位匿名评审对命题身份、操作、对象、条件、范围五项全部判定通过。两项主要指标分别要求改善至少10个百分点且双侧精确概率不超过0.025，并需同时成立。本轮 `registered_gain=false`，没有建立 TSG 独立收益。完整绑定的不利差异通过了预定概率阈值。

分母保持144个查询；每个根任务的三个查询共同计分，16个三任务上下文组共同交换方法标签。核验器枚举全部65536种交换。统计解释依赖固定任务、上下文分组和方法执行位置可交换的条件，不提供新的自然任务总体保证。

## 失败位置与信息空间

下表为首次主要评分之后的互斥失败分解，不改变原始指标或收益判定。

| 首先未满足的条件 | Graph | 强平面表示 |
| --- | --- | --- |
| 来源参考未知 | 14 | 14 |
| 已知参考，但表示无效 | 10 | 0 |
| 表示有效，但作用状态不一致 | 1 | 3 |
| 作用正确且绑定可用，但双评审未共同通过 | 25 | 1 |
| 完整命题绑定成功 | 94 | 126 |
| 固定位置总数 | 144 | 144 |

Graph 共有12个位置属于无效表示，其中两个同时属于参考未知：第09组的九个位置在 `unresolved_semantics` 中填入了目录之外的自由文字；第14组一个任务的三个位置存在逐字引文不一致。原始表示和查询图保持原值，相关位置继续留在分母中。

在25个作用判断正确、绑定形式可用、语义评审未共同通过的 Graph 位置中，操作项有20个未共同通过，条件项有八个，对象项有两个，范围项有一个。同一位置可以涉及多个项目。相应平面位置有一个，其操作和条件项目均未共同通过。上述互斥分解中的测量引文失败、评审引文失败和原生绑定可用性失败均为零。

实际记录显示了不同的角色绑定问题：

- `attribute-00-08`，`matplotlib__matplotlib-22719`：完整命题保留了两个可选分支，操作投影没有完整表达继续产生无数据 artists 的分支。
- `attribute-00-16`，`astropy__astropy-13977`：完整命题和范围保留返回 `NotImplemented` 并避免 `ValueError` 的约束；操作字段只投影方法名称和通用调用行为，两位评审均认为该字段的完整操作证据不足。
- `attribute-01-00`，`django__django-13964`：操作字段指向事务提交，原命题涉及延迟的外键存在性检查；提交是检查的时间界限。
- `attribute-02-06`，`matplotlib__matplotlib-24870`：默认参数下的命题绑定到了显式 `levels=[.5]` 的调用引文，两位评审在该操作证据是否充分上发生分歧，位置保留未通过状态。

这些记录支持修订 Graph 对完整命题及其操作、条件和替代分支的关系消费。操作节点的通用名称、完整命题中的谓词约束和对应调用实例需要共同保留。作用判断正确的位置仍然可能出现公开绑定错误。

在本轮固定参考和评分规则下，即便某个 Graph 方法使全部130个已知位置成功，相对当前平面结果的最大改善也只有来源作用3/144，即2.08个百分点，以及完整绑定4/144，即2.78个百分点。这个上界已经低于10个百分点的预定门槛。因此，在同一批固定任务上重复评审或修正接口，无法建立本轮要求的表示增量。该边界条件于本轮来源和查询范围。

## 实现修订与证据边界

数据、语义指令、执行顺序、比较预算、指标、分母及阈值在方法输出之前固定。方法执行期间、查看任务级参考答案和匿名语义评分之前，记录了两次失败计数实现修订：[概念标识失败计数](../../data/method/tsg-source-attribute-20261101/failure-accounting.json)与[逐字引文失败计数](../../data/method/tsg-source-attribute-20261101/failure-accounting-literal.json)。修订将已经无效的实际表示记为失败，没有修正模型原始提交、增加语义反馈、重交消费者或替换任务。原始实现保存在 `measurement-sources.zip`，修订身份与结果共同核验。

实际记录的15项检查通过，包括已有十二组测量投影的一致性，以及 Graph 与平面真实提交的逐字引文失败。评审前冻结包在隔离解包目录中复现了第09组与第14组的独立机械核验。补齐来源身份所需的排除名单等输入后，使用相同已安装依赖环境完整复算评分，结果文件 SHA256 与冻结原件完全一致；全部288个位置的独立核验也通过。这些检查支持失败计数和材料复现；语义准确率由本轮来源参考与匿名评审共同定义。

提取、查询消费、参考判断和匿名评审使用隔离上下文，仍共享模型来源；`independent_human_gold=false`。精确后端模型构建身份和实际 token 用量保持未知，Graph 的额外确定性计算单独保留。证据覆盖提示属性测量，代码生成调用为零，`formal_claim_allowed=false`。真实安全、功能性、策略价值和 JCI 上下文资格需要对应实验。

## 复现材料与结果映射

完整材料为[冻结归档](../../results/tsg-source-attribute-20261101-complete-frozen.tar.gz)，校验值保存在同名 `.sha256` 文件。评审前归档为 `tsg-source-attribute-20261101-before-review.tar.gz`，其 SHA256 为 `85ea0bed2a4739390e0cedfc5b6d883dc468239823f0d5cd1abdc5c0962f5772`。

完整归档同时包含 `identity.json.hashes` 指定的输入：既有24个公开问题的排除材料、两个资格选择文件的任务标识元数据，以及固定配置与设计。资格选择文件仅含身份和预留状态，不包含受保护任务正文或结果，不赋予新的正式数据角色。

在冻结归档解包后的项目目录中，使用记录的 Python 3.12.14 环境与 NumPy 2.5.1，可直接执行独立核验：

```text
python data/method/tsg-source-attribute-20261101/verify.py --output NEW_VERIFICATION.json
```

主要结果已固定。复算生产评分时应在项目副本中将现有 `result.json` 保存至副本的归档目录，再执行以下命令；冻结原件保持原值。

```text
python data/method/tsg-source-attribute-20261101/measurement.py evaluate
python .test-tmp/analyze_attribute_comparison_20261101.py
```

失败分解同样使用排他输出；复算时将已有 `failure-decomposition.json` 保存至副本归档目录。生产评分需要归档中的原生组件及项目安装环境；独立核验不导入生产评分或 Graph 组件。

| 报告内容 | 实现与结果字段 |
| --- | --- |
| 主要指标表 | `measurement.py:evaluate`、`paired_summary` → `result.json.summaries.source_force_accuracy` 与 `.complete_proposition_binding` |
| 固定位置计分 | `result.json.rows`；独立 `verify.py:verify_group` 复算原始图、状态、实际绑定和匿名判断 |
| 精确检验与收益判定 | `paired_summary`；独立 `verify.py` 的完整枚举；`result.json.registered_gain` |
| 互斥失败表及上界 | `.test-tmp/analyze_attribute_comparison_20261101.py` → `failure-decomposition.json.methods` 与 `.maximum_graph_minus_flat_if_all_known_positions_succeed` |
| 具体语义例子 | 对应 `private-NN.json` 的实际投影，以及首次 `review-a-NN.json`、`review-b-NN.json` 的同名 label |

关键身份：

- `measurement-plan.json`：`b6926448ca242b3c3a3e22d263a6d6df6a96e014c910758431a755590e9f1e4d`。
- `result.json`：`af4d0e586c70d62f65f2550be0943b9f8724f3d034ec695f1e81717cda9cd3bd`。
- `verification.json`：`491c6b642ed8d826c462af7e64dd22d36c33c54a5baa87e77e159a6eb320e98b`。
- `failure-decomposition.json`：`acc0bca13a2fc06fe03a8122d893a4d8a53f77051bc22f9c956a6b1c9149ec7d`。
