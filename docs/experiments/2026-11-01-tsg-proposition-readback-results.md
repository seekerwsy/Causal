# 完整命题读出的开发结果

## 实现与机械核对

`src/tsg/prompt_tsg.py:source_proposition_readback` 已实现并执行。它保持原有 `source_proposition_measurement` 的状态解码，逐条保留完整命题与角色端点，读取所属表达式、操作实例、要求级条件、直接约束目标、保留范围、要求拥有的关系及来源指代上下文。未选中上下文不并入所选命题的作用状态；未声明结构保持 `undeclared`，空字段不证明来源不存在相应要求。

输入为此前48任务研究的冻结实际 Graph。[机械检查设计](2026-11-01-tsg-proposition-readback-design.md)与实现入口 `data/method/tsg-proposition-readback-20261101/check.py` 固定了核对范围。独立核对使用原始 JSON 的关系与 NetworkX 的可达性，不复用生产读出的遍历。

| 实际检查 | 结果 |
| --- | --- |
| 固定 Graph 查询位置 | 144个全部保留 |
| 原有有效位置的状态和汇总字段 | 132个与冻结测量完全一致 |
| 原有无效位置 | 十二个保持原身份与失败状态 |
| 完整任务图核对 | 44张通过 |
| 要求级原生条件 | 十四个完整保留 |
| 直接约束端点 | 四十五个完整保留 |
| 指代及对照等来源关系 | 七条完整保留 |

44张图中共核对170个命题记录：38个声明为 atom、45个为 opaque、各一个 AND 与 OR，85个未声明组合结构。本轮没有原生 NOT 正例，不报告其经验表现。读出验证的是已经形成的关系、归属和来源锚点；`source_entailment_verified=false`，不认证提取语义。

## 已暴露案例的匿名语义检查

[语义检查设计](2026-11-01-tsg-readback-semantic-probe-design.md)在新评审之前固定四个已知案例，并按固定哈希规则选择两个保持原表现的对照。六个查询均已暴露，新增任务数为零。每个查询呈现实际新读出及原始平面绑定，共十二个匿名位置；两位新上下文评审分别提交一次完整判断。

| 原 Graph 位置 | 检查内容 | 新 Graph 读出 | 原始平面绑定 |
| --- | --- | --- | --- |
| attribute-00-08 | 无数据 artists 与问题说明的 OR 要求 | 两位均通过 | 两位均通过 |
| attribute-00-16 | 返回 NotImplemented 且避免 ValueError | 两位均通过 | 两位均通过 |
| attribute-01-00 | 外键检查与事务提交的归属 | 两位均通过 | 两位均通过 |
| attribute-02-06 | 默认调用与显式 levels=[.5] 实例 | 未共同通过 | 两位均通过 |
| attribute-04-14 | 固定保持原表现的对照 | 两位均通过 | 两位均通过 |
| attribute-08-11 | 固定保持原表现的对照 | 两位均通过 | 两位均通过 |

本轮 Graph 为5/6，平面为6/6。预定解释检查要求前两个案例通过、原定两个错误归属案例继续未通过，以及两个对照的两种表示均通过。Django 案例被新评审共同接受，因此 `interpretation_check_passed=false`。没有独立收益成立。

新评审对 Django 的解释为：完整命题提供外键约束延迟至提交的谓词，事务提交操作及其输入约束共同表达相同事务。旧评审将提交视为检查的时间界限，要求直接绑定检查动作。操作端点及其引文没有被程序修改，两轮采用的操作粒度与完整关系解释出现差异。这说明该案例不能继续充当稳定的错误归属参照；也不能把新判断解释为源图已被修正。

显式 `levels=[.5]` 与默认调用的实例冲突仍被两位评审共同识别。OR 分支和返回值约束在新的完整关系读出中均被接受。它们支持完整谓词与关联角色共同表达要求，同时要求来源测量明确区分操作概念、具体调用实例和执行时间边界。

## 解释范围

此前48任务研究按角色投影及其证据评价；本轮开发检查依据事前固定的新指令，阅读完整的关联谓词与角色记录。两轮不能合并评分，不能将本轮5/6用于替换旧主要结果。原48任务仍为 Graph 119/144来源作用、94/144完整绑定，平面127/144与126/144；原始分母、概率检验、阈值和不利结论保持冻结。

案例选择发生在旧结果已知之后，包含特定失败与保持原表现的对照；六个查询不构成新独立样本。两位评审共享模型来源，表示格式可能透露形式。当前证据支持机械读出完整性和特定案例的可解释性，未建立自然任务总体收益、自动提取准确率或下游效果增量。代码生成调用为零，正式协议保持未激活。

操作粒度及时间边界的共同定义、独立来源角色判断，以及新任务上的完整绑定和下游验证仍未完成。预定解释检查的未通过结果保留，当前结果不支持扩大独立收益声明。

## 材料与复现

冻结材料为 `results/tsg-proposition-readback-20261101-frozen.tar.gz`，校验值保存在同名 `.sha256` 文件。它保存本轮源代码、匿名材料、两份首次评审及结果，并携带此前48任务归档和对应输入。此前完整归档的SHA256保持为 `7807e0d2fa8b1447a4e97a91324eae96d04622de02fff869a7c58ad26b727a43`。

使用匹配的项目安装环境、Python 3.12.14与NetworkX 3.7，在项目副本中将本轮已有 `result.json` 和 `probe-result.json` 保存至副本的归档目录后，执行：

```text
python data/method/tsg-proposition-readback-20261101/check.py
python data/method/tsg-proposition-readback-20261101/probe.py evaluate
```

保留已有 `probe-blind.json`、`probe-private.json` 和两份评审，评分复算无需重新调用评审模型。机械结果来自 `check.py:verify_readback`，字段为 `result.json.position_status_counts`、`.full_graph_composition_counts`、`.native_relation_coverage`。语义结果来自 `probe.py:evaluate`，字段为 `probe-result.json.rows` 和 `.interpretation_check_passed`。判断理由保存在两份 `probe-review-*.json` 中。

关键身份：

- 原生 Graph 实现：`d7a72f655e9ad5dbda25dad43506832e59f5545120108498062d9aa56fa7d757`。
- 机械检查：`941e4691555552f46fb366004dac2b9ccca7790234051cdbf449a7327dc32862`。
- 机械结果：`5d3aef48d30c9ec787637886eec85b3cb75c387b498c7158cc43fac31478d2ba`。
- 语义检查实现：`d4fc5b8b5443d91129e374aac9589c197dc699661deb90039d14fca96f650ebf`。
- 语义结果：`8b158618eed32ce24dc7b69b18f466bebf2d78d0a209692c70ac337334785bcc`。
