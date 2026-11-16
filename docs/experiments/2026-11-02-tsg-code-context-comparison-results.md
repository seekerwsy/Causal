# 原始代码上下文表示诊断结果

## 已执行范围

按照[固定设计](2026-11-02-tsg-code-context-comparison-design.md)，使用 `pydata__xarray-7229` 的同一完整问题说明和三个原始代码文件，两个隔离上下文分别生成实际Graph和平面表示。两种方法各完成一次机械检查，均通过；最终记录与各自草稿摘要相同，检查错误输出为空。方法上下文没有取得冻结参考、另一方法或评分。

Graph已通过现有原生编译器及完整来源读出，包含50个实际来源节点。两份新的隔离测量依据相同来源、方法输出前固定的参考与统一指令分别判定，没有读取彼此结果。隐藏名称不能隐藏表示形式，本次不声称完全盲法或人工参考。

固定计划SHA256为 `430a0f5225523995e70d06944ba1936b11e71ccd868ec0ee61bfb05b43134c04`；实际测量资料为 `8c3df9c424a94692232e30a531add96dda5c2711d43c53ef59c13a3e98eb3467`。原始来源参考及旧研究分母、结果和归档均保持原值。

## 事前固定的语义判定

| 固定测量项目 | Graph两份评价 | 平面两份评价 |
| --- | --- | --- |
| 公开入口、实现与参数角色 | complete／complete | complete／complete |
| 要求对象、属性所有者及保留范围 | complete／complete | complete／complete |
| 当前属性来源及生效条件 | complete／complete | complete／complete |
| 有条件的静态调用及坐标属性路径 | complete／complete | complete／complete |

两种方法均为4／4项共同确认成功，逐项分歧为零。两份评价都能在实际记录中定位相应含义；没有用参考替方法补充缺失信息。结果是一个自然任务上的语义完整性相同，尚无Graph增量。四项不能当作四个独立任务，本次没有显著性检验或总体收益结论。

Graph规范记录长度为29525字符，平面为25923字符，均低于共同40000字符上限。长度是本次实际表示成本，不推断一般计算效率或阅读成本。完整机器读出包含额外来源身份与结构元数据，记录长度不能直接替代最终测量输入的长度。

## 原生结构读出的额外诊断

原始Graph读出中，八个要求类型命题的 `binding_complete` 均为false。坐标保留命题 `req.coordinates` 的自然语言含义明确写出坐标属性与数据变量属性的不同所有者，也有 `about_operation` 和 `has_subject` 关系；其来源属性明确声明 `binding_complete=false`。因此，事前语义项目中的完整判定不能解释为原生结构已经支持自动操作。

该命题的主体为示例time坐标，操作为where。现有 `source_proposition_measurement` 要求绑定主体直接通过 `used_by` 或 `produces` 与操作相连。time属于结果内部的坐标，现有图没有通过这些直接输入／输出关系把它连接到where。不能未经证据将time改写成where的直接参数。实际表示还没有完整表达一般坐标集合、具体示例坐标及返回对象之间的归属关系，命题范围也未形成原生scope记录。

这项事后结构检查说明：补足源代码可以支持语义理解，原生Graph的对象归属及可操作绑定仍需明确设计。后续调整需要分别保留操作实参、结果对象的组成部分与要求谓词的对象，验证来源支持的归属路径，再检验其是否改善属性测量或干预。不能通过将完成标记直接改为true、把所有引用关系解释为归属关系或重评分本轮结果建立收益。

原生结构诊断没有改变上述四项冻结评分，未新增科学重复，也不证明新增边类型将带来收益。当前仍缺少Graph相对强平面的独立收益及下游安全结果证据。

## 独立核对与复现

生产脚本为 `data/method/tsg-code-context-20261102/comparison.py`。`verify_comparison.py`独立读取原始记录，核对共同完整来源、固定摘要、50项原生节点证据及含义、原始关系、原生输入输出与命题角色、两份测量计数和分歧。它不调用生产计分或Graph编译函数，结果为 `VERIFIED_CODE_CONTEXT_COMPARISON_ACCOUNTING`；它不认证语义真值。

在保留首次实际表示与两份评价的独立副本中，保存原生成输出，然后依次运行：

```text
python data/method/tsg-code-context-20261102/comparison.py prepare
python data/method/tsg-code-context-20261102/comparison.py evaluation
python data/method/tsg-code-context-20261102/comparison.py result
python data/method/tsg-code-context-20261102/verify_comparison.py
```

该流程复算机械转换与固定评价，不重新调用评审。没有执行原始库、生成候选代码或运行安全及功能测试；完整功能性、下游收益与正式声明资格均为false。当前默认方法及JCI预算曲线的冻结配置保持原值。

冻结材料为 `results/tsg-code-context-comparison-20261102-frozen.tar.gz`，大小302341字节，SHA256为 `e578a572a137f0b003d8c4dae135c169ed2425e1abe4c26c2b2a4f41d1f73f36`。在 `.test-tmp/tsg-code-context-comparison-replay-20261102`独立解压，使用包内六份公共源码及原项目Python环境重跑四个阶段，共同输入、计划、编译图、测量资料、名称映射、结果和独立核对七份输出均与原件逐字节相同。没有重新制作表示或调用评审。本段记录归档之后完成的复算，冻结归档保持原值。
