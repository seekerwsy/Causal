# 来源调用位置与对象状态的核查结果

## 完整来源与独立核对

按照[固定设计](2026-11-02-source-call-audit-design.md)，实际解析三个已暴露自然来源任务的14份Python程序，以及两份已取得的Kedro实际API源码，共16份文件。没有取得新任务，没有读取正在生成的Codecov候选，也没有调用模型或执行来源程序。

使用LibCST1.9.0的只读visitor及位置、父节点、表达式上下文、作用域、可能限定名称元数据；没有使用transformer或写出程序修改。实际提取1168项操作、360项赋值及3713项LOAD语法位置。独立Python AST逐项核对全部1528项操作和赋值的种类、字节范围及逐字内容，另外核对全部嵌套来源锚点、文件摘要和语法包含引用。状态为 `VERIFIED_SOURCE_CALL_SYNTAX_CATALOG`。

解析与元数据用途依照已完整阅读的[LibCST元数据说明](https://libcst.readthedocs.io/en/latest/metadata.html)和[只读访问说明](https://libcst.readthedocs.io/en/latest/tutorial.html)。scope和possible qualified names提供静态候选；Attribute目标不由该作用域分析解析。2272项LOAD位置有词法access记录，1036项为未解析的Attribute目标，403项没有scope元数据，另有两项没有access记录。它们各自保留明确状态，不被转换为运行时定义。

## 来源状态分歧的实际位置

Codecov原始模块中的四项具体调用具有不同位置和独立身份：

| 来源行号 | 实际调用 | 来源作用 |
| ---: | --- | --- |
| 555 | quote(root) | 项目目录值的引用处理 |
| 592 | opj(root, yaml_location) | YAML文件位置 |
| 647 | opj(root, '.bowerrc') | 配置文件位置 |
| 658 | os.walk(root) | 报告目录遍历 |

文件清单准备中第572、574行的root访问及第627行gcov目录选择也具有分别可核对的位置。原有Graph的op.collect同时连接处理前后的root对象，YAML和.bowerrc等消费者未分别绑定；强平面记录明确保留这些消费者。当前独立评审分歧继续保留，本检查不改变其评分。

Codecov十项root读取均有八个库返回的词法赋值候选。候选数量直接说明：单凭同名变量和词法候选，不能确定某次调用实际消费的处理状态。新工具没有选择最后文本赋值作为答案，所有runtime_definition_established均为false。跨分支状态与具体消费语义仍需来源判断。

Kedro实际shelve源码中，第114行的Unpickler(f).load()属于Shelf.__getitem__，其位置与其他类中同名恢复调用保持分开。该定位可以帮助核查“普通读取已经恢复对象”的API背景，但不建立跨模块实际调用路径、任意pickle安全性或生成实现正确性。

## 后续方法约束

后续Graph制作需要将具体调用位置附着到其操作实例，区分原始对象、处理结果和实际消费者；过程级节点继续保留总体要求，具体调用分别提供来源支持。已存在的对象、操作、产生、使用和条件关系能够承载这些内容；机械位置资料为绑定提供可核对锚点，完整语义仍由独立来源评价判断。

位置资料如进入下一轮表示制作，Graph与强平面应获得相同资料和原始代码，允许相同推理工具，制作和查询预算在输出前固定。语法位置提取正确不计为Graph组件收益。当前Codecov16项生成继续使用其冻结输入，不取得本次新增资料。

## 实现与证据身份

共用只读实现为 `src/tsg/source_calls.py`；输入与全量提取入口为 `data/method/source-call-audit-20261102/run.py`，独立核对为同目录 `verify.py`。catalog.json摘要为 `49147b7f95433ad7df7a5cdc991d764ebd9f04ab6eb5e114a55195512a5fbebb`；核对摘要为 `14e1caf1f2165750b5d3dee5faa4df5c94875cccee1af2e5124888a457319278`。输入清单、版本和实现摘要随结果保存。

该检查使用开发暴露资料，只认证指定来源的语法记录一致性，生成调用与新增科学重复均为零。运行数据流、要求蕴含、因果结构、自动绑定增量、代码收益及正式资格均未建立。

完整冻结资料为 `results/source-call-audit-20261102-frozen.tar.gz`，952987字节，摘要 `0ae91e9d444e6fccdef454d02abbe2327a27da571566fac33d082faa7158cc2e`，本地与服务器归档一致。在 `.test-tmp/source-call-audit-20261102-replay`独立解压，使用包内实现和输入重新提取16份来源，再执行独立核对，catalog与verification的摘要分别复现 `49147b7f95433ad7df7a5cdc991d764ebd9f04ab6eb5e114a55195512a5fbebb`和 `14e1caf1f2165750b5d3dee5faa4df5c94875cccee1af2e5124888a457319278`。重放没有新来源、模型调用或独立实验样本。
