# 完整要求清单的来源资格结果

## 自然来源与实际范围

按[固定设计](2026-11-01-tsg-complete-inventory-design.md)完成一轮自然来源获取和三份独立上下文判断。既有48任务排除上轮六目标后，只有一个达到5000字符，覆盖不足记录保留。本轮从相同固定公开 Parquet 的允许来源字段取得六个新根任务；此前24个和48个任务的近重复分量均排除。

| 新自然任务 | 仓库 | 原文字符数 |
| --- | --- | ---: |
| pytest-10356 | pytest-dev/pytest | 5278 |
| scikit-learn-13135 | scikit-learn/scikit-learn | 5280 |
| sphinx-11510 | sphinx-doc/sphinx | 5362 |
| astropy-13398 | astropy/astropy | 5323 |
| django-13449 | django/django | 6278 |
| scikit-learn-14710 | scikit-learn/scikit-learn | 6629 |

五个仓库满足至少三个仓库、每仓库最多两个任务的规则。独立来源核对使用稀疏矩阵乘法和 SciPy 连通分量重建选择，与生产选择逐项一致。未读取补丁、测试、提示评论、难度、受保护正文或评价标签。模型训练中的既有暴露未知；字符近重复整理不证明语义或统计上的完全独立。

## 全部参考结果

两位来源判断者各自仅读取完整原文和共同定义，分别建立全部明确任务要求、条件、直接规范重述、未确定事项及排除的报告流程。第三位读取原文和匿名配对清单，独立检查双方来源支持、完整性、绑定和联合含义。全部首次输出及六个任务保留。

| 任务 | 两份明确要求数量 | 两份未确定事项数量 | 第三位全部条件通过 | 严格完整参考资格 |
| --- | ---: | ---: | --- | --- |
| pytest-10356 | 6／6 | 1／1 | 通过 | 未通过 |
| scikit-learn-13135 | 1／1 | 0／0 | 通过 | 通过 |
| sphinx-11510 | 1／1 | 0／0 | 通过 | 通过 |
| astropy-13398 | 5／5 | 2／1 | 未确定 | 未通过 |
| django-13449 | 1／1 | 0／0 | 通过 | 通过 |
| scikit-learn-14710 | 2／2 | 1／1 | 通过 | 未通过 |

严格资格为3/6，未达到预定5/6门槛。程序状态为 `COMPLETE_INVENTORY_REFERENCE_COVERAGE_INSUFFICIENT`，`method_comparison_allowed=false`。本轮没有启动 Graph/Flat 清单比较，不提供新的表示成绩。

pytest 的不确定事项为可选去重；scikit-learn-14710 保留编码方向的不确定性。两份清单对各自已知要求及未确定内容一致，第三位全部条件通过；预定零未确定事项规则仍将两个任务排除。astropy 对变换注册类型是否具有强制性存在未解决差异，一份清单记录了该不确定事项，另一份没有完整记录其规范地位。该任务的完整性及联合含义保持未知。

## 方法含义

本次数据中，严格资格只保留了各有一项明确要求的三个任务；条目较多的三个任务均未取得资格。长原文不保证具有更多确定要求，排除所有未确定事项还可能使比较范围偏向简单任务。该观察限定于这六个任务，不能解释为自然任务总体规律或 Graph 优势。

后续方法需要把明确要求与来源不确定事项分别保存，并验证不确定性的忠实保留。某项可选实现或条件未确定时，不能自动推断为没有该要求，也不能自动否定其他明确要求的可识别范围。相关研究需要另行前瞻设计与验证；本轮严格3/6、门槛及禁止启动比较的结果保持冻结，不改判为5/6或6/6。

完整显式要求清单不等同于完整程序功能规格。该研究尚未测量软件安全、功能性、JCI 真实任务效果或策略价值。三位判断者共享模型来源，不称人工真值。没有模型主体代码生成、服务支出、正式角色或默认方法切换。

## 已实现和测试的 Graph 读取机制

`prompt_contract.py:compile_source_propositions` 将来源命题记录编译为既有规范 Graph，严格检查逐字引用并保留来源角色与逻辑结构。`prompt_tsg.py:source_requirement_inventory` 选择显式规范作用且独立受到断言、没有规范祖先的完整表达式；OR、NOT 成员不独立进入清单，缺失规范作用的候选保持未知。来源覆盖及语义认证标记始终为 false。

`.test-tmp/test_complete_inventory_readback.py` 的十七组实际数据检查通过：十六组在44张实际有效图上逐项重现原编译结果，并以原始关系和 NetworkX 独立核对清单根；另一组检查18张未标规范作用的旧图全部保持未知，节点类型没有被推断为规范证据。测试没有虚假任务或替代节点。这些检查不建立新的自动提取准确率。

## 结果与复现

材料位于 `data/method/tsg-proposition-readback-20261101`。入口 `check_inventory_reference.py` 固定来源与实现、准备匿名配对材料并计算资格。主要输出为 `inventory-reference-result.json.rows`、`.qualified_tasks`、`.method_comparison_allowed`。逐任务理由保存在 `inventory-agreement.json`。

`verify_inventory_reference.ps1` 独立读取原始 JSON 和原文引文，重算全部资格、三项通过数、五项判断一致数及比较门槛；未导入生产 Python 评分。结果状态为 `VERIFIED_COMPLETE_INVENTORY_REFERENCE`。来源获取另经 `.test-tmp/verify_inventory_acquisition.py` 独立核对，记录为 `inventory-acquisition-verification.json`。

冻结材料为 `results/tsg-complete-inventory-reference-20261101-frozen.tar.gz`，同名 `.sha256` 保存校验值。归档只保存允许的来源字段，不携带包含答案列的原始 Parquet。完整来源获取核对需要另行提供配置指定的原文件和相同 SHA256；参考资格及读取测试直接使用归档的来源文本。

在 Python 3.12.14、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、NetworkX 3.7、PyArrow 23.0.1及 PowerShell 环境中，保存副本已有 `inventory-reference-result.json` 至副本归档目录，再执行：

```text
python data/method/tsg-proposition-readback-20261101/check_inventory_reference.py qualify
pwsh -File data/method/tsg-proposition-readback-20261101/verify_inventory_reference.ps1
python -m pytest .test-tmp/test_complete_inventory_readback.py -q
```

复算不调用模型。关键 SHA256：

- 来源编译实现：`ee17b0a2c3868cecd67bea34f19f845e0a0b7ec2c15499d296123d490df0790f`。
- 规范 Graph 与清单读取：`8dddb91615680f51a456402c33237d4b089d703fcb70c054e492cea3d867c144`。
- 来源和资格入口：`b3c170d8b03819ac01d69d796f9d0569383998e50099cbae9b1f522a9d9e0458`。
- 独立资格核对：`3cd6c996444e90863706eddc023a94cb7108535b46ce6fe19fbaa8e9379dd524`。
- 固定计划：`f6f9eb290f6cbe56ea8d19c74f13fd091a7e4924c885156c2a3d7aa6fef5b02f`。
- 实际资格结果：`2da8beb327ac471bf027e249b67bfcac241eb854d5d220836a8bf7d57cd67653`。
