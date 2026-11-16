# 原始表示的独立读出与下一项来源准备

## 实际读出结果

按 `2026-11-02-tsg-source-blind-readout-design.md`，对已暴露的RestrictedPython受控任务执行两个新的隔离读出。它们只取得固定六项问题及自身原始表示，不取得完整原始源码、事前参考、旧评分或另一方法。Graph使用原有独立制作的记录，未使用后续人工关系修订。

两份首次回答固定后，由另外两个隔离上下文逐项评价。来源和参考只用于核对，不能补足答案遗漏。实际结果如下：

| 项目 | Graph | 强平面 |
| --- | --- | --- |
| 完整输入规范JSON字符 | 36436 | 23846 |
| 实际回答规范JSON字符 | 12767 | 11135 |
| 两份评审共同完整项目 | 六项 | 六项 |
| 完整任务读出 | 通过 | 通过 |
| 评审分歧 | 零项 | 零项 |

六项为要求角色、操作范围、对象与量词、policy条件、结果归属和非目标范围。完整输入均低于40000字符，回答均低于16000字符。身份、字段、条目编号及逐字引文机械校验通过，独立计数状态为 `VERIFIED_SOURCE_BLIND_READOUT_ACCOUNTING`。

这是一个已暴露任务，六项不是六个独立样本；没有显著性检验或总体表示收益。本任务的原始记录足以独立支持当前读出，原始来源缺失不能解释这次平局。当前六项指标没有显示Graph额外收益，不扩大同一任务和同一问题的重复次数。原有表示研究及其评分保持原身份。

本次上下文按输入文件隔离，表示形态仍可辨识，模型既有知识和共同模型来源不能消除。精确模型构建及实际推理用量未知，不据字符数量声称完全相同计算成本或成本优势。没有代码生成、JCI执行或正式角色赋予。

结果SHA256为 `080e8634151d09f194d567f42bff7ebb87dfce84a99c75130d8749b2c4b716fc`，独立核对为 `40bbbd9beb3f97fa4ed334437023d8affb1afbe901fd06f6f1beace5885c7885`。完整输入、首次答案、两份评审及逐字引用均保存在 `data/method/tsg-source-blind-readout-20261102`。

## Kedro 单项要求与来源参考

已为固定来源CVE-2024-9701编写明确标注的自然代码受控任务。共同上下文包含两个原始模块、原始API类引用及许可证。新增要求仅约束存储恢复时允许的精确module/name组合、拒绝结果和适用范围；read及继承构造、值及嵌套引用、返回映射及实例data、正常save往返分别表达。原始编程请求没有提供，整体提示不标记为自然请求。

公开API背景为研究者转述：[shelve文档](https://docs.python.org/3.12/library/shelve.html)说明值恢复使用pickle；[pickle文档](https://docs.python.org/3.12/library/pickle.html)说明global可以指向类或函数，并讨论限制允许对象及其局限。两份文档已完整阅读。任务的特定允许集合和兼容要求由研究者规定，不能将这些API事实解释为完整安全认证。

独立上下文只阅读任务与原始资料，支持任务可解释、单项恢复策略身份、基准未表达新增精确限制、非目标合同相容和绑定上下文充分。六项完整绑定参考均为supported；13项连续逐字证据通过机械核对，状态为 `VERIFIED_CONTROLLED_SESSION_TASK_REFERENCE_ACCOUNTING`。相容性仍是来源语义判断，新增合同尚未完成可执行验证。允许拒绝无法核对编码不能扩展为拒绝任务明确要求的正常save往返。

本轮没有制作Kedro的候选Graph、平面记录或读出答案，没有取得该任务的方法评分。其静态表示比较参考已准备，`code_generation_qualified=false`、正式角色未赋予。准备人员已接触原始源码、原始测试及来源测量；未来方法制作上下文只取得冻结的共同任务资料，不取得这些测试、测量或参考。

任务来源SHA256为 `779924d59035c62c28428361bb8fa2c9d7a024b7dc2f5e99791308579a9bea0d`，首次参考为 `6e0702e1a17bd6334f83bf3217abaaa320a2709804310c8641ae54aa50b493a1`，核对为 `b8cb1e62b73911ac3a68b1d0291a2cec3da5ddc8afd517d1c3ea8cfd1fcaff05`。当前文件为 `kedro-task-source.json`、`kedro-task-review.json`和 `kedro-task-admission.json`。

## 固定来源的后续取得条件

其余22项原固定身份全部取得修复提交及父提交元数据。Starlette的原始仓库地址保持encode/starlette，公开接口确认其规范位置为Kludex/starlette，同一固定提交身份没有变化。五项提交包含多个父提交，全部父项保留。核对状态为 `VERIFIED_FIXED_SOURCE_METADATA_ACCOUNTING`，元数据SHA256为 `43a32666f50ec0eb0c9f19156f6df43c1bbbcbfe19297bad4009817cff39bf0e`。

在读取这些来源程序之前固定规则：第一Git父提交仅作为修复前来源候选，其他父提交保留；不依测试、Graph或JCI表现更换候选。候选尚未证明存在目标缺陷。缺失目标、零效果、不适用和未知均保留固定身份，不补充替代来源。

本步骤没有取得这22项程序正文，没有建立其任务资格、Oracle资格或代码谱系独立性。自然来源取得范围仍为原24项身份，同一轮准备，没有按方法结果选择新来源。

## 复现及后续边界

在冻结包的独立副本中保存已有派生输出后，执行：

```text
python data/method/tsg-source-blind-readout-20261102/run.py assemble
python data/method/tsg-source-blind-readout-20261102/run.py report
python data/method/tsg-source-blind-readout-20261102/verify.py
python data/method/security-code-source-20261102/verify_kedro_task.py
python data/method/security-code-source-20261102/verify_remaining_metadata.py
```

复算使用首次固定答案与审查，不重新调用上下文或执行来源程序。源码与初始Task来源按原目录布局保留，Python需要当前artifact_io、records及NumPy。新的自然任务方法比较仍须在输出之前固定共同制作与修订预算、任务集合及成功门槛。

接下来为Kedro的新合同验证允许值的真实往返、禁止引用的拒绝及无法判定实现的测量边界，随后才能准备公平的实际代码生成比较。当前读出平局和语义参考不能替代这些下游证据，也不能将Graph和JCI的目标认定为完成。

冻结包为 `results/tsg-source-readout-preparation-20261102-frozen.tar.gz`，包含40个文件，164136字节，SHA256为 `2ff487caf345fb58eb1e165a81c296e9e61ebf157c89798c1b5e5939bdb088b8`。它保存实际输入、首次读出、独立评审、Kedro任务参考、固定来源元数据及所需程序。

在 `.test-tmp/tsg-source-readout-preparation-replay-20261102`独立解压，使用包内artifact代码重新建立读出输入、拼装评价、计算结果并核对来源准备，十项派生输出均与原件逐字节相同。该复算未重新调用模型或执行来源程序，不主张重新调用模型能够逐字节产生原答案。记录为 `results/tsg-source-readout-preparation-20261102-replay.json`，状态 `VERIFIED_EXTRACTED_READOUT_AND_SOURCE_PREPARATION_REPLAY`。本段记录归档之后完成的复算。
