# 外部条件保留与完整要求移除的开发结果

## 实际实现与全部机械位置

按[固定设计](2026-11-01-tsg-condition-preserving-edit-design.md)，现有 `prepare_expression_removal` 分别处理目标表达式和外部条件。目标区间覆盖完整表达式成员，位于其他位置的条件保持原文，并返回 `retained_condition_evidence` 和 `condition_scope_review_required`。部分相交、共享条件冲突和非目标来源指代依赖继续保持未解决。所有提案仍需独立语义评审，`whole_prompt_coverage_verified=false`。

全部44张有效图及170个实际命题完成检查：十六个产生结构提案，154个未解决。十六个提案包含十五个 atom 与一个完整 OR。原有四张无效图保持原状态，新增独立任务数为零。

| 全部实际位置的原因 | 数量 |
| --- | ---: |
| 未声明或 opaque 的完整结构 | 130 |
| 指定完整表达式的一处来源生成删除提案 | 16 |
| 目标区间与保留含义重叠 | 6 |
| 目标没有独占规范作用 | 14 |
| OR 内部成员未独立受到断言 | 2 |
| AND 为多项要求容器 | 1 |
| 非目标来源指代依赖删除证据 | 1 |

此前相同170个位置只有一个结构提案，使用其冻结规则的结果保持原身份。本轮数量变化说明已实现的准备规则有所不同，不能解释为十五个新增语义成功，也没有建立表示收益。

## 来源先行的独立语义检查

六个固定目标按设计保留唯一 OR 案例，并从此前区间覆盖不足位置按固定哈希取得其他五个任务。两位新上下文先只依据原文和目标引文形成来源参考；新提案生成后，另外两位新上下文检查完整原文及实际修改后的提示。源码和规则均在上述输出之前固定。

两份来源参考对六个目标均支持单项规范要求，引用全部有效；两位编辑评审对来源支持及实质一致性的检查均通过。每个目标必须同时通过完整要求移除、非目标保留、条件归属、没有反向要求和剩余文字完整性，才算本轮开发成功。

| 固定目标 | 实际结构提案 | 两位评审均通过全部条件 |
| --- | --- | --- |
| matplotlib-22719：空数据 artists 或准确说明问题及避免方法 | 生成 | 通过 |
| astropy-13033：异常告知缺失必需列 | 生成 | 通过 |
| sphinx-10614：SVG 继承图链接进入正确页面且避免404 | 生成 | 通过 |
| astropy-13453：HTML 写出遵循 formats | 生成 | 未通过 |
| xarray-4075：给定布尔权重实例的预期平均输出 | 生成 | 通过 |
| pytest-6202：将指定返回表达式改为 return s | 生成 | 未通过 |

完整开发成功为4/6。OR 案例以完整替代性要求接受评审，没有把两个成员分别编辑或解释为两个独立处理。外部输入和配置仍可以保留；已通过位置没有因条件证据位于其他段落而自动失败。

## 两个未通过位置

astropy-13453 的完整问题文本重复出现 HTML 应遵循 formats 的规范要求。消费者删除一处后，另一处仍明确表达相同要求。两位评审均判定 `target_requirement_removed=fail`，其余条件通过。来源引用定位正确没有建立全提示的重复覆盖。

pytest-6202 的目标引文同时包含旧表达式导致问题的诊断事实和替换要求。消费者删除整段后，诊断事实丢失，后文 `After changing this` 及 `this line of code` 失去明确所指。两位评审均判定非目标保留、条件归属和剩余文字完整性失败；目标义务本身已经移除。

这些结果约束下一项方法修订：同一完整谓词的来源出现需要按完整绑定汇集；支持命题的证据区间与实际编辑的断言区间需要分别确定。仅保留外部条件还不足以解决重复要求和同一片段中的多重作用。当前六个位置保持本次首次提案与首次评审，不能通过后续修订改写为全部成功。

## 证据范围与功能性

本轮是从已知失败中选定的开发检查，不是新自然总体抽样。六个目标具有不同的新检查身份，不替换此前十二位置来源参考的8/12结果，也不重新评分旧48任务的 Graph/Flat 比较。两位来源判断者和两位编辑评审共享模型来源，不能称为人工真值。

本轮没有强平面对照的新输出，不能证明 TSG 独立收益。没有生成软件、测量代码安全、完整功能性或 JCI 效应，功能性维持未测量。正式协议、受保护数据和服务支出均未启用，默认 JCI 方法及 Atomic 家族没有切换。

## 独立核对与复现

材料位于 `data/method/tsg-proposition-readback-20261101`。入口 `check_condition_preservation.py` 的 prepare 固定来源输入、目标及实现，materialize 产生实际提案，evaluate 组装开发结果。主要字段为 `condition-proposals.json.reason_counts`、`.prepared_expressions`，以及 `condition-result.json.rows`、`.semantic_edit_successes`。

`verify_condition_preservation.ps1` 不导入生产 Python 实现，直接读取原始 JSON，按逐字出现位置重建十六个修改后提示，核对 Unicode 来源坐标、外部条件文字、170个位置计数、两份来源参考和两份编辑判断。它独立重算六个位置的联合条件及4/6结果，状态为 `VERIFIED_CONDITION_PRESERVING_EDIT_CHECK`。评审输入 SHA256 在评审之前固定为 `c52876779a7dff6e2b2039dadd8d85a89e375841ae4e78f3c7254d05b79c364b`。

冻结包为 `results/tsg-condition-preserving-edit-20261101-frozen.tar.gz`，校验值保存于同名 `.sha256`。使用匹配的 Python 3.12.14、NumPy 2.5.1、NetworkX 3.7及 PowerShell 环境，在复现副本中保存已有 `condition-result.json` 至副本归档目录，保留全部输入、提案及首次判断，执行：

```text
python data/method/tsg-proposition-readback-20261101/check_condition_preservation.py evaluate
pwsh -File data/method/tsg-proposition-readback-20261101/verify_condition_preservation.ps1
```

评分复算不调用模型。关键 SHA256：

- 准备实现：`8c99721c969ce65a974308288d9b513eadba1fb92ad2999df54754913189510b`。
- 执行和评分入口：`1f76a49397529e8085cd2f295075227b9122ba8a9ec673613ddde95e94da65c8`。
- 独立核验：`a8566eb51f49a1ccf7b88d10119412b00bb264488d7a590ef0b15e58fde8a1ce`。
- 固定计划：`f3caca8579e8ef9f18402cebd4a016658f4950e0f9edddf71c7ce5ab0ea7c2e0`。
- 实际结果：`4871ab285d06d8f1659f31d9bbb50e602cb27c10453a19b6a441ec74a061ab4a`。
- 独立核验结果：`43704e44a4dc36a8afb6b0473e5ca31d16cf7bceaa76e7fe6b8d9746435cf2fb`。
