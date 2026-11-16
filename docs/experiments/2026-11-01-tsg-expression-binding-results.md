# 完整表达式与条件归属的消费者检查结果

## 已实现行为

按[固定设计](2026-11-01-tsg-expression-binding-design.md)，`source_proposition_readback` 增加以下实际字段：

- `propositions[*].expression_path_node_ids`：表达式根至当前命题的有序路径。
- `propositions[*].expression_condition_attachments`：路径上实际条件边及其命题所有者，保留原始方向和关系类型。
- `selected_expression_root_node_ids`：所选命题所属的完整表达式根，与指代及背景引入的其他表达式分别列出。
- `nodes[*].source_unit_ids`：实际证据区间对应的原文物理行编号。

完整谓词、分支、条件和操作证据共同表达绑定；消费者不再需要根据一个互斥引用类别替代这些关系。[共同语义说明](../tsg-binding-semantics.md)分别规定来源锚点、表达式、条件所有者和不确定性。原文没有支持的输入假设、具体执行身份和时间关系继续保持未知。

## 实际核对

| 检查范围 | 结果 |
| --- | --- |
| 固定 Graph 查询位置 | 144个全部保留 |
| 有效位置原有全部读出字段 | 132个与冻结原值完全一致 |
| 原有无效位置 | 十二个保持无效，没有重新生成 |
| 完整实际图 | 44张通过独立路径、条件归属及来源位置核对 |
| 完整命题记录 | 170个 |
| 具有嵌套表达式路径的记录 | 五个 |
| 按命题路径保留的条件附件 | 205个，包含不同命题路径中重复出现的来源条件 |
| 原文索引实际检查 | 十六组全部通过 |

205个附件不是205个独立条件或任务。完整图包含38个声明为 atom、85个 undeclared、45个 opaque，以及各一个 AND 和 OR。当前实际图没有 NOT 正例，不作该逻辑类型的经验正确性声明。

`matplotlib__matplotlib-22719` 的两个替代分支分别保留同一 OR 根和各自条件关系。`mwaskom__seaborn-3069` 的三个成员分别保留同一 AND 根；纵轴反转成员具有自己的条件附件，隐藏网格及延伸范围成员保持各自实际条件记录。核对验证这些实际关系未被跨分支合并，没有认证提取的来源含义正确。

独立检查入口为 `data/method/tsg-proposition-readback-20261101/check_expression_binding.py`。它使用原始记录与 NetworkX 的祖先及路径计算核对生产输出，并删除新增派生字段后与此前132个冻结完整读出逐项比较。结果为 `expression-result.json`，状态 `VERIFIED_EXPRESSION_BINDING_ONLY`；主要字段为 `.position_status_counts`、`.composition_counts`、`.coverage`、`.rows` 和 `.full_graph_checks`。

## 证据边界

当前实现使表达式层级与条件归属可以直接读取和核对，没有运行新的 Graph/Flat 比较，也没有修复或重新评分旧语义判断。此前来源参考继续为8/12通过，四个位置未知；此前48任务主要结果继续为 Graph 94/144完整绑定、平面126/144。`source_entailment_verified=false`，独立表示收益没有建立。

实际编辑或属性学习仍需要消费者正确选择完整命题并使用这些关系。接口增加字段不能证明消费者已经减少实例错配、非目标漂移或效应估计误差。新比较必须独立固定来源语义参考、实际消费者、信息与计算预算、主要指标及全部任务分母。Atomic 候选规则、默认 JCI 方法及全部冻结结论保持原身份。

## 复现材料

冻结材料为 `results/tsg-expression-binding-20261101-frozen.tar.gz`，同名 `.sha256` 文件保存归档校验值。使用匹配的 Python 3.12.14、NetworkX 3.7项目环境，将已有 `expression-result.json` 保存至复现副本的归档目录，保留原有 `result.json` 和全部来源记录，执行：

```text
python data/method/tsg-proposition-readback-20261101/check_expression_binding.py
python -m pytest .test-tmp/test_source_unit_evidence.py -q
```

复算不调用模型。代码生成调用及新增独立任务均为零；没有服务支出、受保护评价或正式协议激活。

- 原生 Graph 实现 SHA256：`8af1827f7a392a787115f4e54c20c60a64e7d628e22c8fadb25a570c3ed25273`。
- 独立检查 SHA256：`749bf1a17680755fbe523e0dc845e24205e7e7f58f804470635459a69c809dee`。
- 固定设计 SHA256：`d5cbdcc6e765b0022697eabb33ba7f0c0be39d173a0de5a990f2fb785e2f5036`。
- 实际结果 SHA256：`7fa077c4fe5eb88f18da415c1a5f4795309c4f9b5e596d0ff012cefd401a0053`。
- 当前共同语义说明 SHA256：`713e5f4f6adb741ffb163017b8ae67f84e75394a1cd093b77eb55abd5eca144d`。
