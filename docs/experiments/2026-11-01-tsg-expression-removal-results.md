# 完整表达式移除准备的实际结果

## 已执行机制

[固定设计](2026-11-01-tsg-expression-removal-design.md)已经实现并在真实原文上执行。`src/tsg/prepared_prompts.py:prepare_expression_removal` 实际消费表达式路径、成员、条件所有者与来源区间，检查非目标要求、共享条件及来源指代依赖，再调用既有 `apply_prepared_edits` 生成删除后的提示。输入指定一个实际表达式出现位置；输出始终保留需要独立语义评审、全提示重复覆盖尚未认证的状态。

## 全部实际结果

对48个既有任务中的44张有效图、全部170个命题逐一执行。其他四个任务的原图保持无效，没有重新生成或补充成功案例。

| 原有图标记的来源作用 | 实际命题数量 |
| --- | ---: |
| descriptive | 123 |
| normative | 43 |
| mixed | 2 |
| mentioned | 2 |

作用标记来自实际 Graph，不属于本轮新取得的独立语义参考。170个位置中一个产生结构删除提案，169个保持未解决。

| 全部位置的实际原因 | 数量 |
| --- | ---: |
| 完整结构为 undeclared 或 opaque | 130 |
| 目标文字区间未覆盖全部成员或其条件证据 | 16 |
| 删除区间与保留含义重叠 | 5 |
| 目标没有独占规范作用 | 14 |
| OR 内部成员未独立受到断言 | 2 |
| AND 为多项要求容器 | 1 |
| 非目标来源指代依赖删除证据 | 1 |
| 指定完整表达式的一处来源已生成删除提案 | 1 |

43个标记为 normative 的位置中，十九个结构未解决、十六个区间覆盖不足、五个与保留含义重叠，各一个分别属于 AND 容器、来源指代依赖和生成提案。该数量不能作为自然任务总体成功率，也不能与旧平面成绩比较。

唯一提案来自 `pydata__xarray-7233`，删除原文中的 `All variables that were coordinates before the coarsen.construct stay as coordinates afterwards.`。独立原文切片重建与实际编辑完全一致，程序列出的非目标证据保持原文内容。尚未经过新的独立语义编辑评审，不能称为成功完成 Atomic 干预或全提示要求移除。

## 对下一步的约束

当前记录暴露出两个实际限制：许多来源命题没有明确的可编辑组合结构；条件证据经常与目标文字分散在不同位置，当前连续删除规则不能处理这些情况。它们需要完整表达式提取、编辑范围及语义保持共同解决。增加读出字段本身不能补足这些信息。

本轮没有产生新的 OR 或 NOT 完整编辑正例；两项 OR 成员均保持未解决，NOT 没有实际正例。当前证据不足以直接扩大新的表示收益实验。下一项开发验证需要处理分散的条件证据及实际语义编辑，保持原始来源、未知、已有负结果和全部分母；不能通过减少条件或排除失败提高表面成功数量。

## 独立检查与复现

`data/method/tsg-proposition-readback-20261101/check_expression_removal.py` 使用原始图及 NetworkX 独立确定完整成员，检查 OR 成员和 AND 容器未被独立删除，再通过原文切片及位置变化重建准备成功的文本与全部保留证据。原始提案保存在 `expression-removal-result.json.rows`，汇总来自 `.reason_counts`、`.prepared_expressions` 和 `.prepared_composition_counts`。状态为 `VERIFIED_STRUCTURAL_EXPRESSION_PREPARATION_ONLY`；`semantic_success_established=false`。

冻结材料为 `results/tsg-expression-removal-20261101-frozen.tar.gz`，同名 `.sha256` 文件保存校验值。在匹配的 Python 3.12.14、NetworkX 3.7项目环境中，保存复现副本已有的 `expression-removal-result.json` 至副本归档目录，保留其他输入，再执行：

```text
python data/method/tsg-proposition-readback-20261101/check_expression_removal.py
```

本轮没有新增独立任务、代码生成、服务支出、受保护评价、正式角色或默认方法切换。安全代码产出、功能性、JCI 真实任务收益及 TSG 独立收益均未由本轮建立。

- 准备实现 SHA256：`14fc7385db0ced41384597894448e8531833a7d2cace618d1d60905bf96ff2da`。
- 独立检查 SHA256：`300290e69f39fcefcc79ef763dce6ccd8d64e1afe0147777ea261c7dd1d7dda6`。
- 原生 Graph 实现 SHA256：`8af1827f7a392a787115f4e54c20c60a64e7d628e22c8fadb25a570c3ed25273`。
- 实际结果 SHA256：`da6a15028ee174444de57cb986b132f5e31afff131f1d4b0ac1ee3f59120e457`。
