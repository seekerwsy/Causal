# 多处来源与断言编辑范围的开发结果

## 已实现的准备行为

按[固定设计](2026-11-01-tsg-assertion-edit-design.md)，同一个 `prepare_expression_removal` 增加两项明确输入：

- `equivalent_requirement_node_ids` 列出同一完整政策的其他实际来源出现。每处保留自身表达式、条件和绑定，语义等价仍需独立核对。
- `assertion_edits` 将实际编辑绑定到来源出现，允许编辑范围窄于支持该要求的证据范围。每项逐字编辑必须位于所属节点的实际证据区间。

程序逐处检查独立断言、完整组合与叶项绑定，检查非目标证据、共享条件和来源指代依赖，再通过同一个 `apply_prepared_edits` 生成提示。OR、NOT 的内部成员与 AND 容器继续保留原有 Atomic 边界。程序输出始终要求语义评审，不自动认证来源出现穷尽或单项政策身份。

## 两个表示流程的实际结果

六个既有目标及两份冻结来源参考全部保留。Graph 规划者读取相同原文、目标及自身旧流程实际形成的查询 Graph，实际字段为 `representations[task_unit_id].graph` 与 `.catalog`。强平面规划者读取相同原文、目标及自身完整事实和查询测量。两者分别使用一个新的隔离规划上下文，均允许推断全部关系、重建结构和使用相同机械检查机会；未读取来源参考、历史得分或另一方法输出。

两份首次规划输出生成全部十二个实际提示。两个新的匿名评审上下文依据完整提示、相同冻结来源参考和同一六项语义条件进行评价。

| 固定原任务 | Graph 完整语义编辑 | 强平面完整语义编辑 |
| --- | --- | --- |
| matplotlib-22719：完整 OR 要求 | 通过 | 通过 |
| astropy-13033：必需列缺失异常信息 | 通过 | 通过 |
| sphinx-10614：SVG 链接导航 | 通过 | 通过 |
| astropy-13453：HTML 遵循 formats | 通过 | 通过 |
| xarray-4075：给定实例的平均输出 | 通过 | 通过 |
| pytest-6202：指定返回表达式替换 | 通过 | 通过 |

两种方法均为6/6。每个位置均由两位评审同时通过完整目标移除、非目标保留、条件归属、无反向要求、剩余文字完整性及来源参考一致性。所有引用有效，未丢弃未知或失败位置。本轮没有观察到表示差异。

## 两项已知问题的实际处理

HTML 案例中，两种方法均删除了两个实际出现的完整规范句，保留两份原有复现、数据、配置和观察。Graph 用两个实际要求节点声明同一政策，并产生两个编辑。

pytest 案例中，两种方法均保留旧返回表达式导致问题的诊断事实，单独移除规范替换断言。Graph 使用较窄的实际编辑区间；平面方法另将后续检查中的指代明确为原有错误返回语句。两位评审均接受其条件归属和非目标保留。

十八组实际数据检查全部通过：十六组覆盖原170个位置，确认默认调用的状态、实际编辑及修改后文本保持此前原值；另外两组分别核对实际重复要求的共同移除，以及混合引文中较窄断言编辑对诊断事实的保留。检查位于 `.test-tmp/test_assertion_edit_mechanism.py`，没有虚假任务、替代节点或 mock。

## 科学含义与下一项研究范围

本轮证明已执行的准备机制能够处理六个既有目标，包括两个已知失败类型。新规划输出和首次评审具有新的开发身份；此前4/6结果、旧48任务的表示负结果及十二位置参考的8/12结果保持冻结。

相同六个目标的强平面方法也已全部通过，继续使用这些目标无法建立新的成功数量增量。它们保留为准备函数及语义边界的回归材料。后续独立贡献验证需要新的任务范围和前瞻性设计，并检验完整要求清单、完整条件绑定及其下游用途；不能用旧三查询的局部准确率推断整个任务清单已经正确，也不能把更换指标后的旧成绩重新解释为贡献。

本轮只有一个六任务联合规划上下文／方法，不将六个位置解释为六次独立学习重复，不作显著性、总体收益或计算成本完全相同的声明。两种方法均复用各自既有表示，因此也不建立新的自动提取准确率。来源参考和评审共享模型来源，不称人工真值。

软件安全、完整功能性、JCI 真实任务收益及策略价值均未测量。没有代码生成、新服务支出、受保护数据、正式角色或默认方法切换。当前独立 TSG 收益仍未建立。

## 独立核验与复现

材料位于 `data/method/tsg-proposition-readback-20261101`。`check_assertion_edits.py` 固定输入和匿名映射，生成实际提示，并将首次来源参考与两份首次评审组装成 `assertion-result.json`；主要字段为 `.rows` 和 `.semantic_success_counts`。实际 Graph 原生准备结果及两种方法的逐字编辑保存在 `assertion-proposals.json.rows`。

`verify_assertion_edits.ps1` 不导入生产 Python 实现，独立重建全部十二个实际文本，核对多编辑位置、Graph 的来源区间及非目标保护、冻结匿名映射、原文引用和全部联合判定。状态为 `VERIFIED_ASSERTION_EDIT_DEVELOPMENT_COMPARISON`。评审前固定的输入 SHA256 为 `f5b3555c267f594fdc63295bfe2324465dd227abfcdfb98a6b28ce34ad07edc6`。

冻结材料为 `results/tsg-assertion-edit-20261101-frozen.tar.gz`，同名 `.sha256` 保存校验值。在匹配的 Python 3.12.14、NumPy 2.5.1、NetworkX 3.7及 PowerShell 环境中，保存复现副本原有 `assertion-result.json` 至副本归档目录，保留全部首次提案和判断，执行：

```text
python data/method/tsg-proposition-readback-20261101/check_assertion_edits.py evaluate
pwsh -File data/method/tsg-proposition-readback-20261101/verify_assertion_edits.ps1
python -m pytest .test-tmp/test_assertion_edit_mechanism.py -q
```

复算不调用模型。关键 SHA256：

- 准备实现：`1ef16cbf82a00c5293844813b5b64cfa256bceed4bcac7cdad6baa3e17eadf92`。
- 执行与评分入口：`c15e600d6de72dac287ca938bfb388fffb80003e98b15d8d4feb89a2ad80470b`。
- 独立核验：`1d66a5a5f36abce4072257643276b3ac03b3d5fa37624580fe74e8142722da2c`。
- 固定计划：`fa591000476ad019f4df5a956ef183c75507857e80e7cf29b9bb66f6c779b38e`。
- 实际结果：`13cd8476870676e94bcc09dcfed728b368e6662a251bfd3fc041114e908f23ab`。
- 独立核验结果：`c641859d00e1eae031a24a491a753d0bb1a49bedb6a7aba12fe28666e0c10b19`。
