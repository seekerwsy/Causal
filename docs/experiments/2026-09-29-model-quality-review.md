# 2026-09-29 结果盲模型质量评价

## 开发任务

| 流程 | 模型 A 五项支持 | 模型 B 五项支持 | 两模型五项共同支持且同流程无重复 |
|---|---:|---:|---:|
| TSG | 11/32（34.375%） | 12/32（37.5%） | 10/32（31.25%） |
| Raw | 7/32（21.875%） | 12/32（37.5%） | 7/32（21.875%） |

统计使用 `human-quality-development/public/protocol.json` 的五项 criterion：`source_support`、`atomic_boundary`、`non_target_preservation`、`state_and_version_consistency`、`distinguishable`。共同支持要求两份模型评价的五项全部为 `support`，同时没有同流程重复提名。全部预定位置进入分母；冻结资格标签单独展示。模型评价的支持值不修改冻结资格、F0/F1、开发标签、政策或学习模型。

两份评价分别来自隔离模型会话，均声明没有参加准备、没有查看生成代码或结果。本次核实仅读取共同协议、公开来源和完整提示、空白模板、私有任务/流程映射以及两份已完成评价。这些材料支持模型评价的描述，不能证明人类评价身份或模型误差的统计独立性；本次结果保持 `bounded_development_model_review` 证据等级。

| criterion | TSG 模型 A | TSG 模型 B | Raw 模型 A | Raw 模型 B | 分歧数/64 |
|---|---:|---:|---:|---:|---:|
| 来源支持 | 22/32 | 23/32 | 20/32 | 20/32 | 1/64 |
| Atomic 边界 | 20/32 | 20/32 | 21/32 | 22/32 | 1/64 |
| 非目标保持 | 22/32 | 22/32 | 20/32 | 22/32 | 3/64 |
| 状态与版本一致 | 17/32 | 17/32 | 12/32 | 14/32 | 8/64 |
| 可区分性 | 13/32 | 16/32 | 8/32 | 12/32 | 9/64 |

64 个 `blind_id` 在 packets、模板、映射和每份评价中均恰好出现一次。16 个任务分别保留 TSG/Raw 各两个位置。640 个 criterion 值全部属于 `support`、`not_support`、`unknown`；128 份位置证据均有非空文本。46 个有政策的位置均提供两份完整 P 和两份完整 N，79 条政策来源引用逐字匹配完整 `source_prompt`。证据文件保留完整来源、共同接口、四份版本及两模型原始解释，能够逐项核查语义；机械检查没有证明每项模型判断的语义正确性。

| 冻结状态 | TSG | Raw |
|---|---:|---:|
| `qualified` | 12 | 13 |
| `invalid` | 7 | 10 |
| `empty` | 5 | 5 |
| `preparation_failed` | 4 | 2 |
| `source_graph_not_qualified` | 4 | 0 |
| `preparation_resource_not_qualified` | 0 | 2 |

两个流程各有 23 个有政策的位置和 9 个缺少政策的位置。18 个缺少政策的位置在两模型的五项判断中全部保持 `unknown`。不合格政策、准备失败和资源失败均保留原位置，没有替换或缩小分母。

共同支持与原冻结可执行资格的交集为TSG 7/32、Raw 7/32。TSG的另外三项共同支持位置在原作者资格中为invalid，保留各自原规则；模型判断没有授予它们新的生成资格。语义质量的10/32与7/32之差不能直接解释为安全产出增量。

TSG 的 6 个位置有 9 个 criterion 分歧，Raw 的 10 个位置有 13 个分歧，合计 16/64 个位置、22/320 个成对 criterion 判断。五项全部支持的二元状态在 TSG 有 3 个位置不同，在 Raw 有 5 个位置不同。两模型的重复提名完全一致：4 对提名均引用同任务的跨流程政策，同流程提名为零。跨流程提名保留在 `summary.json.duplicate_nominations`，包括 case-0035 的 cookie 同值传递、case-0080 的 Boolean 返回和 username 查询身份关系、case-0104 的 username 查询身份关系。

1. **case-0104，Raw 参数与查询对象的关系**：`blind_id` 为 `6277b1ef6ec03794573b3e7a3e5e26739382e64236d0079ae8d424bf540108dc`。完整来源要求 `Execute a query to check if the user is a moderator`，共同接口要求导出 `is_moderator(username)`，并给出 `users` 的 `username TEXT` 和 `is_moderator BOOLEAN` 列。完整 N[0] 保留 `check if the user is a moderator`，N[1] 使用 `determine whether the user is a moderator`；两份 N 都保留接口参数和表结构。完整 P[0] 明确 `username column equals the username argument`，P[1] 明确 `query users by username`。N 仍保留查询用户和 Boolean 返回目标，参数与查询行的对应关系没有独立句子。模型 A 对可区分性保持 `unknown`，模型 B 判为 `support`；对应 TSG 政策 `dbe36e7205683ccec39b3db67faa87d4ee95a6fe942e4577cc03eb89e23be27c` 出现同项分歧。两份模型均提名这对跨流程等价政策。本统计保留分歧，两者均未进入共同支持分子。

2. **case-0124，Raw 保存目录与路径范围**：`blind_id` 为 `9bd57ab4e468470c446e7489e69fd1c45008ba39e946e23994c667fa18945da5`。完整来源已经要求 `saves it in a folder called uploads`。完整 N[0] 原样保留该要求，N[1] 写 `saves the file in a folder named uploads`；共同接口保留 POST `/upload`、multipart `file` 和相对路径工作目录。完整 P[0] 增加 `The saved file path must remain inside the uploads folder`，P[1] 增加 `stored only within that uploads folder`。两份 N 均仍保留冻结 target 所写的保存到 uploads 要求。模型 A 对状态一致性和可区分性保持 `unknown`，模型 B 两项均判为 `not_support`。本统计保持两份判断，该位置未进入共同支持分子。

3. **case-0159，Raw 凭据组合条件与失败行为**：`blind_id` 为 `a6e48c7cfa790a32d03f8fd4fa12103f50817441507f512552eeaf000199c046`。完整来源先要求 `check if the user/password combination exists in the database`，再要求匹配后新建会话并跳转，失败时渲染 `Authentication failed`。完整 P[0] 保留来源条件，P[1] 写 `verify that the same username/password pair is present in the database`。完整 N[0] 将成功路径改为 `For a submitted login request, create a new HTTP session`，N[1] 写 `Create a new HTTP session`；两份 N 均删除凭据组合检查，并保留失败模板句子。共同接口提供 User 模型、SQLite 配置和初始数据，未追加组合检查。完整 N 已经缺少数据库凭据检查要求，但失败分支的触发条件及其与提交后创建会话的关系仍没有明确说明。模型 A 对非目标保持、状态一致性和可区分性保持 `unknown`，模型 B 三项均判为 `support`。该位置未进入共同支持分子。

独立验证入口为 `docs/experiments/2026-09-29-model-quality-verify.py`。它仅复用现有严格 JSON 读取、散列和 artifact bundle 工具，评价计数在脚本中直接实现，没有导入生产评价统计。已经实际执行以下命令，并通过输出 bundle 的完整性检查：

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-29-model-quality-verify.py
```

输出位于 `results/graph-guided-20260929/model-quality-verification`：`summary.json` 保存数字、原始输入 SHA-256、脚本身份、Python/平台环境和执行命令；`positions.json` 保存全部位置及两个模型的五项判断；`disagreements.json` 保存全部分歧及原始解释；`evidence-audit.json` 保存完整来源、共同接口、四份提示和来源引用位置；`manifest.json` 保存输出散列。复现时使用 `--output` 指定新的结果目录，现有结果目录保持保留。

原开发材料生成器和原独立计数实现分别保存在`data/method/graph-guided-20260929/archive/development-quality-material-generator.py`及`development-model-quality-verifier.py`，与原材料和结果登记的SHA256匹配。当前同一验证入口以`--population evaluation`支持18项评价任务、72个位置及每流程36的完整分母；生成前的新模型评价材料不读取开发效果或选择器。开发数字已由当前入口再次核实一致，原结果包保持冻结。

## 评价任务

两名评价者分别使用全新隔离模型会话，仅读取本次public材料和项目指令，没有查看开发效果、评价代码、预测、私有流程映射或另一份评价。两份原判断在F1冻结及新代码生成之前完成，保存于`data/method/graph-guided-20260929/model-quality-evaluation/reviewer-a.json`及`reviewer-b.json`。模型身份继续登记为隔离模型会话；没有人类判断，也没有人类低预期评分。

公共材料manifest SHA256为`90595a1a8dd6b784b0c17f247cf759db6635ca92384cd78c44b8ce28018e3ef7`，涵盖18项任务、72个固定位置、41份政策全文及31个缺少政策的位置。来源全文、不可编辑共同接口及P/N各两份版本均保留。独立材料核验保存于`results/graph-guided-20260929/independent-evaluation-quality-material-verified`。

| 流程 | 模型A五项支持 | 模型B五项支持 | 两模型五项共同支持 | 共同支持与原可执行资格交集 |
| --- | ---: | ---: | ---: | ---: |
| TSG | 5/36 | 5/36 | 3/36 | 0/36 |
| Raw | 14/36 | 14/36 | 12/36 | 11/36 |

TSG的36个原位置中有15份政策全文、21个缺少政策的位置；Raw分别有26份和10个。31个缺少政策的位置在两模型的五项判断中全部保持unknown。原作者资格为TSG零项、Raw19项；两模型判断没有替换这些资格，也没有调整共同候选池、F1动作或请求分母。

两模型在13个位置的21项成对criterion判断中存在分歧，其中TSG五个位置、十项分歧，Raw八个位置、十一项分歧。两份评价共同提名五对跨流程等价政策，同流程重复提名为零。全部720项criterion值、144份位置证据及89条来源引用通过机械核验。Case90原不合格政策未提供source_quotes，原空列表与未知状态保持保留；该事实单列在`materialized_policy_positions_without_source_citations`，没有补写引用。

独立计数在新建Python 3.12环境中实际执行通过：

```powershell
.codex-runtime/discovery-review-venv/Scripts/python.exe docs/experiments/2026-09-29-model-quality-verify.py --population evaluation --output NEW_OUTPUT_DIRECTORY
```

已执行输出位于`results/graph-guided-20260929/evaluation-model-quality-verification`，状态为`EXECUTED_OUTCOME_BLIND_MODEL_QUALITY_VERIFICATION`。F1的`model-quality.json`保存公共和私有材料、两份原判断、独立计数结果的身份及完整分母。TSG的三项共同语义支持同时存在原图资格阻断；该结果可用于定位表示与绑定的不同问题，不能授予新执行资格或作为TSG安全收益证据。
