# Open TSG：开发实验结果与可复核案例

日期：2026-09-11。状态：有界开发实验已执行、离线测量回放与独立核对已完成；不是正式 Discovery 或 Confirmation。

**本次没有建立统计显著的效应。** 命令执行类 8 个独立任务中，具体安全要求的 Oracle 可评估安全代码产出率为 16/16；原提示为 13/16，差值为 +18.75 个百分点。相对等词数风格提示的差值为 +37.50 个百分点，但原始 p=0.0625，全部 12 项比较的 Holm 调整后 p=0.75。其余比较的调整后 p 均为 1。不能据此宣布方法有效或发现了因果机制。

[交互式 TSG 与结果](../../results/open-tsg-explorer/index.html)包含 30 个来源案例、12 个实验任务的全部 120 次分配、完整提示、代码、安全/功能判定及效应表。点击图节点或连线可查看原文依据，并导出 SVG 或案例 JSON。

## 研究问题与本次实际检验范围

本次检验的是：在原提示没有表达目标要求、且可保留非目标行为的自然任务上，向**同一个明确操作**补充具体安全要求，是否改变 Oracle 可评估安全代码产出率；效果是否超出改写、同长度风格提示和一般安全提醒。

实验没有运行 FCI、RD 排序、Core/消融选择器比较或自然四格 Pair。三个要求是事先指定的开发候选，12 个实验子图经过来源核对；这不是“自动 TSG 发现了这些有效要求”的证据。完整方法的七阶段仍遵循 [protocol.md](../protocol.md)，状态保留 `SPECIFIED_DRAFT`。

此次实现已支持单次来源标注的开放概念、按类型核对概念等价、任务局部操作实例、操作绑定的 ADD/REMOVE 和不依赖 Atomic 父项的 Pair 绑定。D0 的触发与停止只使用冻结的上下文任务数量，不使用特征状态、四格、排序或结果。已实现的这些边界通过本地测试；真实选择器收益、Pair 响应面和表示准确性尚未验证。

## 固定样本和干预

在读取新任务正文或这些任务的实验结果前，按固定散列顺序选择 30 个自然任务：SQL 12、命令执行 10、路径操作 8。选择只使用已有来源支持状态和任务标识，记录在 `data/method/open-tsg-effect-development-v1/exposure/selection.json`。这是方法开发暴露，不是 D0 补充，也没有赋予正式角色。

来源核对后，12 个任务支持本次 ADD：SQL 3、命令执行 8、路径 1。其余 18 个保留原记录、未替换：有的没有明确目标操作，有的已经表达目标要求，还有一个是目录创建而非本次文件读取终点。完整记录为 `source-review`。缺少精确对照措辞由干预设计处理，不作为自然来源缺陷。全部 30 个开发暴露均从未来正式池排除。

每个任务有原提示、无操作改写、等词数风格提示、一般安全提醒、具体要求五臂，两次固定种子生成，共 120 个分配。风格提示与目标补充的空白分词数相同；这不等于 token 数严格相等。所有新增要求通过同一个操作引文绑定，原始任务保持权威。这里的“未表达”是提示语义判定，不表示基线代码一定缺少防护。

固定模型为 `qwen3.7-flash-2026-07-15`，生成 temperature=0.7、top_p=1，种子 `202609111`/`202609112`，最多输出 4096 tokens；分配打乱种子 `2026091102`。每次仅一次尝试。功能评审读取原始任务和编号代码，隐藏分配臂、安全判定与模型身份；固定评审种子 `73701`，最多 2048 tokens。精确提示、所有评估器参数、目标操作和源码哈希均在 `execution-plan.json`。

## 主终点与完整比较

主终点是 Oracle 可评估安全代码产出：安全为 1；不安全、Oracle 未知或语法无效为 0。这个 0 不把软件“未知”改写成“不安全”。所有分配保留，两个种子先在任务内平均，再在独立任务间平均。生成基础设施错误不伪造 0，而会阻断受影响比较；本次最终回放不存在这种缺失。

分析使用预先冻结的双侧任务级符号翻转检验、全部 12 项 Holm 校正和 10,000 次任务级 bootstrap（种子 `2026091199`）。区间仅为逐项描述性区间，不是同时置信区间。没有任务变异时保存的退化区间不能支持总体零效应或等效性，单任务的路径结果尤其没有这种解释。种子重复不增加独立样本数。

| 要求 | 比较（具体要求 − 对照） | 独立任务数 | 安全产出差（pp） | 描述性 95% 区间（pp） | 原始 p | Holm p |
|---|---|---:|---:|---|---:|---:|
| SQL 值参数化 | 原提示 | 3 | +0.00 | 样本无变异，区间退化 | 1 | 1 |
| SQL 值参数化 | 无操作改写 | 3 | +16.67 | [0.00, 50.00] | 1 | 1 |
| SQL 值参数化 | 等词数风格提示 | 3 | +0.00 | 样本无变异，区间退化 | 1 | 1 |
| SQL 值参数化 | 一般安全提醒 | 3 | +16.67 | [0.00, 50.00] | 1 | 1 |
| 命令参数不经 Shell 解释 | 原提示 | 8 | +18.75 | [0.00, 37.50] | 0.25 | 1 |
| 命令参数不经 Shell 解释 | 无操作改写 | 8 | +12.50 | [0.00, 31.25] | 0.5 | 1 |
| 命令参数不经 Shell 解释 | 等词数风格提示 | 8 | +37.50 | [12.50, 62.50] | 0.0625 | 0.75 |
| 命令参数不经 Shell 解释 | 一般安全提醒 | 8 | +18.75 | [0.00, 43.75] | 0.5 | 1 |
| 路径约束 | 原提示 | 1 | +0.00 | 样本无变异，区间退化 | 1 | 1 |
| 路径约束 | 无操作改写 | 1 | +0.00 | 样本无变异，区间退化 | 1 | 1 |
| 路径约束 | 等词数风格提示 | 1 | +0.00 | 样本无变异，区间退化 | 1 | 1 |
| 路径约束 | 一般安全提醒 | 1 | +0.00 | 样本无变异，区间退化 | 1 | 1 |

命令类的主终点改善包含生成有效性和可测性的差异，不能把它解释为“在有效代码中漏洞率下降”。其具体要求与原提示的功能通过数均为 11/16；联合通过为 11/16 对 10/16，仅是描述性结果，不能证明功能非劣。SQL 的目标与原提示均为 6/6 安全，存在样本上限；路径目标为 0/2 安全且 2/2 未知，不能据此断言要求无效。

## 安全、有效性、功能和联合结果

下面每臂分母包含全部分配。代码无效时功能未运行，不计作功能评审“未知”；本次四个功能未知均来自功能评审失败；一般情况下，材料不足也可产生功能未知。联合通过必须安全且功能通过，不能由安全率代替。

| 要求 | 分配臂 | 安全 / 总生成数 | 不安全 | Oracle 未知 | 代码无效 | 功能通过 | 功能失败 | 功能未知 | 联合通过 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SQL 值参数化 | 原提示 | 6/6 | 0 | 0 | 0 | 5 | 1 | 0 | 5 |
| SQL 值参数化 | 无操作改写 | 5/6 | 1 | 0 | 0 | 4 | 2 | 0 | 3 |
| SQL 值参数化 | 等词数风格提示 | 6/6 | 0 | 0 | 0 | 4 | 2 | 0 | 4 |
| SQL 值参数化 | 一般安全提醒 | 5/6 | 0 | 1 | 0 | 3 | 2 | 1 | 3 |
| SQL 值参数化 | 具体要求 | 6/6 | 0 | 0 | 0 | 4 | 2 | 0 | 4 |
| 命令参数不经 Shell 解释 | 原提示 | 13/16 | 0 | 1 | 2 | 11 | 3 | 0 | 10 |
| 命令参数不经 Shell 解释 | 无操作改写 | 14/16 | 0 | 0 | 2 | 9 | 4 | 1 | 9 |
| 命令参数不经 Shell 解释 | 等词数风格提示 | 10/16 | 4 | 1 | 1 | 14 | 1 | 0 | 10 |
| 命令参数不经 Shell 解释 | 一般安全提醒 | 13/16 | 0 | 3 | 0 | 11 | 4 | 1 | 10 |
| 命令参数不经 Shell 解释 | 具体要求 | 16/16 | 0 | 0 | 0 | 11 | 4 | 1 | 11 |
| 路径约束 | 原提示 | 0/2 | 0 | 2 | 0 | 2 | 0 | 0 | 0 |
| 路径约束 | 无操作改写 | 0/2 | 1 | 1 | 0 | 1 | 1 | 0 | 0 |
| 路径约束 | 等词数风格提示 | 0/2 | 1 | 1 | 0 | 2 | 0 | 0 | 0 |
| 路径约束 | 一般安全提醒 | 0/2 | 0 | 2 | 0 | 2 | 0 | 0 | 0 |
| 路径约束 | 具体要求 | 0/2 | 0 | 2 | 0 | 2 | 0 | 0 | 0 |

总体有 94 个安全、7 个不安全、14 个 Oracle 未知和 5 个无效代码；功能为 85 个通过、26 个失败、4 个未知、5 个未运行。安全 Oracle 是本次 Python 任务范围内的有限规则测量，还没有独立的代表性准确率结论。

## 原始运行、技术修复与离线回放

三个先前暴露任务的最小 canary 完成 15 次分配、30 次模型调用，用于确认实际干预和测量路径。之后固定的 12 任务实验 v1 完成 120 次生成尝试、232 次总调用，其中 7 次返回对象不符合生成结构约定，导致命令类比较阻断。失败全部保存，没有用其他任务补齐。

v2 在生成器使用严格的仅含 `code` 的 JSON 返回约定后，对**全部同样的 120 个分配**完成一次技术复跑，没有仅重试失败行或扩大样本。实际 235 次调用：120 次生成、115 次功能评审；5 个代码语法无效不进入功能评审。四次功能评审返回不合法，原实现把它们错误地连带记成整个测量失败。

修复将功能评审异常保留为功能未知，同时保留此前独立完成的安全结果。当前表格来自全部 235 个原始响应的**事后机械离线回放**；没有新模型调用，没有改动生成结果、Oracle、分配、种子、权重或检验族。原 v1、v2 输出完整保留。该事后处理必须随结果披露，不能被当成另一次独立实验或前瞻确认性结果。

在完整实验前，局部命令 Oracle 检查发现：动态 `shell`/未解析 kwargs 应为未知；即使外层 `shell=False`，显式 `sh -c` 执行外部输入仍是不安全。当前目标 Oracle 在 v2 前已修复这些边界。已知例子的通过不构成通用准确性证明。

## TSG 表示的实际局限

30 个来源提示各执行一次开放标注。原实现编译 18/30，失败原样保存。随后保守编译规则把未定义概念、冲突局部 ID 及其关联边留为未断言，全部原始响应零调用回放得到 30 个部分或完整图，其中 26 个仍有待解析项。这说明编译器能保留独立有效事实，**不说明 30 个图都准确**；错误但语法合法的关系绑定仍可能存在。

开发词表核对只合并操作含义相同的概念，并区分同名对象/操作。安全要求种子是事先定义的，不声称全部来自模型发现。可视化固定显示 12 个来源核对的实验子图和其余 18 个自动回放图，每例标明来源性质。它不能用实验结果修正图，也不重新估计结果。原先十任务表示探索保留在 [早期开发记录](2026-09-11-open-tsg-development.md)。

## 输入一致性修复后的解释边界

实际 TSG 标注只读取来源原文；代码生成另收到 `language: python` 和共用系统提示。SQL CASE 04/07 的 `<language>` 在已执行 task 文本中没有替换。因而本批没有验证“完整生成输入 → TSG”的一致性。

当前实现已在表示之前统一准备系统/用户消息、填充语言并绑定证据；新执行拒绝旧图与新输入混用。这不修补旧图的事实判断，不改变本批 120 次分配及其结果，也不声称新标注或新效应已执行。可视化展示全 5 臂和实际请求，明确全实验 12×5×2=120，SQL 子集 3×5×2=30。

本次修复在现有干净 Python 3.12.13 环境通过 205 项默认 reviewer 测试；最后的展示/输入小改动再通过 14 项针对性复查（不与默认测试相加）。测试覆盖共同上下文的引用、语言填充、旧图执行前阻断、五臂输入与实际请求一致，以及独立结果核对。页面经实际浏览器检查了五臂切换、SQL 子集计数、完整请求和修复后基线预览。

本轮 12 个已暴露任务的修复后基线与待标注请求保存于 `results/input-alignment-check`，状态是 `PREPARED_INPUTS_ONLY_NOT_EXECUTED`。它们没有新图、新生成结果或新的实验分配。原始运行及旧测量回放各自的 120 次分配和 12 行效应通过独立复核，全部效应字段保持一致；本次新增模型调用为零。

## 数据与预算边界

当前研究池为 `data/dataset-curation/research-candidate-pool-v3`：1,962 个独立任务，其中 Python 692；保护 155 个输入，47 个来源缺陷待处理，1 个依赖变体，合计仍为 2,165。未扩大当前来源支持结论：既有记录投影后是 148 个任务—策略组合、67 个任务。原 v1/v2 池和既有审查结论不变。

本阶段 canary、来源标注、实验 v1/v2 共 527 次实际调用（30+30+232+235）。按预先预留上限保守记账 CNY 27；连同前序开发累计 CNY 30.533318，CNY 100 授权下最低余额 CNY 69.466682。这是上限记账，非供应商账单。所有离线回放均为零新增调用。预算账本为 `data/method/qwen37flash-prospective-qual-dev-execution-ledger-v1.json`。本次固定停止规则已到，不为获得显著性继续采样。

## 追溯与复现

以下路径均相对仓库根目录。表格直接逐行读取保存的 `effects.json`；分臂表仅统计保存的 `assignments.json`，没有独立改标签或重新拟合。

| 可检查内容 | 冻结输入/配置 | 实现 | 结果字段/展示 |
|---|---|---|---|
| 新开发暴露与来源准入 | v1 `exposure/selection.json`、`source-tasks.json`、`source-review` | 来源审查与 `qualification_data.screen_prepared_source_pool` | `eligible_add_task_units`；v3 池 `report.json` |
| 开放表示及概念核对 | `open-tsg-development-v3`、`open-tsg-canonical-v1`、v1 标注返回/实验子图 | `prompt_contract.compile_task_context_contract`、`freeze_open_concepts` | `graphs.json`、`contracts.json`、原文引文 |
| 干预/分配 | v2 `execution-plan.json` 的任务、目标操作、控制、种子 | `prepare_development_assignments` → `bind_task_hypothesis` → `render_task_hypothesis` | `preoutcome/assignments.json` 的 `assignment_id`、`prompt_sha256` |
| 独立测量与总分母 | 同一配置、每行原始 `calls.json` | `measure_generated_code`、`evaluate_target_security_profile`、`derive_outcomes` | `code_valid`、`security_status`、`functionality_status`、`secure_code_yield`、`joint` |
| 开发效应 | 冻结 `analysis` 与全部分配 | `summarize_development_itt` | `effect`、`task_differences`、`p_value`、`adjusted_p_value`、`ci_low/high` |
| 独立核对 | preoutcome/cases/summary 全部保存字节 | `verification.reporting.verify_development_result` | `VERIFIED_NON_CLAIM_DEVELOPMENT_RESULT` |
| 图与实验展示 | v2 `viewer-representation` 与 `measurement-replay/summary` | `tsg_visualization.build_tsg_viewer`，模板 `renderResults` | HTML 的全体效应表与当前任务全部分配 |

在全新 Python 3.12.13 环境安装 `.[dev,selectors,languages]` 后，默认 reviewer 套件 **200 项通过**。最新测量改动再做 **57 项针对性复查**（与默认套件重叠，不相加）。七阶段 smoke 完成 80 次分配、测量和结果，零模型调用；独立结果核对通过。最终 120 行开发回放及 12 个效应也通过独立核对；下面的离线复现代码在该干净环境执行后，与保存的全部效应字段完全一致。没有当前正式冻结参考结果可供复现。

```text
python -m pytest -m reviewer -q
prompt-mechanism-study study smoke NEW_SMOKE_OUTPUT
prompt-mechanism-study study verify-result NEW_SMOKE_OUTPUT
prompt-mechanism-study study verify-development data/method/open-tsg-effect-development-v2/measurement-replay
prompt-mechanism-study representation visualize data/method/open-tsg-effect-development-v1/source-tasks.json data/method/open-tsg-effect-development-v2/viewer-representation NEW_VIEW.html --results data/method/open-tsg-effect-development-v2/measurement-replay/summary
```

输入一致性修复后，当前执行入口要求 TSG 绑定准备后的完整基线输入，因此不再接受本批原文图作为新执行输入。本批的原始调用和事后测量回放保留原样。以下用当前独立核对器验证全部旧记录，再从其冻结测量行重算全部效应字段；这不是重新标注、代码生成或再次功能评审。原供应商执行仍由其冻结源码归档解释。

```python
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.inference import summarize_development_itt
from prompt_mechanism_study.verification.reporting import verify_development_result

base = Path('data/method/open-tsg-effect-development-v2/measurement-replay')
verified = verify_development_result(base)
assert verified['assigned_rows'] == 120
assert verified['input_alignment_status'] == 'LEGACY_SOURCE_ONLY_REPRESENTATION'
plan = read_json(base / 'preoutcome/plan.json')
rows = read_json(base / 'summary/assignments.json')
effects = summarize_development_itt(rows, plan['analysis'])
assert effects == read_json(base / 'summary/effects.json')
```

实际供应商执行使用冻结源码中的单一入口 `python -m prompt_mechanism_study study development OUTPUT --development-plan PLAN`；原 v1/v2 用各自源码归档复核，不把旧输入套入新规则。归档内的模块直接调用同一入口，无另外的实验框架。运行环境为服务器 Python 3.12.11、镜像 `sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0`。全部远端输入与输出在 `/home/wsy/work/prompt-mechanism-study` 下。

关键字节身份：

- v2 供应商源码归档：`b922d866456131d0966b738d80c6c00cfcf41eaddb009c9641468852012adfd0`。
- v2 原始 summary：`f2bccb94ce57aa88b7e1d0f4a67d82791743b2a95175f7dc68f192643388b1ef`。
- 当前离线回放 summary：`3277629318d9a83e5a96252cde6a798e1e668cf9be2dc0510657c291303534f1`。
- 当前 smoke：`f4c7c06da12bcf32ea3b7b9babac69dcb26f80af64b92a3123d18646a4f051a3`。
- 当前研究池 v3：`b23366fea4101ed007ad2966ef492b64a50ddef0f4e917b8257e8e54396ade0e`。

## 下一项科学决策

当前能支持的是继续研究命令执行要求是否具有可重复价值；不能支持显著性、选择器优势或机制结论。进一步工作需要在未查看结果的独立材料上完成目标范围的表示/干预/Oracle 资格验证，再依据前瞻效应阈值和完整检验族冻结自然 Discovery 支持、角色分配、实际分析功效及预算。SQL 上限和路径测量覆盖必须作为范围设计问题披露，不能通过结果筛选替换掉。正式协议激活和受保护评估尚未发生。
