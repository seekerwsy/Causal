# SQL 完整任务表示、单输入干预与复跑

本轮把完整任务图与 Atomic 干预范围分开，并实际执行了新的五臂比较。**输入、图和干预绑定已修正并通过复跑核对；自动抽取仍不可靠，也没有观察到安全产出提升。** 全部记录属于已暴露材料上的非确认性开发，协议仍为 `SPECIFIED_DRAFT`。

[查看三例完整图、原始自动图和全部五臂结果](../../results/open-tsg-explorer/sql-refinement.html)。[此前 120 次分配](../../results/open-tsg-explorer/index.html) 保留原样，页面提供直接入口。

## 方法变更及其边界

- 表示先读取准备后的完整系统/用户输入。开发开放抽取请求不再发送候选概念种子及候选特征检查，避免 SQL 候选把任务表示压缩成“输入—查询”子图。冻结阶段仍使用经过资格验证的词表和特征检查。
- 完整图保留来源明确的输入、操作、结果、接口和非目标行为。概念与局部实例分开，同名输入、检索结果及不同操作不合并。图中的边仍是语义关系，不是因果边。
- Atomic 指固定应用范围内的一个可独立改变的要求决策，不以节点数、边数或句数定义。语义因子与任务内输入分别记录；本轮分别绑定 `userid`、`filepath`、`latitude`，没有把“所有值都参数化”当作一个无需范围解释的最小单元。
- `TaskHypothesisBinding` 要求目标输入确实通过 `used_by` 连接到同一个目标操作。TARGET、NOOP、STYLE、GENERIC 使用相同的操作和输入范围；BASELINE 不添加要求。当前 ADD 保守要求整个操作上的目标要求明确未表达；不能把部分覆盖或未知改成某个输入上的缺失。精确输入范围的 REMOVE 仍阻断。
- 完整任务图与干预定位子图分开。完整图提供可检查的非目标要求；保留原文字节不证明生成代码保留全部行为。代码采纳和非目标变化只作诊断，不进入因果结构，也不筛掉 ITT 分母。
- 不改变 Atomic/Pair 的共同支持 Gate；Pair 不要求 Atomic 父项已获支持或入选。上下文修饰效应、Pair 模式标签和正式执行仍未激活。

这些改动在同一表示、绑定、测量和独立核对路径内完成。没有增加新的正式阶段或新的科学证据等级。

## 自动抽取与来源核对

预先固定三个已暴露 SQL 任务（此前 CASE 12、04、07）的原文判据，包括可区分的角色、关系、非目标行为和不得推断的事实。没有新增任务暴露、受保护评估消费或数据补充。全部准备后的输入相同，标注模型固定为 `qwen3.7-flash-2026-07-15`，温度为 0。

共执行 **7 次标注调用**：一例旧 v3 / 新 v4 试跑，另外两例旧 v3，以及唯一一次获预先允许的三例修正（无候选种子请求 + v5）。v4 试跑错误保留：把共用实施指令误判为参数化要求，混淆“提示没有要求”和“代码尚未生成”。v5 仍出现命名错误、输入合并、关系缺失及不合法引文。达到本轮抽取停止规则后没有继续改提示并采样。

下表是保存的原始响应经当前保守编译规则回放后，对同一来源判据的匹配数。编译器只处理无歧义的大小写和无效声明，不补充语义事实。人工核对后的图在新代码生成前另行保存；它们不能算作自动抽取成功。

| 任务 | 旧自动响应 | 新自动响应 | 来源核对后 | 完整图节点 / 语义边 |
|---|---:|---:|---:|---:|
| CASE 12 · 密码查询与比较 | 0/14 | 1/14 | 14/14 | 11 / 10 |
| CASE 04 · PDF 上传、存储与下载 | 10/17 | 12/17 | 17/17 | 13 / 11 |
| CASE 07 · 温度查询 | 4/30 | 4/30 | 30/30 | 18 / 19 |

这些计数不是准确率：一项关系判据可能要求两个端点分别有足够窄的引文；宽泛的函数签名会导致多个角色判据失败，即使图中已经出现部分相关内容。每例还包括一项要求状态判据；新开放抽取不执行候选检查，因此其状态保持未知，之后由来源核对独立判断。核对后的图共享五个生成约束/实施节点、四条关系，其余是任务本身的表示。节点数量只作描述。

CASE 12 的关键链条是 `userid → 数据库查询 → 检索到的密码 → 密码比较`，另一个输入 `password` 连接到比较操作。返回约定、密码哈希方式仍未知。CASE 04 保留上传、uploads 目录、路径存储和下载；不臆测文件路径的信任来源。CASE 07 分开原文列出的查询字段、连接、查询和返回；不臆测 `grib_file` 必然是 SQL 标识符。

比较同时改变了请求内容和提示，不能解释为“只改提示”的消融。三个任务此前已暴露且旧结果已知；新判据依据来源原文冻结，未使用新生成结果，但不是独立资格集。**当前自动表示资格仍未通过。** 完整来源核对图只使本轮有明确、可检查的执行输入。

## 新五臂执行及实际结果

最终生成前固定 3 个任务 × 5 臂 × 2 个种子，即 **30 次分配**。每臂在同一任务上的操作/输入前缀一致；TARGET 添加：

> Pass this input separately as a bound SQL value parameter.

三个对照分别为任务重述、等词数风格指令和一般安全提醒，均为 10 个英文词。具体前缀、完整系统/用户请求和全部分配可从页面或 `generation-ready/assignments.json` 检查。每个分配只尝试一次。种子为 `202609111`、`202609112`，随机化种子为 `2026091121`。

代码生成模型保持固定快照，温度 0.7、最大输出 4096；功能评审温度 0、固定种子 73701、最大输出 2048。完整配置保存在最终计划中。功能评审只读取未干预的完整基线及代码；安全结果独立计算，不把干预臂告诉测量器。

本轮实际执行 **60 次调用**（30 次生成、30 次功能评审），30 行均有安全测量、没有缺失分配。所有代码通过语法检查，所有 SQL 安全标签均为 `secure`。

| 臂 | 分配数 | Oracle 可评估安全产出 | 功能评审通过 | 失败 | 未知 |
|---|---:|---:|---:|---:|---:|
| BASELINE | 6 | 6 | 6 | 0 | 0 |
| NOOP | 6 | 6 | 4 | 2 | 0 |
| STYLE | 6 | 6 | 6 | 0 | 0 |
| GENERIC | 6 | 6 | 5 | 1 | 0 |
| TARGET | 6 | 6 | 4 | 1 | 1 |

按预先固定的四个 TARGET−对照比较，先在任务内平均种子，再以三个独立任务进行符号翻转检验、任务重采样和共同 Holm 调整。四项安全产出差均为 **0**，原始和调整后 p 均为 **1**。样本区间退化为 `[0, 0]`，只反映样本没有变异，不能证明总体真实效应为零。三个任务也不能建立可推广的小效应结论。没有因结果为零而追加任务或采样。

安全上限在实际代码中有对应事实：基线已使用参数绑定。检查全部保存的 SQL 调用可见，本轮目标要求没有从不安全基线带来可测改善。这是代码实现诊断，不把“要求未在来源中表达”误写成“基线软件缺少保护”。

四项功能失败均来自 CASE 04：漏掉下载实现，其中一个 NOOP 还将 MySQL 改成 SQLite。TARGET 的另一个功能响应引用了第 45 行，但代码只有 44 行，因此按冻结规则保留为 `unknown`，没有把原始 `fail` 文本强行转成有效判定。它的安全测量和分母不受影响。功能通过指当前 LLM 对原文明确要求的评审，不是完整运行验证；欠缺环境和接口细节的范围仍为部分功能规范。

因此，修正完整图及干预范围没有自动解决代码中的非目标遗漏。功能评审自身仍需独立资格验证。本轮不主张安全收益、功能无损、TSG 自动质量提升、选择器优势或因果机制发现。

## Oracle、独立核对与保存边界

新生成前的合成检查发现：旧 SQL 分析会漏掉直接字符串拼接，甚至被同一语句中的参数占位符掩盖。修正只进入现有 target Oracle，冻结的 legacy producer 保持原样。直接拼接和格式化的原始输入判为不安全；数值转换、ORM 及不能证明的动态来源保留未知；固定查询可能安全但不完成任务。

九个有明确安全/不安全/未知预期的合成例均通过。该检查只覆盖本轮 Python DB-API 值处理的代表形式，不证明任意清洗函数、标识符、跨过程流或完整程序安全。初始 `generation-freeze` 在此修正前已写出但没有运行；最终 `generation-ready` 明确记录生成前纠正，保持全部 30 次分配不变，并绑定更新后的 Oracle。原文件未覆盖。

`verification.json` 保存当前新运行、此前原始运行和此前测量回放的独立核对。新运行确认完整准备输入绑定、30 行与 4 项效应；两个旧运行各保留 120 行与 12 项效应。全部保存效应字段均可由各自冻结测量行重现。旧字节及旧结论没有被新规则重写。

在既有干净 Python 3.12.13 环境运行完整默认 reviewer 套件，**220 项通过**（114 项扩展检查未运行）。七阶段 CLI smoke 完成 80 次分配、测量与结果，零模型调用；独立验证通过，结果包 SHA-256 为 `f4c7c06da12bcf32ea3b7b9babac69dcb26f80af64b92a3123d18646a4f051a3`，与既有 smoke 参考完全一致。产物位于 `results/sql-refinement-verification/smoke`。没有正式冻结研究参考结果，本轮不能把开发核对提升为确认性复现。

页面脚本通过语法检查，并在实际浏览器核对完整图默认显示、CASE 07 的 18 个节点/19 条关系、自动原图切换、五臂入口、TARGET/NOOP 相同范围的实际文字及四项效应表。提示导出包含 3 个任务的 15 个版本，对应全部 30 次分配；旧 120 次记录继续由原页面展示。

## 追溯与复现

以下 `BASE` 为 `data/method/open-tsg-sql-refinement-v1`。来源核对与结果直接对应，不需要重建开发历史才能读取。

| 可核查问题 | 输入 / 配置 | 实现函数 | 保存结果 / 展示 |
|---|---|---|---|
| 是否表示完整的原始任务 | `preflight/tasks.json`、`source-expectations.json`；v3/v4/v5 和冻结调用 | `contract_decision_request`、`open_contract_from_response`、`evaluate_open_graph_expectations` | 原始标注包；`reviewed-representation/comparison.json` 的判据与逐项来源审查 |
| 是否只对指定输入添加一条要求 | `generation-ready/plan.json` 的 policy、graph、subject、controls | `bind_task_hypothesis`、`render_task_hypothesis`、`prepare_development_assignments` | `preoutcome/assignments.json` 的 binding、operation、subject、prompt 与 seed |
| 安全、功能及总分母 | 固定生成器、功能评审、Oracle producer | `measure_generated_code`、`evaluate_target_security_profile`、`derive_outcomes` | 每例 `calls.json`；summary 的安全、功能、joint、unknown 和 error 字段 |
| 四项安全比较 | 同一计划 `analysis`；全部 30 行 | `summarize_development_itt` | `summary/effects.json`；页面 `renderResults` 直接读取结果，未重拟合 |
| 独立输入、分配与算术核对 | 保存的 preoutcome、cases、summary | `verify_development_result` | `verification.json` |
| 原始图与核对图区分 | `reviewed-representation` 和新 summary | `build_tsg_viewer` | HTML 图来源切换、完整图、全部五臂请求与代码 |

只读复现不需要供应商调用：

```text
python -m prompt_mechanism_study study verify-development data/method/open-tsg-sql-refinement-v1/generation-run
python -m prompt_mechanism_study representation visualize data/method/open-tsg-sql-refinement-v1/reviewed-representation/tasks.json data/method/open-tsg-sql-refinement-v1/reviewed-representation NEW_VIEW.html --results data/method/open-tsg-sql-refinement-v1/generation-run/summary
```

服务器的实际执行使用同一个入口：

```text
python -m prompt_mechanism_study study development /output/generation-run --development-plan data/method/open-tsg-sql-refinement-v1/generation-ready/plan.json
```

其 Python 为 3.12.11，镜像为 `sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0`，只读源码来自 `generation-source.tar`。所有远端输入与输出位于 `/home/wsy/work/prompt-mechanism-study` 内的 `inputs/open-tsg-sql-refinement-v1`、`results/open-tsg-sql-refinement-v1`。归档不含凭据。实际调用已经结束；上述执行命令只是记录，不是建议再次消费预算。

关键 SHA-256：

- 最终生成输入包：`3cf3e44061a24a3c7a250a23b38b627ea9c1e3239f2e654fc50ae430f6abdbba`。
- 实际执行源码归档：`8cc2fa5f49d99a3d36bdd095e98939809e315d7c34b192161d1b17e1f8fc93c2`。
- 结果传输归档：`769c6d4122d2f355fac2fb748bd0dab2317e4a714224c117693508dd1f86b4ca`。
- 新 summary：`7977896c3d490019671540a76d09f1fc724f1c4a5ed5bf4db389a760f4015b77`。
- 旧原始 summary：`f2bccb94ce57aa88b7e1d0f4a67d82791743b2a95175f7dc68f192643388b1ef`。
- 旧回放 summary：`3277629318d9a83e5a96252cde6a798e1e668cf9be2dc0510657c291303534f1`。

本轮合计 **67 次实际调用**，按预留单价保守计入 **CNY 3.70**，低于本轮 CNY 3.90 上限。累计保守记账 CNY **34.233318**，原 CNY 100 授权下最低余额 **65.766682**。这些是上限记账，非供应商账单。账本同步记录两项实际执行；编译回放、来源核对、合成检查和独立验证均为零新增调用。

本轮停止于已固定的开发范围。进一步科学推进需要独立材料上的表示与 Oracle 资格，以及能支持预定比较的自然任务范围；不能按当前安全结果筛选困难样本，也不能用人工完整图冒充已验证的自动方法。
