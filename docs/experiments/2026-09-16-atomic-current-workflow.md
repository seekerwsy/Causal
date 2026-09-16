# 当前链路验证：自动构图、局部修正与 Atomic 编辑

本轮完成 **一次真实基线、一次改进复验和离线下游对照**。
全自动链路没有达到预定的单 API 因素目标；在真实基线记录上做两处开发者来源修正后，
既有候选草案与审定改写接口可以处理该因素。没有新增默认方法组件，也没有修改论文。

## 固定问题与执行范围

沿用上一轮已暴露的 pandoc 自然任务，固定因素为：
**不得将用户可控输入传入 `subprocess.run(..., shell=True)`。**
目标 REMOVE 应保留另一项 `os.system` 禁止及全部非目标功能，不要求代码变得不安全。

本次通过 `prepare_task_input` 准备实际系统消息、用户原文和 Python 语言，使用当前
`source_records.attempt_graph` 路径。模型为 `qwen3.7-max-2026-05-20`，沿用已有参数、
一次普通审核及至多一次机械修复／一次语义补丁。没有加入 reviewer。
本轮上限 10 次调用、5.50 元，来自既有授权；两次输入和代码均在各自调用前保存。
只使用一题开发材料，不接触保护集、不生成代码、不运行正式 Discovery/Confirmation。

初始词表为开放来源词表，没有预装候选查询。因此构图后返回 `NO_SOURCE_BOUND_SCOPES`
表示没有预装查询，不是适用性模型判了“不适用”。后续固定因素通过草案接口离线检查；
本轮没有声称执行自动候选发现、新归一化词表下的重新抽取或正式资格验证。

## 真实基线：能够构图，粒度不足

基线调用顺序为抽取、一次机械修复、普通审核、一次语义补丁，合计 **4 次／1.289772 元**。
机械修复处理来源覆盖记录的引用缺口；它不是安全要求的语义修复。

本次审核确实发现了文件不存在、转换失败两个缺失条件，补丁也将它们写进条件字段。
不能把本轮说成“审核从来不能发现条件丢失”。但最终仍保留两个复合记录并标为 atom：

| 记录 | 最终表示 | 对本轮比较的影响 |
| --- | --- | --- |
| 安全要求 | `os.system` 与 `subprocess.run(shell=True)` 两项禁止合在一条 | 无法直接提供预定的单 API 因素；下游不能自行选取其中一半 |
| 错误处理 | 失败时记录日志与不直接抛出其他异常合在一条，共用失败条件 | 两个义务的条件范围没有分别表达 |

安全要求此次已经引用完整句子，直接目标也是来源要求的 pandoc 转换操作，较早历史图的
片段引用／被禁止 API 操作误绑没有在这次基线重现。这些正确部分不能抵消粒度缺口。

如果把复合节点整体提交给草案／删除接口，机械草案可以进入待审核状态，删除会同时去掉
两项 API 禁止。这不是预定的单 API 干预，不能计为成功候选。它与修正后的因素意义不同，
因此不能按两组等价政策计算成功率或效应差。

## 改进复验：未通过，撤回提示修改

尝试只澄清现有抽取与审核提示中的“原子单位”：按分别成立的要求拆分，保留各自条件；
用非本题的例子区分“禁止 A 或 B”和“允许选择 A 或 B”。未改 schema、词表、模型、
输入、种子或审核次数。

复验第一次响应即返回 `finish_reason=length`，未生成可用图，后续审核／补丁没有执行。
提供方报告 8195 个 completion tokens，其中 4096 个 reasoning tokens；请求上限为 8192。
JSON 在来源影响表中途截断。原始响应完整保存，没有补齐 JSON 或将部分记录送入正式链路。

已完整返回的安全记录仍是复合 atom，这只能作为调试观察；不能冒充一次完成审核后的
语义失败评分，也不能推测未执行的审核会怎样处理它。复验未满足预定采纳门槛，
**提示修改已撤回，默认路径恢复原状；没有追加重试。** 截断调用按冻结规则保守记账
**1.800000 元**，并非核实的实际账单。

因此两种失败要分别报告：基线是可编译图的要求粒度问题，复验是输出交付失败，
本轮没有证明新提示提升了自动抽取质量。

## 离线局部对照：现有下游能够处理修正后的因素

在基线最终记录上，由 Codex 开发者给出局部来源判断和补丁，通过现有
`repair_request → apply_record_patch → compile_records` 验证，不增加提供方调用：

1. 将安全记录改为 `os.system` 禁止，新增完整 subprocess 禁止。
2. 将错误处理记录改为带失败条件的日志要求，新增不直接抛出其他异常的独立要求。

只替换 **2 个原记录、增加 2 个原子记录**，其他原记录保持不变。来源影响声明没有缩小。
这是真实自动输出上的作者修正，不是另一份从头制作的“理想图”，也不是独立人工资格审定。

修正后，固定因素可以进入 `PENDING_SEMANTIC_REVIEW` 草案。
原生整段删除因共享证据重叠而拒绝；已有审定改写接口则能只删除 API 列举中的 subprocess 项：

```text
Security Policy: don't pass user-controlled input to `os.system` that can cause arbitrary code execution.
```

对实际输出另行核对：文本恰好等于原文删除
`` or `subprocess.run` with `shell=True` ``，系统消息、语言和其余原文不变；
修正图中 **17 个非目标来源事实和 15 条关系** 保持不变。ADD 因来源明确表达要求而被拒绝。
记录位置在删除后会变化，诊断驱动现在读取显式的来源到变体节点映射，不把局部编号相同
当成含义相同；该映射仍须通过既有语义身份、引用和关系投影检查。

改写、局部状态和固定候选探针由开发者提供，不能报告为全自动成功。
原生来源词表下的渲染对照不冒充新候选词表的自动重新抽取。
候选仍待语义审定，干预仍待独立资格；没有生成结果、安全效果或功能成功率。

## 决定、费用与复现

本轮支持的窄结论是：**这一固定因素的下游表达／改写接口可行，当前自动记录的粒度
仍是直接障碍。** 不支持总体稳定性、图结构发现价值或提示改进有效性。

当前不再追加审核措辞迭代。下一项有研究价值的工作是用这项明确审定的因素，检查
对照措辞和独立安全／功能测量是否能支持一个有界生成比较，同时保留自动图的失败对照。
作者修正与全自动结果须始终分列；本轮不改变正式资格要求。

共 **5 次提供方调用，保守记账 3.089772 元**；授权账本剩余 **3.888119 元**，
不是核实的账户余额。没有新自然任务暴露、保护集消耗或代码生成调用。
完整测试 101 项通过；恢复默认提示后 23 项相关测试通过；没有新增默认测试。

材料根目录：
[`current-workflow`](../../data/method/atomic-candidate-interface-development-v1/current-workflow/analysis/summary.json)。
`inputs/`、`recheck/inputs/` 保存前置计划；两个 `execution-source.tar.gz` 保存各自执行代码，
两个 `results.tar.gz` 保存原始请求／响应和结果。精确摘要见 `analysis/summary.json`。
`local-correction/` 保存作者判断、最小补丁和前后记录，`local-correction-results/` 保存实际编辑。
`closure/` 保存本轮一次性结算。源码和凭据没有混装，凭据始终留在服务器。

从仓库根目录运行以下命令，使用 Python 3.12 和已声明依赖。前两条重放冻结代码并替换
网络层，逐字核对实际 HTTP 请求、结果和费用，**不会调用提供方**；第三条重放离线编辑：

```text
python data/method/atomic-candidate-interface-development-v1/current-workflow/replay.py data/method/atomic-candidate-interface-development-v1/current-workflow
python data/method/atomic-candidate-interface-development-v1/current-workflow/replay.py data/method/atomic-candidate-interface-development-v1/current-workflow/recheck
python data/method/atomic-candidate-interface-development-v1/reproduce.py NEW_OUTPUT_DIRECTORY --inputs data/method/atomic-candidate-interface-development-v1/current-workflow/local-correction/inputs.json
```

两批共 5 次请求及失败均已精确重放；本轮离线改写和上一轮 shell-removal 结果也逐字重现。
付费 `launch.sh` 仅保留作执行记录，复核应运行上面的离线命令。
