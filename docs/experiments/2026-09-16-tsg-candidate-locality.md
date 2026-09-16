# TSG 组合结构与候选局部性修订

本轮已完成表示、候选接口和开发评分修订。离线边界通过；一次真实图书任务成功构图，但保留关键语义错误，按预定规则停止，未扩大到三任务。协议仍为 `SPECIFIED_DRAFT`，没有独立资格或正式研究结论。

## 实施了什么

1. 要求保存 `atom / and / or / not / opaque` 及成员引用。合取叶子继承条件；替代和复合否定的成员不会被自动当成独立义务，也不能被误判为未表达。下游只读取既有结构。
2. 每个来源片段提交有原文依据的影响声明；同一次审核检查局部／全局／未知影响。已知关系只提供影响下界，不能凭缺边判无关。首轮只按操作隔离未知。
3. 分开表示要求条件、操作执行条件，以及独立但不限制执行的 `context_for`。缺少独立上下文的条件候选保留未确定，不通过虚构执行条件放行。
4. 候选评分结合固定来源依赖和断言影响。未定位错误仍全局阻断；相关节点、参与关系、组合祖先和共同条件不能被“无关”标签绕过。报告正确性、找回率、覆盖、额外输出与整图诊断。
5. 保存审核前记录、合同和图，按固定来源含义比较审核变化。错误变未知不计为正确修复。

保持一条现有入口 `scripts/run_tsg_development.py`，通常三次、最多五次调用；没有新审核者或重试系列。语义原子化与独立编辑可行性仍分别判断。

## 验证及真实结果

隔离 Python 3.12.13 环境中，现有完整套件 **110 项通过**，测试总数未增加。六类新边界放入现有抽取、候选和评分测试。付费冻结后另补了一处评分下界：与操作直接相连的要求／参与者及组合祖先也必须计入依赖；受影响的 16 项测试通过。该最后修正仅离线验证，不回写冻结运行或原评分。

真实使用 `qwen3.7-max-2026-05-20`，保留原模型设置。输入仅为已暴露的 SQLite 图书查询任务，调用前冻结实现、四个候选参考查询、七个语义比较单位及预算。上限五次调用／四元。

| 结果 | 本轮观察 |
|---|---|
| 模型调用 | 3 次：记录、审核、范围判断；没有机械修复或语义补丁 |
| 构图 | 1/1 完成；JSON 和结构编译均成功 |
| 关键语义 | 返回分支条件未结构化；返回要求扩到连接／查询操作；输入假设缺少对象绑定；异常条件只保留在文字中 |
| 参与关系 | 连接操作把已有数据库资源当成其产生的结果，混淆数据库资源与连接句柄 |
| 模型审核 | 13 条记录全部批准；前后原始记录完全相同 |
| 作者来源核查 | 7 个固定含义单位中 2 个正确、5 个有结构或范围错误，前后不变；净纠错 0 |
| 可用于干预的比较 | 0；原始范围状态不能替代非目标行为与范围保留检查 |
| 成本 | 0.824160 元；剩余授权账本 14.181239 元，不是已核实账户余额 |

上述核查由开发作者完成，不是外部盲审。最终 117 条断言全部留有来源判断，其中 99 条支持、16 条不支持、2 条未确定。这些相互依赖的断言不能当成独立样本估计准确率。

## 参考问题与模型问题分开

冻结参考的自动定位有两个缺陷：`book_id` 只锚定函数签名，未纳入合法的 `book ID` 提及；“数据库”却锚定文件路径，匹配到路径节点，漏掉另行表示的 SQLite 数据库资源。因此原始 **2/9 来源检查、四个参考范围均未自动对齐** 不能解释为只保留了两项正确含义，也不能直接用来估计候选覆盖。

原始参考与分数原样保留，`source-diagnostics.json` 单列作者逐项核对：十字符限制／book ID 为 `absent`，两项数据库资源查询为 `not_applicable`，SQL 参数绑定／book ID 为 `unresolved`。前三项状态本身有来源支持，但完整依赖不满足可用要求。最后一项涉及“SQLite 表查询是否已足以确立 SQL 适用前提”的参考口径，仍标记争议，不将未知算作错误确定判断。

参考缺陷不能消除图里的真实错误：返回条件没有条件节点，两个返回要求的 `scope_kind=task` 确实被编译成对连接、查询和返回三个操作的约束。这是可从记录到图直接核实的语义范围问题。

本任务只生成了原子声明，重要来源影响均为全局，也没有局部未知。因此，复合结构和局部隔离的程序行为有离线证据，本次自然任务没有验证其稳定抽取收益。审核净收益为零也只描述这一次运行，不能推断所有审核均无效。

## 保留结果与复现

材料根目录为 `data/method/open-tsg-scope-development-v1/natural-transfer/requirement-composition-locality/`：

- `inputs/`：调用前计划、输入、模型配置、来源与候选参考、离线检查记录。
- `execution-source.tar.gz`：实际执行源码；SHA-256 `056efb8f330c532796233034e9b1a6437a7e94b0f97f2f0d2490a6c95da5ad30`。
- `server-results/comparison/`：三次完整请求／响应、审核前图、最终图和成本。
- `analysis/`：冻结参考评分、作者来源核查、参考缺陷、审核转移及成本；`closure/`：一次性预算结算。

服务端工作目录仍在 `/home/wsy/work/prompt-mechanism-study`，环境镜像为 `sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0`，实际启动命令保存在 `launch.sh`。已使用归档实现及原始响应完成精确 HTTP 请求和全部结果／报告重放，重放没有联网或再次记账。

下面的最小离线构图重放只读取已保存响应。先解压执行源码到本批 `replay-source`，将 `PYTHONPATH` 指向其中的 `src`，在仓库根目录使用 Python 3.12 执行：

```python
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.prompt_contract_extract import _attempt_task_contract
from prompt_mechanism_study.prompt_contract import task_context_contract_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record

b = Path('data/method/open-tsg-scope-development-v1/natural-transfer/requirement-composition-locality')
calls = iter(read_json(p) for p in sorted((b/'server-results/comparison/calls').glob('*/call.json')))
def retained(request, config, prompt):
    saved = next(calls)
    assert request == saved['request'] and saved['error'] is None
    return saved['response_text'].encode()
task = read_json(b/'inputs/cases.json')[0]['task']
a = _attempt_task_contract(task, catalog=read_json(b/'inputs/catalog.json'),
    evaluator=read_json(b/'inputs/evaluators.json')['max'],
    annotator_prompt=read_json(b/'inputs/instructions.json')['stage_system_prompt'],
    review_status='development_exposed', provider=retained)
r = read_json(b/'server-results/comparison/summary/results.json')[0]
assert a.error_type is None and next(calls, None) is None
assert task_context_contract_record(a.contract) == r['contract']
assert prompt_tsg_record(a.graph) == r['graph']
```

## 本轮停止后的研究决定

此次修订解决了表示与下游使用混淆、全图一票否决等可确定的实现问题；没有证明自动语义抽取可靠。下一项工作应先固定语义等价的参考锚点及 SQL 适用口径，再针对“文字里有条件，但结构字段为空／范围错误”检查抽取和现有审核。继续增加审核次数或扩大模型调用，当前没有证据支持。自动图、人工审定图与扁平特征的结构价值比较仍未执行。
