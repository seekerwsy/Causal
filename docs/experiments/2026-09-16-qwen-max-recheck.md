# Qwen Max：六题完整复测

已执行、完成来源审查并精确离线重放。**六份源图和完整输出均通过：6/6；图参考 175/175，综合参考 195/195。** 所有额外断言均通过作者的原文核验，未发现错误或未经证实的确定性最终状态。可用参考范围为 13 个。这是一轮开发复测，不是独立资格认证或总体准确率估计。

| 原始题号与任务 | 图参考 | 综合参考 | 调用数 | 保守费用（元） |
|---|---:|---:|---:|---:|
| 1 密码查询 | 21/21 | 22/22 | 5 | 1.170840 |
| 2 PDF 操作 | 24/24 | 25/25 | 4 | 1.005036 |
| 3 温度查询 | 44/44 | 51/51 | 5 | 1.698228 |
| 4 双查询 | 26/26 | 30/30 | 4 | 0.988200 |
| 5 safe/raw | 37/37 | 40/40 | 4 | 1.112280 |
| 6 条件原子要求 | 23/23 | 27/27 | 4 | 0.739080 |
| 合计 | 175/175 | 195/195 | 26 | 6.713664 |

密码题的一次修复删除了签名到导入模块的错误绑定，同时保留 userid 的数据值角色。温度题保留了收到请求、提取字段和查询结果之间的对象关系；修复将 grib_file 留为未知角色，没有误判来源不完整。PDF 保留下载定位角色、PDF 结果和 MySQL 资源类型。双查询各自产生独立结果，并返回这两个对象。safe/raw 的三个要求分别绑定正确条件；最后一题将参数绑定和最多 10 个字符拆为两个完整要求，共同保留外部请求条件。

18 个原始类型回答全部符合当前规则。最终 62 个范围状态中，43 个未决、9 个要求未表达、6 个不适用、4 个要求存在。原始模型回答并非全对：safe/raw 和条件原子题各有一个无条件参数绑定负面回答，被既有覆盖检查阻止；条件原子题的无条件长度范围也因类型域未确定而保持未决，没有变成缺失要求的断言。因此，通过的是包含验证与有限修复的完整流程，不能宣称模型每次原始输出都正确。

模型仍为 `qwen3.7-max-2026-05-20`，启用思考、思考额度 4096、总输出上限 8192，temperature 0、top_p 1、seed 2026091202。完整复用此前通过六题集成的源码、提示、模型设置及逐题参考；图构建、一次全面审查、最多一次语义修复、独立范围判断保持不变。没有修改代码或增加测试，复用原有 19 项干净环境验证；26 次实际请求、响应和最终结果全部精确重放。请求均返回指定模型并正常结束。

用户先写“追加3预算”，在前两题运行期间更正为“是30元预算”。因此保留已启动的前两题，再按原顺序执行其余四题；六个任务恰好各运行一次，没有依据新结果替换、遗漏或重复任务。沿用三个已暴露自然任务和三个合成控制题，没有新增任务曝光。两段均使用同一个入口 `scripts/run_tsg_development.py` 和原候选源码；这次六题复测跨越预算更正，不等同于完成预设的三轮稳定性验证。

预算只追加 **30 元**：先记入的 3 元加上更正差额 27 元，没有追加成 33 元。原余额 1.259370 元，加 30 元，减本轮 6.713664 元，现剩 **24.545706 元**。前两题使用 9 次调用、2.175876 元，后四题使用 17 次调用、4.537788 元。按[官方北京原价](https://help.aliyun.com/zh/model-studio/qwen3-7-max)输入 12 元/百万 token、输出 36 元/百万 token 保守计账，不计缓存优惠；这是授权记账余额，不是供应商钱包查询。本轮付费调用已经结束。

## 复现与解释边界

- 前两题：[冻结计划](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-two-recheck/inputs/plan.json)、[结果汇总](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-two-recheck/analysis/summary.json)、[全部断言审查](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-two-recheck/analysis/source-review.json)。
- 后四题：[冻结计划](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-remaining-four/inputs/plan.json)、[结果汇总](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-remaining-four/analysis/summary.json)、[全部断言审查](../../data/method/open-tsg-scope-development-v1/qwen-max-funded-remaining-four/analysis/source-review.json)。
- 表格按原始题号连接两段 `analysis/case-results.json`；调用数和费用取同任务实际调用之和。整轮指标为两份 `analysis/summary.json` 相应字段的和，原始状态分布来自两段最终 contract，未重评旧结果。
- 每段的 `execution-source.tar.gz`、`results.tar.gz`、`analysis/reproduction.json` 保留实际源码、输出和离线复现过程。默认入口和方法没有增加分支。

在这套当前流程上，Qwen Max 再次完成六题验收，表现好于此前 DeepSeek Flash / Pro 检查中出现的角色、完整性和结果身份问题。但 Qwen 使用思考模式和部分原生 schema 约束，DeepSeek 对比配置不同，且都是已暴露开发材料，不能推断一般模型能力排名。稳定性重复与未参与调试的自然任务验证仍未完成，正式协议保持 `SPECIFIED_DRAFT`。

后续进展：同一候选已完成另行冻结的[三轮稳定性检查](2026-09-16-qwen-max-stability.md)，18/18 通过。本记录的单轮结果、费用和输入保持原样，未作为三轮之一复用。
