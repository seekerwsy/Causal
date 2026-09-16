# 本地模型、多种子开发与比例适当的表示检查

状态：已完成已授权的有界开发阶段及独立结果复核；不是正式 Discovery 或 Confirmation。
本阶段回答三个问题：图检查是否区分真正缺失与证据歧义；生成结果有多大种子波动；
下一阶段需要多少独立任务，以及怎样公平检验 TSG 的结构价值。

两个模型各完成 600 次预定生成尝试，共用 12 个独立任务。32B 命令要求相对原始基线
及任务重述均提高 7.5 个百分点；7B 命令比较因七次生成失败保留为阻塞。阶段共 24 项
比较，20 项可估计的 Holm 调整 p 值均为 1，另四项阻塞，不能作确认性结论。两模型
SQL 相对原始基线均为零；路径测量几乎全部未知。图检查更能区分问题类型，但自动
抽取与功能评审仍未通过正式资格验证。

可直接浏览[两模型总览](../../results/open-tsg-explorer/local-models.html)、
[7B 全部分配](../../results/open-tsg-explorer/local-7b.html)和
[32B 全部分配](../../results/open-tsg-explorer/local-32b.html)。

## 在新结果之前固定的范围

- 沿用此前已暴露且经来源核对可执行 ADD 的 12 个任务，SQL 3、命令执行 8、路径 1。
  SQL 使用最近一轮的单输入要求及完整来源核对图；其他要求保留明确的操作范围。
  不根据任一模型的新安全结果挑选、替换任务或改变要求。
- 在表示前准备完整系统/用户输入，填入 Python；旧来源图的事实在新的完整输入上
  重新定位和编译。共用指令单独表示。来源核对由当前助手完成，不称独立真人金标准。
  SQL 三项使用完整来源图；其他九项保留来源核对的实验子图，并未在本轮完成新的
  自动完整图抽取或证明全任务语义覆盖。
- 生成模型固定为服务器已有 Qwen2.5-Coder-7B-Instruct 和 32B-Instruct，BF16，
  vLLM 0.18.0。温度 0.7、top_p 1、最多 4096 输出 tokens，每任务每臂 10 个预定种子。
  两模型共 1,200 次代码生成分配，每分配一次尝试；失败原样保留。
- 两模型的功能结果统一由固定的本地 Qwen2.5-Coder-32B-Instruct 评审，温度 0，
  固定评审种子，使用既有按原始任务评审的提示。SQL/命令/路径安全结果仍来自同一个
  冻结 AST Oracle。功能未知不会抹掉已独立测得的安全结果。
- 完整五臂为 BASELINE、NOOP、STYLE、GENERIC、TARGET。先在每个任务、每个臂内
  平均种子，再按独立任务比较。每模型保留原来的 12 项描述性比较；阶段总表另将
  两模型的全部 24 项比较共同作 Holm 调整。缺失比较保留在检验族中。
- 显著性不作开发验收条件。报告总分母、效应、种子波动、测量未知和功能遗漏。
  不按新结果改变生成模型、采样数量、对照、Oracle 或任务总体。
- 最小接口试跑、功能评审检查和 Oracle 检查使用合成材料或已经暴露的开发材料，
  与 1,200 次分配分开记录。它们不构成正式独立资格验证。

## 表示检查的修正

同一个检查函数仍以原文锚点、通用节点角色、关系和明确需求状态为输入，但现在分别
输出 PASS、MISSING、AMBIGUOUS_SOURCE_BINDING、BLOCKED_ENDPOINT_BINDING、
UNASSESSED_FEATURE 等状态。端点歧义不会再连带计作关系语义错误；开放抽取未进行的
候选状态判断不会计成错误的“缺失要求”。未知也不会被改写成 absent。

完整图覆盖与该比较的关键绑定分开。关键检查必须明确列出；未列出时状态为
NOT_SPECIFIED。即使关键机械检查全部通过，也仍要求来源语义核对，不能自动取得
正式执行资格。原有冻结检查记录保留，新的离线诊断另存，不重写旧分数。

新的 SQL 自动图诊断如下；分母是预设机械检查项，不是语义准确率。端点阻塞表示其
关系暂时不可判断，不另算一次已证实的关系语义错误。

| 图 | PASS | MISSING | 锚点歧义 | 端点阻塞 | 未评估特征 | 角色合并 | 关键绑定 |
|---|---:|---:|---:|---:|---:|---:|---|
| CASE 12 自动图 | 1 | 1 | 4 | 8 | 0 | 0 | 需要来源核对 |
| CASE 04 自动图 | 12 | 1 | 0 | 3 | 1 | 0 | 机械通过，仍须语义核对 |
| CASE 07 自动图 | 4 | 9 | 0 | 15 | 1 | 1 | 需要来源核对 |

来源核对图分别为 14/14、17/17、30/30 项通过。这验证了检查器可区分缺失、歧义和
未评估，不能证明自动抽取改善，也不能证明助手整理图的独立语义准确性。本阶段没有
新的抽取模型调用。

## 接口试跑与功能限制

1. 7B 的三个合成接口请求返回有效 JSON；一个重复种子对得到相同字节。这是最小
   接口检查，不是后端确定性或采样独立性的证明。
2. 两模型各一个已暴露 SQL 任务、五臂各一次，共 10 次代码生成，均完成测量。
   对应 10 次功能请求均因 vLLM 的结构化输出后端不支持 `uniqueItems` 返回 HTTP 400。
   修正只从传输 schema 去掉这个不支持的关键字；本地验证仍检查重复和越界证据行。
   这 10 次失败请求以及独立安全结果完整保存，不作为主运行样本。
3. 修正传输后的九个 SQL/命令/路径合成功能例中，七个符合预期。SQL 和路径各一个
   未知 helper 案例被误判失败。在主运行前仅澄清一次提示，并补三个“helper 不透明但
   可见代码已证明失败”的例子；12 例均为有效响应，10 个符合预期，原两例仍误判。
   这不是 7/9 到 10/12 的准确率提升，新增三例不能修复原有错误，也不是独立留出资格集。

到此停止功能提示调试，固定该评审器完成开发批次，并明确禁止功能保持或准确联合
成功的科学结论。功能结果作原始辅助诊断；安全测量仍由独立冻结 Oracle 完成。
前置检查共 44 次本地请求，包含 10 次试跑生成和失败的功能请求；不混入主运行分母。

## 实际冻结配置

| 项目 | 固定值 |
|---|---|
| Python / 运行时 | 3.12.13；PyTorch 2.10.0+cu128；vLLM 0.18.0 |
| 权重 | 既有 Qwen2.5-Coder-7B-Instruct / 32B-Instruct，BF16，全部索引分片与配置逐文件 SHA-256 |
| 生成 | temperature 0.7，top_p 1，max_tokens 4096，单次尝试，timeout 600 秒 |
| 主种子 | 2026091201–2026091210；两模型、五臂共用同一预定集合 |
| 功能评审 | 固定 32B，temperature 0，seed 73701，max_tokens 1024；盲于臂和生成模型身份 |
| 服务 | 各一个 A800，tensor_parallel_size 1，max_model_len 8192，max_num_seqs 8，eager |
| 主程序 | 每模型 8 个工作线程；旧冻结源码独立保存，不在运行中修改 |
| 安全 Oracle | SQL `python.cwe89.sql_values.v1`；命令 `python.cwe78.function_parameter_subprocess.v2`；路径 `python.cwe22.path_confinement.v2` |

执行计划束 SHA-256：`b7dcc50b0e3ddccdcd3b5d394acc3c4bf3275b6da2a55055c78fbe6b4c53e765`。
执行源码压缩包：`c7ddff20af572e3b09c4941729868310080503ab31fb2c0719018a66a0759bcc`。
完整模型身份文件：`19e1085cc5100948235eaaba364508406795fb9fcf4e620088ed58357b99119e`。
每个模型、分片、tokenizer 的具体身份和完整服务命令在
`server-results/runtime/model-identities.json`、`launch-7b.json`、`launch-32b.json`。
原始权重从 `/home/ubuntu/RAID5/data/model_zoo/CodeLLMs` 只读加载。

生成返回未正常结束时，当前客户端保存请求和错误，但没有保留原始响应 envelope。
因此不能从这些记录证明具体是长度上限、哪种停止原因或哪段代码所致；报告只记录
可证实的失败，不把它解释为模型随机性，也不选择性重试。

## 验证

- 在包含 dev、selectors、languages 依赖的干净 Python 3.12 环境中，完整 reviewer
  套件 225 项通过、113 项未选择。之后增加跨模型汇总与 Prompt 导出完整性检查，
  其所在文件最终 26 项通过。
- 七阶段 CLI smoke 为 80 次合成分配、零外部调用；独立验证通过，结果束哈希仍是
  `f4c7c06da12bcf32ea3b7b9babac69dcb26f80af64b92a3123d18646a4f051a3`。
- 已保存的 SQL 30 次运行、原始 120 次运行及其 120 次测量重放均独立验证通过；
  原始失败与旧来源输入边界保留，没有按本轮规则重解释。
- 两份新的 600 次运行均经独立原始响应验证，准备输入、任务/臂/种子绑定、完整
  分配记账及保存统计通过；阶段 24 项 Holm、种子 MC 误差和语法诊断也从保存数据核对。
- 浏览器检查了总览、模型与要求切换、两模型详情页及 Prompt 导出；每模型保留
  60 个任务臂 Prompt 版本和全部 600 次分配。

这些测试验证实现与可复查性，不是 Oracle 准确率或因果效应证据。

## 结果与异常定位

| 指标 | 7B | 32B |
|---|---:|---:|
| 总分配 | 600 | 600 |
| 已取得测量 / 生成失败 | 593 / 7 | 600 / 0 |
| 代码有效 / 无效 | 517 / 76 | 550 / 50 |
| 安全 secure / insecure / unknown | 362 / 58 / 97 | 413 / 32 / 105 |
| 功能 pass / fail / unknown | 261 / 244 / 12 | 327 / 214 / 9 |
| 功能请求验证失败 | 0 | 1 |
| 完整任务臂格 / 其中产出随种子变化 | 53 / 31 | 60 / 22 |
| 主运行本地调用 | 1,117 | 1,150 |

安全和功能计数不含各模型的无效代码 not_run 与生成失败，完整分母仍是每模型 600。
这里没有检验两模型总体能力差异；所有计数均属于冻结任务与接口下的开发产出。

7B 的 600 次分配全部尝试，593 次取得测量，7 次返回未正常结束。测量包含 76 份
无效代码，因此共 517 次功能评审，合计 1,117 次本地请求。安全计数为 362 secure、
58 insecure、97 unknown、76 not_run，另有 7 次生成失败；功能计数为 261 pass、
244 fail、12 unknown、76 not_run，另有 7 次生成失败。功能计数不作准确率声明。

七次生成失败都在命令任务：BASELINE 1、NOOP 2、GENERIC 1、TARGET 3。它们使
7B 的四项命令对比按原计划阻塞。逐分配表保留所有失败；命令 TARGET 已测安全数为
52/80，BASELINE 为 41/80，但这些分子不能补齐缺失结果以获得新的完整效应估计。
SQL TARGET − BASELINE 为 0，TARGET − NOOP 为 −3.33 个百分点，TARGET − STYLE
为 +3.33 个百分点，TARGET − GENERIC 为 +30 个百分点；这些均只有三个独立任务。
路径 50 次均为 Oracle unknown；其可测安全产出差为零，不能说明真实安全效应为零。

76 份无效代码都与原始模型 JSON 的 code 字段逐字相同，且在独立 Python 解析中失败：
49 份 f-string 未闭合、11 份普通字符串未闭合，其余 16 份为其他语法错误。缺陷已经
存在于原始返回，未在解包或测量时删改。这里评价的是冻结 JSON 输出接口下的产出，
不能区分模型行为与受约束解码的各自贡献；本轮不切换格式、修补代码或选择性重跑。
无效代码仍是已测得的零 secure yield，不能与未取得结果的七次失败混为一类。

60 个任务臂格中，53 个有完整十次结果，31 个完整格的 secure yield 随种子变化
（SQL 7 格、命令 24 格）；另外七格保留为不完整。这个开发观察支持报告采样波动，
不将 600 次分配当成 600 个独立任务。

展示编号按先前 30 项已暴露来源清单恢复，不修改执行计划。导出的 ZIP 路径同时绑定
任务标识，避免来源子集编号重复造成覆盖。此修改仅影响导出与展示；原始运行结果保留。

32B 的 600 次分配全部取得测量，50 份代码无效。550 次功能请求中，一次 SQL GENERIC
评审返回重复证据行 `[47, 39, 47]`，本地验证拒绝该响应，功能保留 unknown，独立安全
结果保留 secure；没有选择性重评。该事件包含在表内的九次功能 unknown 中。
50 份语法错误也全部存在于原始 JSON 的 code 字段，并经独立 Python 解析确认：
24 份多余右花括号、11 份普通字符串未闭合、9 份 f-string 未闭合、4 份其他语法错误、
2 份左括号未闭合。两个模型的这些问题都不能仅归因于参数规模或采样随机性。

| 32B 安全产出差（百分点） | TARGET − BASELINE | TARGET − NOOP | TARGET − STYLE | TARGET − GENERIC |
|---|---:|---:|---:|---:|
| SQL，3 个任务 | 0.00 | +3.33 | +10.00 | +3.33 |
| 命令，8 个任务 | +7.50 | +7.50 | +3.75 | +15.00 |
| 路径，1 个任务 | 0.00 | 0.00 | 0.00 | 0.00 |

32B 命令 TARGET 为 60/80 secure，BASELINE 与 NOOP 均为 54/80。相对 BASELINE
的原始任务符号翻转 p 为 0.125，相对 NOOP 为 0.0625；跨模型 24 项 Holm 后均为 1。
相应种子 Monte Carlo 标准误为 4.25 和 3.33 个百分点，只描述这八个任务上的重复
采样误差，不能替代独立任务不确定性。即使边际任务 bootstrap 描述区间不含零，
也不能据此绕过完整比较族。7B 的四项命令比较虽然阻塞，仍占阶段检验族位置。

32B 路径 49 次 unknown、1 次代码无效；与 7B 的 50 次 unknown 一起，说明当前
这一个路径任务缺少可判定安全结果。它们的 secure yield 为零，既不是 100 次已证实
不安全，也不是已经证明路径要求无效。功能误判和自动表示质量缺口同样没有因本轮
重复采样而消失。下一步需要增加独立任务并补齐实际使用范围的资格检查。

## 调用、归档与资源收尾

主运行共 2,267 次本地请求：1,200 次生成和 1,067 次功能评审。另有前置检查 44 次，
本阶段合计 2,311 次本地请求、零云端请求，没有新增百炼费用。预定生成没有追加、
重试或任务替换；本轮代码只作解析与评审输入，没有作为程序执行。

两项运行已分别下载并验证压缩包 SHA-256：

- 7B：`3b252a987cb19920ccad0a97e3ceef4811d5cd22badd530f1ac712e5b970a031`。
- 32B：`8dc07279c01bcf503524a2acaa59de88029746a300e7c129ddc4dc3f8b8d9872`。

服务器归档为 `/home/wsy/work/prompt-mechanism-study/archive/local-llm-development-v1-20260911.tar.gz`，
SHA-256 `a937f0e0f28239a0cf64796031a0a72a4fb105769d96ec2ad8a53282ca03372e`，
逐项核对 3,877 个文件。输入与结果原位保留；确认归档后只移除本次两个可再生 vLLM
缓存。两项本次启动的模型服务均已停止并释放 GPU；其他用户进程和原有权重未改动。

## 可复核路径

研究输入和结果位于 `data/method/local-llm-development-v1`。代码继续使用既有
`study development` 与 `study verify-development` 入口；本地和云端模型共用同一个
chat 请求构造及响应验证函数。本地配置不携带百炼专有 thinking 参数或虚构云端凭据。
服务器的输入、运行记录和输出均在 `/home/wsy/work/prompt-mechanism-study` 下，
模型权重从既有模型目录只读加载。

两个主运行分别保存在 `server-results/run-7b` 和 `server-results/run-32b`。
相同任务、臂和种子在两个运行中可能具有相同 assignment_id；跨模型分析使用
`(model_id, assignment_id)`，不把它们当成重复记录删掉，也不当成 24 个独立任务。

| 内容 | 冻结输入 / 实现 | 结果字段或文件 |
|---|---|---|
| 本地请求与模型政策 | `execution-plans/plan-*.json`；`functional_judge.bailian_complete` 的本地 vLLM 分支 | 每 case 的 `calls.json`、运行 `report.json` 的 `live_provider_calls_by_kind` |
| 表示诊断 | 同一保存 SQL 图及其 expectations；`prompt_contract_qualification.evaluate_open_graph_expectations` | `representation-diagnostics/comparisons.json` 的 `check_status_counts`、`critical_scope_status` |
| 分配与独立测量 | `target_workflow.prepare_development_assignments`、`measurement.measure_generated_code`、冻结安全 producer | `preoutcome/assignments.json`、`summary/assignments.json` 的有效性、安全、功能及失败字段 |
| 每模型开发效应 | 冻结 `plan.analysis`；`inference.summarize_development_itt` | 运行 `summary/effects.json`；每模型 12 项 Holm |
| 多种子诊断 | 同一分配；`inference.summarize_development_sampling` | 运行 `summary/sampling.json` 的 cells 和 contrasts |
| 阶段两模型表 | 两份已验证 summary；`inference.summarize_development_models` | `analysis/effects.json`；每模型值另保留为 `per_model_adjusted_p_value`，主显示 24 项调整 |
| 表格和网页 | 本目录 `analysis.py`，调用现有导出器 `tsg_visualization.build_tsg_viewer` | `analysis/` 及 `results/open-tsg-explorer/local-models.html`、两模型详情页 |

零模型调用复核命令，在已安装 `.[dev,selectors,languages]` 的仓库环境中运行：

```text
python -m prompt_mechanism_study study verify-development data/method/local-llm-development-v1/server-results/run-7b
python -m prompt_mechanism_study study verify-development data/method/local-llm-development-v1/server-results/run-32b
python data/method/local-llm-development-v1/analysis.py --output results/local-model-reproduction --viewer-dir results/local-model-reproduction-view
```

复现输出目录应尚不存在。表格构建器核对每个模型的原始分配和安全/功能响应、固定
模型间任务坐标、联合 Holm 与原始数据重算的 MC 误差。`analysis/overview.json` 保存
执行计划、源码压缩包、模型身份、后续表格代码的精确哈希；后处理不覆盖运行摘要。

独立验证的运行 summary 束分别为
`409ec43fb76d816abd828567a81e4e4b71f48b58d9757b5ea1ac344b1faccaa2`（7B）与
`5b7da82c49930617f3f2de72e87457ae06edae5ef8b4c3932c0f6e68d02b34b0`（32B）。
阶段 `analysis/effects.json` 文件 SHA-256 为
`f16fcd8699e3bfbb2b42f67d7ed72218bf4e0c264cc820b19acfdb530d1bc66b`。

服务器上的原始生成命令（每模型一次，共 600 次分配；重新执行会消耗 GPU 时间）：

```text
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/inputs/local-llm-development-v1/source/src /home/wsy/miniconda3/envs/purp/bin/python -m prompt_mechanism_study study development OUTPUT --development-plan /home/wsy/work/prompt-mechanism-study/inputs/local-llm-development-v1/source/data/method/local-llm-development-v1/execution-plans/plan-7b.json
```

32B 对应 `plan-32b.json`；OUTPUT 使用该工作根下新的结果目录。两个本地服务需按
已保存的 `launch-*.json` 启动，并提供相同模型身份。再次生成不保证与保存响应逐字相同；
上述零调用路径才能精确重建本轮已观察到的表格。其不证明模型未来输出确定。

下一阶段的独立任务数量、预算算例、现有结构消融及独立表示研究提案见
[下一阶段设计](2026-09-11-next-study-design.md)。正态敏感性表不是正式功效门槛，
主协议仍要求分类请求模拟及实际任务支持上的 max-|T| 检查。协议仍为 SPECIFIED_DRAFT。
