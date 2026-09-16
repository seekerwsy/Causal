# 自然任务暴露的 TSG 词表限制

当前协议仍为 `SPECIFIED_DRAFT`。本轮是表示方法开发，不是正式资格验证或因果实验。

## 发现与处置

旧候选在固定六题上通过三轮、共 18/18 输出，但其事实词表也被冻结了。
新任务需要的事务提交、重定向、日期计算、代码执行和解压等含义，
没有合适的已有概念。仅改善 repair 无法让这些含义获得完整表示。
这是表示范围的限制，不能据此归因于模型能力，也不能把旧六题成功推广到自然任务。

先按元数据选定并登记八题，再查看原文。选择使用种子
`tsg-natural-transfer-2026-09-16`，Python 元数据，CWE-89/78/22 配额 3/3/2，
各层内按 SHA-256(seed:task_id) 排序，来源和近重复组去重。
没有使用生成结果、候选支持或选择器得分。原始清单保存在
[exposure/selection.json](../../data/method/open-tsg-scope-development-v1/natural-transfer/exposure/selection.json)。

| 序号 | 自然任务 | 本轮原文检查发现的主要边界 |
|---|---|---|
| 1 | SQLite 记录创建、插入 | 保留连接、执行、提交；区分数据库名、表名和记录值的角色。原文未明确要求建表。 |
| 2 | 买单写入后跳转 | 保留表单字段、变量、插入及重定向；不能遗漏非数据库行为。 |
| 3 | 图书查询 | 保留 SQLite 路径、接口、元组、找不到时返回 None、字母数字域及异常。 |
| 4 | Flask ping | 返回原 link；导入 os 不证明必须启动外部进程。 |
| 5 | 日期差 | Python 元数据与 Unix shell 原文冲突；保留来源与系统优先级，不能默默换题。 |
| 6 | Python 脚本执行 | 保留代码输入、执行、捕获 stdout 和返回格式；不能直接套用 shell 参数概念。 |
| 7 | 读文件后返回消息 | 保留目录和 recipient 的不同角色；未要求实际发送文件。 |
| 8 | 解压归档 | 保留 tarfile 指令，即使文件名为 archive.zip；保留全部成员及目的目录。 |

八题均保留于 [source-preflight](../../data/method/open-tsg-scope-development-v1/natural-transfer/source-preflight)，
包含原始输入、实际消息输入及逐题含义清单。它们已用于诊断和改动方法，
因此不能再充当新候选的未见泛化题。没有替换不方便的题目，也没有消耗受保护评估题。

## 最小修复

沿用已有 `DEVELOPMENT_OPEN`，接入同一个分组抽取入口：

1. 已有概念沿用原 ID、完整定义、类型和声明层；新事实仅在没有合适概念时声明。
2. 新事实仍须原文证据、原子化和实体一致性；定义传入关系绑定、审查及范围判断。
3. 仅允许增添开发事实含义。已有概念、候选家族、适用域规则和返回语义不可改写。
4. 新事实不会自动成为干预候选。没有已知候选范围时，保留源图，不制造缺失或不适用结论。
5. 继续使用一次综合审查和最多一次语义修复，不增加调用层级。

输入目录中的提示也同步改为开放事实声明，避免代码接受新概念而提示仍要求封闭词表。
正式使用仍要求先冻结词表；本轮没有激活正式协议。

验收同样需要修正概念名称与含义的混淆：新增概念按完整原文含义、实例及关系评判，
不能只比较名称。预先保留逐条必需含义，输出后明确记录其节点/边映射；同时审查所有
额外断言、覆盖声明、条件和范围前提。歧义不能靠改名消除，未知也不能冒充完整覆盖。
这个规则只适用于新开发检查，不重判历史结果。

## 验证与执行范围

在隔离的 Python 3.12.13 / pytest 9.1.1 环境中，36 项相关既有检查通过。
扩展了一项已有完整流程检查，没有增加默认测试数量。覆盖新事实参与绑定和范围询问、
已知定义和候选规则不可修改，以及范围阶段失败仍保留源图。
旧六题的 25 次 HTTP 请求和输出已离线精确重放，全部结果不变；重放不产生费用。

[open-facts-pilot/inputs](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-pilot/inputs)
固定第一题作为最小真实模型验证，仍使用 Qwen Max 2026-05-20、原采样和修复上限。
最多 7 次调用，总额不超过已授权余额 CNY 3.934326；每次请求预留 CNY 1.8。
价格按[百炼官方价格](https://help.aliyun.com/zh/model-studio/qwen3-7-max)
输入 CNY 12 / 百万 tokens、输出 CNY 36 / 百万 tokens 保守计费，不计缓存折扣。
这是一个开发案例，不能替代六题整合、18 次稳定性和新的八题两轮泛化验证。

首个 pilot 只完成一次模型调用，支出 CNY 0.298572，剩余 CNY 3.635754。
模型生成了五个新概念，但把两个没有额外事实的段落标成 represented，
最终编译报 `source coverage decision is invalid`。没有完成源图、审查或范围判断。
该输出保持失败，不能把“能生成新概念”计作质量通过。

共同原因是分组转换阶段未检查 represented 与实际事实的矛盾，导致错误越过了
已有机械修复入口。现已前移这个检查，同一修复上限不变。
[open-facts-coverage-check](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-coverage-check)
固定同一题重新完整生成，最多七次调用、总额 CNY 3.635754。
改动后 36 项相关检查和旧六题 25 次离线重放再次通过。

本轮还发现参考清单本身的过度要求：`create and insert records into a table`
不明确要求创建表。该项在首个模型输出后识别，因此保留原清单和失败结果，另存
[reference erratum](../../data/method/open-tsg-scope-development-v1/natural-transfer/source-preflight-erratum)
用于新的 pilot；不把参考错误算作模型缺陷，也不重判旧结果。
第二个 pilot 完成四次调用、一次关系修复，支出 CNY 1.149768。
源图生成成功，但语义验收失败：`fact.8` 的完整定义增加“创建表”，审查没有检出；
审查还声称连接操作缺少独立的连接返回对象。后者没有独立的原文对象/消费证据，
却使 u3 被标为不完整、所有候选范围被保留为未知，最终没有可用范围状态。
“没有错误的确定状态”因此不能冒充质量通过。

开发者逐项审查了 64 条保留断言：56 条支持、7 条不支持、1 条未定；
图和完整输出均为 0/1 通过。检查发现旧审查响应表只强制逐项回答关系与完整性，
没有强制逐项回答事实的完整定义。此处是可定位的检漏缺口，而不只是一次随机失误。
[第二次结果与完整源审查](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-coverage-check/analysis)
和首个失败均已保留，五次真实 HTTP 请求及结果完成精确离线重放。

随后在同一次综合审查中加入每个源事实的必答项，核对完整定义、类型、层及谓词对象。
事实项被判不支持或不确定时，自动回到库存修复；审查即使误写成关系修复，也不能
让关系阶段修改事实。仍共享原来的一次语义修复，不增加模型调用轮数。
另明确区分资源状态改变与独立输出值：常见 API 返回句柄并不自动要求另建源对象。

这项后续修复通过 36 项既有相关检查；两个现有测试被扩展，默认数量不变。
在保留自然题上离线核对，十个事实都会进入必答表，人工编写的负面事实意见能正确
触发原有库存修复。这只是离线路由控制，**不是模型已检出或修复了该问题**。
新审查请求已经改变，不能把此前固定候选的 18/18 记到新候选名下。

本轮合计 **5 次真实调用，CNY 1.448340**，授权余额 **CNY 2.485986**。
两个 pilot 均未通过语义验收。当前没有新候选稳定性或泛化成功结论。

## 追加预算后的复测

[单题复测输入](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-node-review/inputs/plan.json)
已准备并于用户“追加50预算”后冻结：同一自然题、同一模型及四步调用结构、至多七次请求，
费用上限 CNY 5。新增授权恰为 CNY 50，保留原余额 CNY 2.485986，总额度 CNY 52.485986；
历史费用不释放。授权 ID 为 `tsg-open-source-facts-additional-cny50-2026-09-16`。
该复测完成六次调用，支出 CNY 1.658448，剩余授权 CNY 50.827538。
源图和范围判断均完成，但完整语义验收仍为 0/1：SQLite 资源节点存在，却没有连接到
连接数据库、插入、执行查询及提交操作，u1/u3 仍被错误地标成完整。
68 条保留断言中 66 条支持、两条完整性断言不支持；另记录缺失关系。
12 个状态中两个确定状态有原文支持，但这不能弥补源图缺失。六次请求与输出精确重放，
费用已入账。[结果与源审查](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-node-review/analysis)
保留失败，不将无错误确定状态计作通过。

根因是审查虽提到检查遗漏，其必答表仍只枚举已有断言和操作结果。对输入及资源的
遗漏没有同等的逐操作判断。现将原结果检查扩展为每个操作的输入/资源和结果两栏，
分别判断缺实体、缺关系或原文未定，负面判断进入已有的一次修复。不会自动补边。
同一已有测试扩展后，13 项相关检查通过，默认测试数和模型调用轮数均不增加。
[新单题检查](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-participation-review/inputs/plan.json)
完成四次调用，支出 CNY 1.053012；逐项原文检查通过全部必需含义及 68 条保留断言。
连接、SQL 插入及提交共享 SQLite 资源，数据库/表名作为选择器，记录值作为插入数据。
十个范围状态含四个有原文支持的确定状态，未定域仍保留未知。该输出无需语义修复，
因此不能据此声称新审查导致了质量提升。全部请求和输出精确重放，余额 CNY 49.774526。
[单题结果](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-participation-review/analysis)
只支持本次开发案例通过，不支持稳定性或独立资格结论。

随后冻结[其余七题](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-remaining-seven/inputs/plan.json)，
保持代码、模型及提示不变，按预选顺序检查案例 2–8，至多 49 次调用、CNY 14。
第一题复用已关闭的同版本结果，避免无目的重复；这不是八个全新重复试验。
该批已完成，七题仅脚本执行题通过，与第一题合计 **2/8**。其余问题如下：

| 案例 | 失败原因 |
| --- | --- |
| 2，股票订单 | 两次库存输出仍有无法唯一定位的原文引用，未完成源图。 |
| 3，书籍查询 | 将整个“存在则元组，否则 None”规则再挂到存在条件下，丢失否则分支。 |
| 4，Flask ping | 把 ping 行为强化成必须启动外部进程；原文允许其他实现。 |
| 5，日期差 | 综合审查请求超过 120,000 字节上限，尚未发出；不能归因于模型回答。 |
| 7，文件读取 | 复用的文件内容定义还断言“用于后续计算”，原文没有该义务。路径范围本身未发现错误确定状态。 |
| 8，解压归档 | 一次机械修复后，引用仍无法唯一定位，未完成源图。 |

完成图的四题逐项检查了 329 条断言：313 条支持、14 条不支持、两条范围坐标未获认证。
全部 25 次函数调用精确重放，其中 24 次实际发送。已知 token 费用 CNY 7.563756；
冻结规则还对未发送调用保守扣除 CNY 1.8，合计预算扣额 CNY 9.363756，余额 CNY 40.410770。
这 CNY 1.8 不是观测到的供应商费用，不释放历史扣额。
[七题结果和逐项审查](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-remaining-seven/analysis)
保持失败，未启动稳定性重复。

后续修正集中在同一入口：一次反馈收集全部引用错误；审查只保留一张完整事实表，其余
断言通过 ID 引用；批准事实前必须判断完整定义是否带入原文不要求的属性，有此替代
可能即触发库存修复；条件边明确约束目标要求的全部含义。没有新增审查轮或测试数量。
13 项相关检查通过；旧日期审查请求在保留完整事实、原文、断言坐标和引用后，从
127,957 降为 96,230 字节，低于未改动的上限。这个离线检查没有调用模型。
[六道失败题复测](../../data/method/open-tsg-scope-development-v1/natural-transfer/open-facts-compact-source-review/inputs/plan.json)
已完成：32 次调用、CNY 9.507528，六题均完成构图，但完整通过仅 1/6（归档解压）。
456 条最终断言已逐项审查，32 次请求和结果精确重放。订单题加入用户名来源和插入用途，
且通用数据库不足以认证 SQL 适用性，留下三个未认证的确定状态；图书题仍丢失否则分支；
ping 题不仅推断外部进程，修复后的 API 回答还给出全空关系表；日期题未明确解决 Shell
与 Python 的语言冲突；文件题仍给文件内容添加后续计算用途。
订单参考中的“插入后跳转”也超出了只给相邻句子的原文，已记录参考争议，不凭这条判失败，
不改判历史输出。此批是针对失败案例的方法开发，不能作为无偏评估，也不能与旧版两题
通过拼成新版本的稳定性成功。

[两次定位实验](../../data/method/open-tsg-scope-development-v1/natural-transfer/delivery-critic-diagnostic/analysis)
进一步区分交付和语义问题。相同消息、模型及设置，只把 Qwen 的原生 schema 输出改成
普通 JSON，原先全空的 ping 关系表恢复了 7 条参与角色和 6 条其他绑定，并通过本地结构
检查；上游外部进程推断仍错误，因此不是整题成功。DeepSeek Pro 开启思考审查同一份
订单草稿，发现原文未要求 HTTP，但仍将“未禁止调用方来源”误作来源证明，也批准了
未要求的用户名插入用途。模型配置与思考预算不同，不能据此单独归因于模型权重。
两次诊断精确重放，费用 CNY 0.911319；结算后授权余额 CNY 29.991923。

随后在相同订单、图书草稿上测试简短的只报问题审查，保留完整事实定义和关系，取消
逐条重复的批准表。两次费用 CNY 0.395568，结果均未达到预先指定标准：订单审查发现
HTTP 和用户名来源问题，但漏掉用户名用途，并误报“读取或写入”通用定义；图书审查
只去掉操作上的条件，仍错误批准整个条件返回要求上的条件。这条简化候选未采用。
[诊断记录](../../data/method/open-tsg-scope-development-v1/natural-transfer/concise-critic-diagnostic/analysis)
含全部反馈、遗漏、误报及精确重放。最终授权余额 CNY 29.596355，没有并行付费任务。

本轮保留的交付修改只有：现有入口的绑定调用使用普通 JSON，并保持本地结构校验。
[当前入口离线验证](../../data/method/open-tsg-scope-development-v1/natural-transfer/json-binding-path-validation/report.json)
通过五份已记录回答确认仅绑定请求的 response_format 改变，输出源图与合约不变；没有
新模型调用，也没有新增测试用例。该修改仍需后续新鲜整题验证，不能把旧回答重放算作
新工作流的准确率。模型自审的漏检和固定词表定义夹带额外语义仍是研究障碍，未宣称
稳定性目标已经达成。

八题开发检查不等于最终泛化验收。新候选仍须经过整合及稳定性验证，再前瞻选择
未参与调参的新八题、重复两次，达到既定至少 15/16 与零错误确定状态标准。

## 数据边界和复现

`configs/formal/qualification_data_manifest.json` 追加八条开发暴露，旧内容快照保存在
exposure 包。后续研究池使用 `research-candidate-pool-v4`：1,954 题，其中 Python 684 题；
额外开发暴露从 33 增至 41。原有来源证据机械复用后为 144 个 Atomic 任务—策略组合、
65 个任务；这不是重新资格判定。旧 v3 和所有已冻结输出保持原样。

```powershell
$env:PYTHONPATH='src'
.tmp/tsg-workflow-review-env/Scripts/python.exe -m prompt_mechanism_study.cli curate prepare candidate-pool data/dataset-curation/research-source-use-v2 data/dataset-curation/research-candidate-pool-v4 --qualification-manifest configs/formal/qualification_data_manifest.json
.tmp/tsg-workflow-review-env/Scripts/python.exe -m pytest tests/test_source_inventory_extraction.py tests/test_source_inventory_contract.py tests/test_open_prompt_tsg.py tests/test_prompt_tsg.py -q --tb=short
```

研究池命令需要新的输出目录；不能覆盖冻结的 v4。付费执行使用 pilot 包的
`execution-source.tar.gz`、`execution/identity.json` 和 `launch.sh`，同一已有 runner
`scripts/run_tsg_development.py`，服务器仍在约定 study 根目录内。
