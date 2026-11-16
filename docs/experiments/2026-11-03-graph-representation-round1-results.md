# Graph表示第一轮来源可行性边界结果

## 执行状态

Codex CLI独立协议审查的最终判定为`BLOCKED_SOURCE_BOUNDARY`。第一轮在表示制作和代码生成之前终止。固定二十项来源中的Brotli属于预定任务名单，其来源测量资格为`qualified=false`，满足第一轮设计规定的来源可行性边界终止条件。

本轮没有制作Raw、Flat或Graph表示，没有形成生成提示，没有发出计划中的240次本地模型调用，没有提取候选代码，也没有运行候选代码测量。Graph代码生成、主要安全判定、功能非劣判定、结构归因判定及独立结果重建均为`NOT_EXECUTED_SOURCE_BOUNDARY`。

## 固定设计保持

| 固定项目 | 保持的取值 | 当前状态 |
| --- | ---: | --- |
| 独立来源任务 | 20项 | 名单保持，Brotli不删除、不替换 |
| 准备表示 | Raw、Flat、Graph | 未制作 |
| 每项任务与每种表示的生成种子 | 4个 | 保持固定，未使用 |
| 计划生成分配 | 240项 | 分母定义保持，未形成执行结果 |
| 每项候选输出额度 | 8,192 tokens | 保持固定，未使用 |
| Graph相对Raw的安全产出实用改善门槛 | 0.10 | 保持固定，未判定 |
| 功能非劣界限 | -0.10 | 保持固定，未判定 |
| 第一轮错误率 | 0.025 | 保持固定，未使用 |
| 结构归因Bonferroni单侧界限 | 0.0125 | 保持固定，未使用 |
| 任务权重 | 二十项任务等权 | 保持固定，未汇总 |
| 研究轮次上限 | 至多两轮 | 保持固定，不能用于绕过本次来源边界 |

来源资格发生在表示制作、随机顺序执行和生成分配之前。Brotli资格失败没有转换为分配后的零结果，也没有进入计划生成分母。Gradio和internetarchive已经取得各自限定端点的局部测量资格；这两项资格保留各自证据身份，不能抵消或替换Brotli。

## 当前能够陈述的结论

- 固定二十项来源无法全部满足第一轮生成前来源资格要求，第一轮达到预先规定的来源可行性终止边界。
- Brotli保留`qualified=false`，固定任务总体、样本数、预算、门槛、错误率、分母和两轮规则均未改变。
- 当前Graph第一轮没有完成代码目标；该状态来自生成前来源边界，未产生Graph相对Raw或Flat的效果估计。
- Gradio和internetarchive的局部测量结果支持各自限定政策范围内的任务准备，未提供Graph表示或代码收益证据。
- 已经固定且与Graph第一轮分离的JCI组件评价可以按原有设计继续，其研究身份、分母和解释不受本次边界改变。

## 禁止陈述的结论

- 不能声称Graph、Flat或Raw取得任何安全产出、局部功能、联合成功、表示准确性或成本结果。
- 不能声称Graph效果为零、有害或优于Raw、Flat，也不能声称图关系具有额外贡献。
- 不能声称主要安全门槛、功能非劣门槛或任何校正区间已经通过或失败。
- 不能声称实际完整提示已经建立预算可行性边界。
- 不能声称自然任务JCI证据、Graph与JCI集成收益、正式确认性证据或协议激活已经成立。
- 不能通过删除或替换Brotli、缩小到十九项、追加来源或种子、修改CPU限制、改变端点、降低门槛或使用第二轮额度继续当前第一轮。

## 局限

本结果只确定固定第一轮设计下的来源资格可行性边界。Brotli判定来自其固定限定输出政策、固定资源限制和固定分母；该判定不评价其他来源的资格，也不扩大为完整进程内存、完整原生分配、Scrapy问题复现或通用Brotli安全结论。

本轮在任何表示输出之前终止，因此没有观察表示信息一致性、真实tokenizer完整提示长度、请求排序、模型响应、生成失败、Oracle支持、安全未知、功能未知或非目标行为漂移。计划中的任务单位配对区间、点估计和独立核对器均没有可重建的生成结果。解析功效记录仍只描述固定数学备择，不能解释为观察到的Graph改善或本轮效果判定。

Gradio与internetarchive结果分别限于固定Linux文件系统政策和各自局部功能端点。两项结果没有代码生成、表示比较、自然JCI上下文或正式确认性身份。来源边界也没有改变此前任何冻结研究的结果、资格、未知状态或证据身份。

## 来源边界冻结归档

- 归档路径：`results/graph-representation-round1-20261103-source-boundary-frozen.tar.gz`
- 归档字节数：`211926740`
- 归档SHA-256：`838d2c753ac04eb4e696e7800fe463a59971b5e22ae7e82916fe9c5cc57a8093`
- manifest路径：`data/method/graph-representation-round1-20261103/source-boundary-frozen-manifest.json`
- 核对状态：`VERIFIED_SOURCE_BOUNDARY_ARCHIVE`；归档能够读取，十九个成员恰好等于manifest声明的十八个纳入文件加manifest自身，逐文件SHA-256全部一致。三项来源冻结归档均存在，其SHA-256与对应结果文档一致；Gradio与internetarchive归档字节数也与对应结果文档一致。

## 核对入口

- 固定设计：`docs/experiments/2026-11-03-graph-representation-round1-design.md`
- 固定计划：`data/method/graph-representation-round1-20261103/plan.json`
- 独立协议审查：`data/method/graph-representation-round1-20261103/codex-cli-source-boundary-result.md`
- 只读核对记录：`data/method/graph-representation-round1-20261103/source-boundary-verification.json`
- Brotli来源结果：`docs/experiments/2026-11-03-brotli-output-contract-results.md`
- Gradio来源结果：`docs/experiments/2026-11-03-gradio-path-contract-results.md`
- internetarchive来源结果：`docs/experiments/2026-11-03-internetarchive-path-contract-results.md`
