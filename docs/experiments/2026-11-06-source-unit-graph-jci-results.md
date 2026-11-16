# 126次开发计划的来源资格结果

本轮身份为`source-unit-graph-jci-20261106`，最终裁决为`STOP_SOURCE_BOUNDARY`。实际新Qwen调用为0/126；六项模型接口资格与120项开发评价均为`NOT_STARTED_BY_PREDECLARED_SOURCE_GATE`。没有新生成结果、安全收益、功能非劣或关系贡献估计，科学成功未建立。原冻结结果保持原身份。

## 协议与实际完成状态

[执行设计](2026-11-06-source-unit-graph-jci-design.md)的修订02在任何新Qwen输出之前冻结，并通过独立只读审查。该审查确认协议约束，未代替实际实现验证、表示语义审查、预算计量或共同执行冻结。

二十任务的来源事实准备完成，作者初判十七项PASS、三项FAIL。新的独立来源参考会话只读取三项争议任务的原始任务与来源资料，没有读取作者事实或历史候选；最终裁决会话读取原始资料、作者事实及独立参考，核对资格与停止条件。当前聊天只读取隔离Codex CLI最终报告。两次独立核对均保留三项FAIL：

| 来源 | 资格裁决的依据 |
|---|---|
| html-sanitizer | 来源文档已经表达最终清理安全、允许列表与Unicode规范化要求，原政策属于该要求的具体化。 |
| PyJWT | 来源已有非对称密钥材料不得作为HMAC secret的错误契约，新增格式和入口属于该边界的具体测量条件。 |
| Requests | 来源已有代理认证发送给代理、避免进入CONNECT隧道内请求的要求，原政策属于该凭据归属边界。 |

来源已有同义要求时，无法同时保留完整来源、原目标政策和原定Atomic ADD语义。修订02已经规定任一任务存在无法解决的来源资格问题就不启动整批120项；全部126项材料必须先于六项资格输出冻结，因此六项同样没有启动。未删除或替换任务，未改变政策或改用REMOVE。其余十七项没有经过本次独立资格核对，不能报告为独立通过。

源码位置目录与解码程序已经实现。两次实际离线验证均退出1，分别暴露文件结尾映射和后续LF边界处理问题；后续修复交付未成功应用。源码合同未通过验证，六十份表示、独立表示审查、实际126项提示、预算绑定与共同执行冻结均未完成。来源边界成立后停止后续实现检查。

资格批次的预定请求数为6，主体批次的预定请求数为120；实际请求数、请求失败数和生成结果数均为0。未启动的请求不能计作生成失败或接口资格失败。二十项来源事实分母与三项独立裁决分母分别报告；目前没有已分配代码结果的效果分母。

## 冻结结果与复核入口

本轮结果目录为`C:/MyCode/causal/data/method/source-unit-graph-jci-20261106/results/source-boundary-final-package`。`MANIFEST.json`绑定包内全部文件摘要，原始二十任务和完整共同来源资料保存在`original-inputs`。隔离会话输入、会话事件及未应用交付保存在本轮开发归档，原始材料与旧冻结包均未覆盖。

核心阅读顺序不超过十项：

1. 本结果文件。
2. 包内`PROTOCOL_AMENDMENT_02.md`。
3. 包内`PROTOCOL_AMENDMENT_02_REVIEW.md`。
4. 包内`FINAL_REPORT.md`。
5. 包内`FINAL_ADJUDICATION.json`。
6. 包内`materials/source-facts.json`。
7. 包内`materials/independent-source-qualification-reference.json`。
8. 包内`runtime/source-qualification-reference-packet.manifest.json`。
9. 包内`runtime/OPERATIONAL_STATE.json`。
10. 本轮`verify_source_boundary.py`，按包内`MANIFEST.json`执行文件完整性和分母核对。

独立文件与分母核对已经通过，共核对56项冻结文件。默认复核命令及完整读取顺序见本轮`REVIEW_GUIDE.md`，使用Python 3.12标准库，不需要运行模型服务或分析案例。

审查归档`source-unit-reviewer-20261106.tar`的SHA-256为`9cc1fa547763668055f79f317f26739297425523bda6026d221e08ee601f590d`；开发归档`source-unit-development-20261106.tar`的SHA-256为`12026047040e564fd4afcac37dbef9b583c323fa06737c6c6fe67b95e81c3542`。两项均已传至研究服务器并确认摘要相同。服务器在新的独立解压目录执行默认核对命令，结果为PASS。交付记录保存在本轮`results/DELIVERY_VERIFICATION.json`，不改写两个既有归档。

来源资格裁决不产生统计效果。总体收益区间、功能非劣、自然任务效果及自然JCI精度增量保持未建立；本轮没有启动新的自然任务研究或增加调用额度。
