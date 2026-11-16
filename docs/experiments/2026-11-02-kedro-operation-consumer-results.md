# 共同API资料下的操作提示结果

## 实际准备与参考

按照 `2026-11-02-kedro-operation-consumer-design.md`，在固定Python 3.12.16镜像中收集shelve和dbm完整源码，以及三个实际API签名及文档字符串，保留Python许可证。新增资料共同提供给全部处理。原有Graph与Flat表示、先前16项生成及其负结果保持原值，本轮仍只有一个已经暴露的自然代码单位。

独立来源参考在新提示编制之前完成，六项操作判断均有来源支持，保留13项逐字证据。参考明确区分原始字节、已恢复对象、二进制文件输入、入口、拒绝位置和结果归属；全部编码、缓存及任意不可信数据的覆盖仍然未知。来源参考不认证候选实现。

两种操作提示各由一个新上下文编制，取得相同基准任务和API资料。Graph取得实际原生source_proposition_readback，Flat取得完整条目，均未取得操作参考、测试、控制实现或旧生成结果。共同输入上限250000字符、输出上限20000字符；实际输入Graph为125778字符、Flat为56638字符，输出分别15557和15673字符，成本差异没有隐藏。

两种提示均通过机械检查。两个独立上下文对Flat六项均判定complete；Graph有五项共同complete，unpickler_input分别判定incomplete和complete，分歧原样保留。首次提示没有根据评价调整，固定20项也没有因为评价取消。准备核对状态为 `VERIFIED_SOURCE_OPERATION_CONSUMER_PREPARATION`，摘要 `fa78cc5550b4bfa0eb0f7f7aabe3ee6ef6275e73ee3f2be7d518158dda7c61f6`。

## 固定预算和实际执行

五种处理各使用四个共同种子2026111751至2026111754，请求顺序按2026111750打乱，共20次生成。实际Qwen tokenizer确认全部完整输入满足32768上下文上限，没有截断提示；每次输出最多4096 tokens，temperature=0.7、top_p=1，并发两个。沿用此前逐项核对的Qwen2.5-Coder-32B-Instruct本地权重。

| 处理 | 输入tokens | 完整策略成功 | 全部局部功能成功 | 联合成功 | 完整策略记录unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 8041 | 0／4 | 0／4 | 0／4 | 4 |
| flat_record | 12104 | 0／4 | 3／4 | 0／4 | 1 |
| graph_record | 14545 | 0／4 | 3／4 | 0／4 | 1 |
| flat_operation | 10744 | 0／4 | 0／4 | 0／4 | 4 |
| graph_operation | 11549 | 0／4 | 0／4 | 0／4 | 4 |

20次请求全部完成，20份代码均可通过语法解析；实际执行840项固定检查，原始报告中的测试错误和跳过均为零项。代码运行异常表现为真实失败，语法通过不代表正常运行。全部位置进入分母，14份完整策略记录unknown保持unknown，不能据此判定完整安全。

实际模块摘要、原始请求、种子、参数、输入tokens、响应与提取代码、测试身份、探针和配对结果均通过独立核对。状态为 `VERIFIED_ASSIGNED_OPERATION_CONSUMER_GENERATION`，结果摘要 `32a3a94c00d0a9a9f42657cd2afaa71fe1dbce99f0199af812f0b92239e0a36e`，核对摘要 `7465606e1204189bffeb5f154bc8e84270bde0ca7d79ea27bc74ebe17ad2ba74`。

Graph_operation相对Flat_operation的策略、局部功能及联合成功差异均为零。两种operation处理相对对应record处理的局部功能成功均减少三次，策略及联合成功没有改善。该开发检查没有建立Graph收益或操作编制流程的下游收益；共同API条件也不能独立估计新增API知识相对于旧实验的贡献。单任务和四个生成种子不提供总体统计结论。

## 实际失败及科学解释

事后诊断使用原始XML、代码和探针，保持原判定与分母，未增加生成调用。11份产物实际出现禁止调用标记。其余九份没有记录到此类标记，但恢复前后的基本API错误阻止完整测量，不能将它们算作安全改进。

真实例子包括：Graph_operation的request-00先调用普通 `_sh[key]`，随后进入安全函数，并引用没有导入的BytesIO；request-02引用不存在的pickle.BytesIO。Flat_operation的request-10调用不存在的 `_sh._factory`；direct的request-03使用不成立的异常捕获组合。其他产物还出现名称未定义、属性缺失、输入状态错误和读取过晚。完整共同API源码已经提供，这些结果没有支持通过增加来源说明和一次操作提示编制即可解决本任务的生成失败。

参考和提示中的语义条件，与代码是否遵守条件保持不同证据身份。Flat操作提示的六项完整性没有产生正确的恢复实现，Graph提示自身还保留一项分歧。因此，本轮不能用文字完整性代替执行收益，也不能归因于缺少一条已存在的先后关系。诊断记录为 `diagnostic.json`，摘要 `1c457b04ee62612bd32d8f80e0a349d15a0f0b7477d86b649151b622cd4308e4`，明确标记事后分析。

该局部消费假设已经完成一次实际检验。后续在本任务上的修改继续属于开发；按既定顺序推进第三项Codecov来源，检验可核对的输入状态和操作归属，并保留相同信息与预算的强平面对照。不会通过增加本任务的种子或修改检查来建立收益。

## 实现、原始资料与边界

代码生成和提取共用逻辑为 `src/experiment/code_generation.py`，会话恢复测量及汇总为 `src/measurement/session_restoration.py`；本研究的薄入口为 `execute.py`。复用既有42项测量，不修改生成代码。新提取实现先对16份真实旧响应复算，提取代码和记录逐字节一致；新测量入口又对第一份固定旧产物实际重放42项，复现其21项功能通过及零项策略通过，状态 `VERIFIED_REAL_OUTPUT_CONTRACT_RUNNER`。这些资格重放没有增加模型调用或独立实验样本。

实际运行输入为 `results/kedro-operation-consumer-20261102-runtime-inputs.tar.gz`，58321889字节，SHA256为 `900d32eb6a1c11fcda3f03a1b2cf61020a175818fcdfedd83af861652f161e73`；生成计划摘要为 `2111346cd538ed961411d41c0f4192e044390a0948ac7ddc09cb5d30cfb3006c`。原始结果归档为 `results/kedro-operation-consumer-20261102-generation-results.tar.gz`，摘要 `f60a5cba8d1234582eb3db518edb3409672854498e822080a7a5f0ae7ab22659`。

在独立目录 `.test-tmp/kedro-operation-consumer-20261102-replay`重新解压上述运行输入与原始结果，分别运行来源准备及生成结果核对。两个输出均与原件逐字节一致，摘要分别为 `fa78cc5550b4bfa0eb0f7f7aabe3ee6ef6275e73ee3f2be7d518158dda7c61f6`和 `7465606e1204189bffeb5f154bc8e84270bde0ca7d79ea27bc74ebe17ad2ba74`。生成核对器在生成期间单独部署，未包含在最初运行输入包中，其当前摘要为 `f9770234759054252101d624600117babb56c48d1992e12fe6079a4a68478847`；其判定标准遵循生成前固定的设计。

服务器输入和结果分别为项目 `inputs/kedro-operation-consumer-20261102-runtime`及 `results/kedro-operation-consumer-20261102-generation`；本地原始结果位于 `data/method/kedro-operation-consumer-20261102/generation-results`。独立生成核对入口为同目录 `verify_generation.py <原始结果目录>`；操作准备核对入口为 `verify_preparation.py`。复算应使用独立解压副本，保留派生核对原件后运行，冻结原件不修改。

本轮模型仅在已有空闲GPU 0生成代码，完成后关闭该模型进程；其他用户的模型没有用于实验。没有付费服务调用、受保护任务使用或正式协议激活。全部来源、提示编制和代码生成都保持开发诊断身份，完整功能、任意pickle完整安全、总体Graph收益及真实任务JCI收益均未建立。

完整冻结包为 `results/kedro-operation-consumer-20261102-frozen.tar.gz`，58977545字节，SHA256为 `5e5b96e00b8ee426c2d23091221baa5b28a1416bf361293679f52f7a99fd18d8`，保留最初运行输入、独立核对器、全部原始生成与测量、事后诊断及本轮结果说明。
