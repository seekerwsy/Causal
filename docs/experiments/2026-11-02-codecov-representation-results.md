# Codecov表示比较的执行记录

## 来源准备与独立评价

遵循[固定设计](2026-11-02-codecov-representation-design.md)，原始来源、作者基准任务及新增单项目录要求已分别固定。Task3来源按既有顺序选择，任务来源摘要为 `d615435023649fcceb855a9a43a7817ae67af172b82f7f58d91dc765486e0251`，未向方法制作上下文提供控制、测试、修复实现或语义参考。每种方法由一个独立上下文制作，共同预算为40000规范JSON字符、64项事实或条目；Graph最多128项关系。

Graph使用完整原生来源读出，节点编号的确定性显示变换保留全部字段。已有49节点真实Kedro表示的资格检查通过，反向转换严格恢复完整原件；该重放没有新模型调用或科学重复。新Codecov表示同样通过独立反向核对。Graph实际显示58023字符，平面显示36329字符，不声明相同实际tokens成本。

两个新的独立上下文评价实际显示内容。平面六项共同complete；Graph五项共同complete，directory_state_distinction分别为complete与incomplete。分歧保留。Graph在原始目录、已引用目录与全部下游消费者的绑定上存在一项不完整判断。表示没有根据评价修改，16个固定位置没有按评价取消。准备核对状态为 `VERIFIED_CODE_COVERAGE_REPRESENTATION_PREPARATION`，摘要 `f1177fbfd5bdd31969c816de01b3ae38a080d4d860d306949c186f6ac95de924`。自动上下文参考与评价保持自动评审身份。

## 固定模型和真实上下文

完整真实tokenizer核对结果：baseline为12041 tokens、direct为12216、flat为19351、graph为32107；所有处理的输入加12288输出上限均满足49152。提示未截断，输出请求为完整codecov/__init__.py。16次计划使用四个共同新种子2026111851至2026111854，顺序种子2026111850。

实际模型配置使用Qwen2.5-Coder-32B-Instruct原权重、bfloat16、单个生成工作进程、temperature=0.7和top_p=1。依据已完整阅读的[官方模型说明](https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct)，所有处理共同使用静态YaRN，factor=4.0、original_max_position_embeddings=32768、rope_theta=1000000及rope_type=yarn，服务上下文49152。通过当前vLLM ModelConfig实际核对，使用hf-overrides的rope_parameters字段，不修改共享config或权重文件。实际版本为vLLM0.18.0、Transformers4.57.6和Torch2.10.0。

静态YaRN可能影响短输入表现，四种处理共同使用该设置。与此前未使用YaRN的Kedro结果不进行表示效果归因比较。原始config摘要保持 `9fb1473a47db69c00c02f365c7b9e9d84fd2163c687c63b5a31167ebb2b189a6`；配置核对记录为runtime-policy.json。生成计划摘要为 `18d0d28d01fca90690a3fdc512585521bb9f9edde4d162b407c3e5ae9bcf714f`，在任何本轮生成之前固定。

## 完整生成与实际测量结果

16项真实生成全部完成，15份代码通过语法解析并实际执行共同20项检查，共300项；Graph的一份代码存在语法错误，保留在四项分母内，没有补充生成。固定测量包含14项局部功能与六项目录策略。测量模块为src/measurement/gcov_directory.py，生成与提取共用src/experiment/code_generation.py，独立核对器为本研究verify_generation.py。

| 配置 | 完整目录策略成功 | 全部局部功能成功 | 联合成功 | 完整策略未知 |
| --- | ---: | ---: | ---: | ---: |
| baseline，无新增政策 | 2/4 | 0/4 | 0/4 | 0 |
| direct，逐字新增政策 | 2/4 | 0/4 | 0/4 | 1 |
| flat | 1/4 | 0/4 | 0/4 | 1 |
| graph | 0/4 | 0/4 | 0/4 | 1 |

完整策略成功要求全部六项检查secure；没有额外命令标记但未生成正确产物的结果保留unknown。局部功能要求14项全部通过，不能用通过部分检查替代。Graph相对Flat和direct的完整策略点差分别为-25及-50个百分点；该单任务四种子结果不提供总体统计推断。没有建立Graph收益。

结果摘要为f26501a661e2b9c0c94532439d3fb12a91b036102575174e0e79c3548db6c1d8，状态VERIFIED_ASSIGNED_DIRECTORY_CODE_GENERATION。独立核对结果摘要为1f88fa4f5d485436294db4f22aef9922b0494051f0952484e59751054c7418ef。全部原始请求、生成参数、实际输入tokens、响应、代码、实际挂载源码、逐项测量及六组配对比较均已核对。

生成候选借用已验证probe的reference模块位置，替换的只有候选模块摘要及实际只读挂载代码；case.json明确记录measurement_role=generated_candidate、实际处理与种子。reference位置名称不表示候选取得作者参考身份。策略unknown、明确不安全、局部功能和联合成功分别保留，语法通过不认证完整模块功能。单一任务的四个种子继续不提供总体统计Graph收益。Goal、正式协议和受保护资料边界保持原值。

## 实际运行身份与控制重放

生成前冻结输入为 `results/codecov-representation-20261102-runtime-inputs.tar.gz`，14214252字节，SHA256为 `d3a68170885c9112ff470a23e1f07a1986404b19c68af370093bf2ee0e17e260`。在 `.test-tmp/codecov-representation-20261102-preparation-replay`独立解压，使用包内共用工具执行准备核对，输出摘要与原件一致，同为 `f1177fbfd5bdd31969c816de01b3ae38a080d4d860d306949c186f6ac95de924`。

实际执行入口为本研究 `run.sh`，在冻结输入包解压后单独部署，摘要 `07ced1afd17b64a82f41bd3b78a9369292e7bd133078d12f487e3d84d1465548`；它不属于上述初始输入归档。入口按顺序执行真实参考重放、固定生成、提取、20项测量、汇总及独立结果核对。各阶段失败立即停止后续过程，不按结果修改分配。

新候选测量入口已经对原有真实作者参考模块重放20项，复现14项局部功能及六项策略全部通过，状态 `VERIFIED_REAL_DIRECTORY_REFERENCE_REPLAY`。参考模块摘要为 `2da010a2bd13e7036fefd6601ae73af1646c0fb018cb2923c8e4f8380a213654`，重放结果摘要为 `3b7acb5df52be0dfdb081d2cd9b315edca8be148a7da624e8f10a8bb9e354218`。这是一次真实控制重放，生成调用与新增科学重复均为零；不当作模型成功或独立任务样本。

服务器输入为项目 `inputs/codecov-representation-20261102-runtime`，控制重放为 `results/codecov-representation-20261102-runner-replay`，固定生成及测量为 `results/codecov-representation-20261102-generation`，过程记录为 `results/codecov-representation-20261102-driver.stdout.txt`及同名stderr。生成服务限定GPU 0、本机端口18582；使用实际核对的同一YaRN配置。只在完整独立核对通过后解释本轮代码效果。

## 原始资料归档与独立复算

完整归档为results/codecov-representation-20261102-frozen.tar.gz，本地与服务器archive摘要相同，为ad14e6dfbb0c0b2de55fc7d2de0c27d6c9cc2f0bee33da9110863dbcf9c0e482。它保留最初完整输入归档、实际部署研究文件（包括单独部署的run.sh和核对器）、全部原始生成与测量、控制重放及过程输出。没有模型权重或凭据。

在.test-tmp/codecov-representation-20261103-full-replay独立解压完整归档，再把包内初始runtime-inputs解压到相应inputs目录。核对器摘要确认为23a7fbb10be33f836242d71dc476d8817128a2c2bd928a5ba3449f807b772078。保存副本已有verification后，使用冻结.runtime及Python 3.12.14运行verify_generation.py，重新读取全部原始结果，核对输出与服务器原件逐字节相同。没有新模型调用或新增科学重复。

## 具体失败机制

2026-11-03的事后诊断使用成熟Python AST、原始响应和逐项真实执行记录，不改变主要结果。入口为本研究diagnose.py，输出diagnostic.json。三份有效Graph候选均保留命令构建中的(codecov.gcov_root or root)，实际六种策略探针均出现额外命令标记。其中request-02和request-14的完整AST与原始模块相同，提示没有改变其程序语义。

Graph的request-15在第666行有多余右括号，提取状态invalid_syntax；实际finish_reason=stop，输出7596 tokens，未达到12288上限。没有证据把这一失败解释成输出截断。其余真实运行包含局部功能失败，不能把原样返回代码或语法通过视为功能保持完成。

当前证据支持继续检查具体调用与对象状态绑定能否实际进入提示和修改位置。它没有隔离表示长度、编码形式、模型能力及提示准备的各自贡献，也不能认定缺少一项关系就是唯一原因。新增机制应在相同来源信息、工具及预算下与完整原文比较，保留强平面诊断；本轮冻结代码不能被手工修改后重新计入成功。
