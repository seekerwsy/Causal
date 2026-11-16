# Graph与JCI Goal联合冻结结果

## 冻结判定

- JCI组件：`JCI_ROUND1_SUCCESS`。
- Graph组件：`BLOCKED_SOURCE_BOUNDARY`。
- 联合判定：`JOINT_SCIENTIFIC_BOUNDED_UNMET`。
- 第二轮状态：`NOT_STARTED_NO_ELIGIBILITY`。
- 正式声明状态：`formal_claim_allowed=false`。

联合成功要求两个组件同时达到各自预定标准。JCI达到reference模拟条件的组件门槛；Graph在固定二十项来源的生成前资格检查处终止，没有产生代码目标证据。联合结果不写入`JOINT_SCIENTIFIC_SUCCESS`，JCI模拟结果不替代Graph代码目标。

## JCI组件的冻结证据身份

JCI第一轮保留四个条件、三个机制、两个批次、每批十六次重复的完整384项分母。四组各96项均完成逐单元独立数值核对和原生图重放。最终汇总包含204项预定比较和132项描述性诊断。

| 证据 | 路径或身份 |
| --- | --- |
| 冻结设计 | `docs/experiments/2026-11-03-jci-robustness-round1-design.md` |
| 组件结果 | `docs/experiments/2026-11-03-jci-robustness-round1-results.md` |
| 完整结果传输归档 | `results/jci-robustness-round1-20261103-complete-results.tar.gz`；2,188,979,195字节；SHA256 `3dee97c0643de4e0250ad2435dfe25a84a21e449cdfc9313824c31679caa005d` |
| 冻结学习输入 | `results/jci-robustness-round1-20261103-inputs.tar.gz`；1,926,808字节；SHA256 `c591489b22eee6bbcb59d1938451ebb26f90d79ebc9027695dc36131e88825e6` |
| 冻结分析输入 | `results/jci-robustness-round1-20261103-analysis-inputs.tar.gz`；24,406字节；SHA256 `d3098a34881d9f788beeeea2ad3f70cca606eb8bc19129be6da2e4e70b097dab` |
| 共享执行源码 | SHA256 `026ae44efa40c80a8734a7afb3d09397b1624a51dc9d6bbba5914d58961dd68c` |
| 逐单元独立核对器 | SHA256 `787b61798589db37d257cffed47a57d2242e7ed5d9a52665e9b9a4b311175207` |
| 原生图重放 | 四组共同SHA256 `ee75c83424bd1dd71faaf29af3b83255e28c76c6e76ec0a6d7db41d239b4fb21` |
| 主配置 | `configs/jci-robustness-round1.json`；SHA256 `857e59604151f119f0aacac7fb1947aebac90ca89853c2bbf26e140f8830556c` |
| 最终汇总 | `results/jci-robustness-round1-20261103-analysis/summary.json`；137,932字节；SHA256 `af02ef80b4e0eee5eebe0ef78403940426f1ee5259b128f05c713439282b6ac2`；`COMPLETED_VERIFIED_ROBUSTNESS_AGGREGATION` |
| 独立汇总核对 | `results/jci-robustness-round1-20261103-analysis/verification.json`；320字节；SHA256 `424a68aee2d1c0e8e7c675663dfa9550ba66322946466a9e88e2445e32779270`；`INDEPENDENTLY_VERIFIED_COMPLETE_ROBUSTNESS_AGGREGATION` |
| 独立汇总核对器 | SHA256 `56d532ae0bd0f3304afb7d5e31e4ae91164d1ec9159aac26aad9c99887d179b0` |
| Codex CLI最终科学审查 | `data/method/jci-robustness-round1-20261103/codex-cli-final-review-result.md`；SHA256 `b10538790ba89b8878174c9418a08641cdd1921bd2e6a72dd6d658f4bfad9e35` |
| 组件冻结归档 | `results/jci-robustness-round1-20261103-frozen.tar.gz`；2,191,231,231字节；SHA256 `44db172714253be7787a4e375c3dcf7365d12f7c6b80473f937823817069eb1f`；19个成员 |
| 组件外部清单 | `data/method/jci-robustness-round1-20261103/frozen-result-manifest.json` |

完整运行启动器没有单独保存主进程退出状态。四份成功终止核验记录、完整执行日志和四组`VERIFIED`状态构成完成证据；完整分析命令退出状态为零。该执行记录限制保留在冻结证据中。

## JCI预定比较、区间与两个批次

204项共同家族包括84项角色集合诊断和120项JCI比较。整轮双侧错误概率为0.025，全部比较共同采用Bonferroni校正配对区间。单项通过同时要求相对方差减少至少5%、校正区间下界大于零、两个批次的差值均大于零。十项JCI对照固定为`direct_uniform`、`direct_context`、`full_logit`、`sparse_logit`、`screened_logit`、`boosted`、`pca`、`skeleton_background`、`shuffled`和`propagated_skeleton`。

| 条件 | 机制 | 相对方差减少范围 | 通过数量 | 校正区间与两个批次状态 | 冻结状态 |
| --- | --- | ---: | ---: | --- | --- |
| reference | downstream_signal | +12.51%至+18.38% | 10/10 | 十项区间均支持改善；十项均在两个批次改善 | 通过 |
| reference | target_new_attribute | +5.19%至+7.92% | 10/10 | 十项区间均支持改善；十项均在两个批次改善 | 通过 |
| reference | upstream_control | -13.78%至+2.16% | 0/10 | 四项小幅正值未达门槛；五项两个批次均损害；`shuffled`点估计、区间和两个批次均为零 | 损害 |
| weak_context | downstream_signal | -8.53%至+2.51% | 0/10 | 两项两个批次损害；两项批次方向冲突；`sparse_logit`区间支持损害 | 未通过并含损害 |
| weak_context | target_new_attribute | -3.33%至+2.04% | 0/10 | 四项批次方向冲突；五项两个批次损害；全部区间均未支持改善 | 未通过 |
| weak_context | upstream_control | -3.78%至+3.18% | 0/10 | 四项两个批次损害；两项批次方向冲突；全部区间均未支持改善 | 未通过 |
| measurement_error | downstream_signal | +0.30%至+1.53% | 0/10 | 九项两个批次为正；一项批次方向冲突；全部低于5%且区间不支持改善 | 未通过 |
| measurement_error | target_new_attribute | +0.12%至+2.45% | 0/10 | 八项两个批次为正；两项批次方向冲突；全部区间均未支持改善 | 未通过 |
| measurement_error | upstream_control | -4.06%至+1.73% | 0/10 | 四项两个批次损害；五项批次方向冲突；`direct_context`区间支持损害 | 损害 |
| limited_structure_data | downstream_signal | -9.80%至+0.72% | 0/10 | 三项两个批次损害；三项批次方向冲突；`sparse_logit`区间支持损害 | 损害 |
| limited_structure_data | target_new_attribute | -5.24%至+1.53% | 0/10 | 两项两个批次损害；三项含零值或批次方向冲突；`sparse_logit`区间支持损害 | 损害 |
| limited_structure_data | upstream_control | -11.23%至+1.93% | 0/10 | 七项两个批次损害；一项批次方向冲突；`direct_context`区间支持损害 | 损害 |

Bonferroni校正区间明确支持损害的七项边界完整保留：

- reference／upstream_control／`skeleton_background`：-13.62%，区间`[-0.0043559146, -0.0007039766]`。
- reference／upstream_control／`propagated_skeleton`：-13.78%，区间`[-0.0043712221, -0.0007422789]`。
- weak_context／downstream_signal／`sparse_logit`：-8.53%，区间`[-0.0028443594, -0.0003309452]`。
- measurement_error／upstream_control／`direct_context`：-4.06%，区间`[-0.0019237536, -0.0000411121]`。
- limited_structure_data／downstream_signal／`sparse_logit`：-9.80%，区间`[-0.0031143356, -0.0004303886]`。
- limited_structure_data／target_new_attribute／`sparse_logit`：-5.24%，区间`[-0.0020964341, -0.0001806157]`。
- limited_structure_data／upstream_control／`direct_context`：-11.23%，区间`[-0.0038862435, -0.0004952462]`。

## JCI偏差、均方误差、覆盖、方向与未知边界

下表记录JCI方法的十二项机制诊断。覆盖为描述性的名义95%正态Wald区间，每行只有32次重复，不提供精确95%覆盖认证，也不进入组件成功门槛。

| 条件 | 机制 | 偏差 | 均方误差 | 覆盖 | 确定方向边 | 方向状态 | 与无噪机制差异 | 完整预测器选择 |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| reference | downstream_signal | 0.012729 | 0.020412 | 30/32 | 1167 | 32通过 | 13 | 6 |
| reference | target_new_attribute | -0.020017 | 0.019276 | 30/32 | 1168 | 32通过 | 14 | 9 |
| reference | upstream_control | -0.005727 | 0.022317 | 30/32 | 1158 | 31通过、1无效 | 15 | 20 |
| weak_context | downstream_signal | -0.007597 | 0.018771 | 30/32 | 100 | 32通过 | 22 | 18 |
| weak_context | target_new_attribute | -0.041127 | 0.019563 | 30/32 | 123 | 32通过 | 18 | 14 |
| weak_context | upstream_control | 0.049267 | 0.031337 | 27/32 | 111 | 32通过 | 19 | 15 |
| measurement_error | downstream_signal | -0.013885 | 0.025971 | 30/32 | 693 | 31通过、1无效 | 47 | 21 |
| measurement_error | target_new_attribute | -0.019989 | 0.021943 | 30/32 | 714 | 32通过 | 65 | 16 |
| measurement_error | upstream_control | 0.006860 | 0.026397 | 29/32 | 738 | 32通过 | 55 | 15 |
| limited_structure_data | downstream_signal | -0.023193 | 0.020591 | 30/32 | 145 | 32通过 | 28 | 17 |
| limited_structure_data | target_new_attribute | 0.030331 | 0.017388 | 32/32 | 71 | 32通过 | 7 | 13 |
| limited_structure_data | upstream_control | -0.017212 | 0.028296 | 30/32 | 112 | 32通过 | 17 | 20 |

弱上下文把三个机制的确定方向边降至100、123和111，三项均为0/10通过。结构观测降至128后，三个机制的确定方向边为145、71和112，三项均为0/10通过，并保留三个区间支持的损害结果。reference的上游机制和measurement_error的下游机制各有一个方向无效单元；两个单元均保留在32次重复和全部比较分母中。

measurement_error的`observed_graph_truth_available=false`。47、65和55仅表示与无噪机制角色的差异；10%属性翻转属于模拟压力参数，没有形成真实Graph测量错误率。132项诊断保留一个`integration_boundary_unknown=1`：measurement_error／upstream_control／`screened_logit`记录29个覆盖、两个未覆盖和一个积分边界未知，该记录没有被归入覆盖或未覆盖。

JCI判定的适用范围仅包括reference模拟条件、相同目标结果预算和独立随机效应估计的条件性方差收益。自然任务收益、自动适用、策略价值、代码安全率、完整功能、安全与功能联合成功、Graph表示收益、TSG独特贡献、Graph与JCI集成收益、未来环境稳定性及正式确认性证据均保持未建立。

## Graph组件的来源边界、固定设计与未执行事项

Graph组件的冻结证据身份如下：

| 证据 | 路径或身份 |
| --- | --- |
| 冻结设计 | `docs/experiments/2026-11-03-graph-representation-round1-design.md`；SHA256 `061c7e800618f2b0b9adc46cfa7faed5f2d6a2e6156840d899eb70e593bb3c08` |
| 固定计划 | `data/method/graph-representation-round1-20261103/plan.json`；SHA256 `ba7f5a84fcc3975737c0b53165dcc4645c7a023d4dfee564f0f5cb1a5f0a2446` |
| 组件结果 | `docs/experiments/2026-11-03-graph-representation-round1-results.md` |
| Codex CLI来源边界审查 | `data/method/graph-representation-round1-20261103/codex-cli-source-boundary-result.md`；SHA256 `0437e56716ead406f08da9af1cf2c2fcd3769b8888039a2fd11e8a57446777fe` |
| 独立只读核对 | `data/method/graph-representation-round1-20261103/codex-cli-source-boundary-verification-result.md`；SHA256 `1aded0e5287e4462113ba7a15337f0a75c8d5478905d9c79d8cffe2acbbb962e`；`VERIFIED_SOURCE_BOUNDARY` |
| 机器可读核对 | `data/method/graph-representation-round1-20261103/source-boundary-verification.json`；SHA256 `682fe425aa71d8ad7126497175fdd8f25b033ecb2dbd380827d00deec6cbe86a` |
| 组件冻结归档 | `results/graph-representation-round1-20261103-source-boundary-frozen.tar.gz`；211,926,740字节；SHA256 `838d2c753ac04eb4e696e7800fe463a59971b5e22ae7e82916fe9c5cc57a8093`；19个成员 |
| 组件外部清单 | `data/method/graph-representation-round1-20261103/source-boundary-frozen-manifest.json` |

| 项目 | 固定状态 | 实际状态 |
| --- | --- | --- |
| 任务总体 | 固定二十项来源，不删除、不替换 | Brotli保留`qualified=false`；来源资格门槛未通过 |
| 共同任务准备 | 可行性记录中十七项取得完整任务的隔离自动输入审查及独立六维绑定参考 | 没有形成满足固定二十项总体的完整生成前资格集合 |
| Requests共同输入与输出约束 | 共同输入34,122 tokens；服务上限49,152；固定候选输出8,192；表示与共同指令合计上限6,838 | 没有制作实际表示或完整提示，真实tokenizer完整提示预算未执行判定 |
| 表示制作 | Raw、Flat、Graph三种表示 | 三种表示均未制作 |
| 生成分配 | 二十项任务乘三种表示乘四个种子，共240项计划分配 | 固定计划保留；进入实际处理的分配为零 |
| 代码生成 | Qwen2.5-Coder-32B-Instruct BF16；每项8,192 tokens | 模型调用为零；没有候选代码 |
| 独立代码测量 | 安全产出、局部功能、联合成功、Oracle支持、未知和非目标漂移分别测量 | 没有候选代码，测量未执行 |
| Graph主要比较 | Graph减Raw的0.10安全改善门槛、-0.10功能非劣界限、0.025第一轮错误率 | 未执行，没有效果估计 |
| 结构归因比较 | Graph减Flat及Flat减Raw，单侧Bonferroni界限0.0125 | 未执行，没有效果估计 |

来源资格发生在表示制作和生成分配之前。Brotli资格失败没有转换为分配后的零结果。未开始的Raw、Flat、Graph比较没有零效果、有害效果或优劣估计。来源边界也没有观察实际提示长度、模型响应、生成失败、Oracle支持、安全未知、功能未知、非目标漂移、任务单位配对区间或成本结果。

Gradio和internetarchive的限定局部测量资格保留各自证据身份，不能抵消或替换Brotli。固定二十项总体、四个种子、240项计划分配、8,192 tokens输出额度、0.10安全改善门槛、-0.10功能非劣界限、0.025错误率、0.0125结构归因界限、任务等权和至多两轮规则均保持不变。旧开发检查保留已有开发身份，不进入本轮Graph证据。

## 用户原计划九项工作的执行记录

| 序号 | 工作 | 状态 | 证据路径与停止原因 |
| ---: | --- | --- | --- |
| 1 | JCI第一轮384项评价、独立汇总与核对、预定门槛及全部诊断报告 | 已完成 | 四组各96项；204项Bonferroni比较、两个批次、上游损害、弱上下文、方向错误和属性测量误差均已报告；组件结果为`JCI_ROUND1_SUCCESS` |
| 2 | internetarchive、Gradio、Brotli三项真实来源资格测量 | 已完成，资格门槛未通过 | internetarchive和Gradio取得限定局部测量资格；Brotli为`qualified=false`；独立审查为`VERIFIED_SOURCE_BOUNDARY` |
| 3 | 剩余来源的完整共同任务、独立输入审查、独立绑定参考和冻结包 | 未全部完成，按来源边界停止 | 可行性记录保留十七项完整任务的独立审查和绑定参考；固定二十项总体没有形成完整生成前资格集合，不删除或替换失败来源 |
| 4 | 最终Raw、Flat、Graph提示的信息一致性和共同输出预算冻结 | 未执行，按来源边界停止 | 三种表示均未制作；Requests完整提示的真实tokenizer预算没有执行最终判定；固定8,192 tokens输出额度保持 |
| 5 | 固定共同任务、提示和预算上的新Raw、Flat、Graph代码生成 | 未执行，按来源边界停止 | 保留240项计划分配；实际模型调用为零，没有候选代码 |
| 6 | 安全、功能、未知覆盖、生成失败和非目标漂移的独立测量 | 未执行，按来源边界停止 | 没有生成代码；不得将未开始的分配记作零结果，也没有代码结果的效果估计 |
| 7 | Graph相对Raw的安全收益、功能非劣性及Flat结构归因比较 | 未执行，按来源边界停止 | 没有安全收益、功能非劣性或图关系额外贡献的效果估计；既定比较、门槛和错误率保持 |
| 8 | 组件联合判定、同一活动方法与联合冻结结果包 | 已完成，联合科学标准未达到 | `JOINT_SCIENTIFIC_BOUNDED_UNMET`；活动方法与审阅指南已更新；联合归档十九个成员，逐文件摘要核对通过 |
| 9 | 符合前瞻条件时的一次修订与第二轮评价 | 不具备启动资格，未执行 | 来源边界要求形成有界未达标结论；`NOT_STARTED_NO_ELIGIBILITY`；没有设计或执行第二轮 |

## 第二轮与联合终点

Graph来源边界已经形成预定终止依据。删除或替换Brotli、缩减为十九项、追加来源或种子、改变端点或资源限制、降低门槛、修改分母、改变错误率或使用第二轮额度继续当前比较均不允许。第二轮资格为无，状态为`NOT_STARTED_NO_ELIGIBILITY`。当前Goal到达有界研究终点。

## 联合归档与共同交付

- 归档路径：`results/graph-jci-goal-20261103-frozen.tar.gz`。
- 归档字节数：2,403,969,788。
- 归档SHA256：`54297b6ae0ccf6433f9cd68ad11ad09942e65035545d7360724a99fa609cfe5c`。
- 归档成员数量：19。
- 成员状态：`VERIFIED_EXACT_NO_DUPLICATES`。
- 逐文件状态：从归档解出后19/19成员的字节数和SHA256与封包前文件一致。
- 可读性状态：`VERIFIED_READABLE_TAR_GZIP`。
- 联合外部清单：`data/method/graph-jci-goal-20261103/frozen-result-manifest.json`。

联合归档在完成字节数、SHA256、成员集合、可读性及逐文件摘要核对后保持不变。联合结果文档与联合清单不纳入归档；联合归档、本文和联合清单必须共同交付。

## 验证命令与结果

- `.venv/Scripts/python.exe -m pytest -q tests/test_artifacts.py tests/jci/test_controlled_transport.py`：`12 passed in 5.17s`。
- `.venv/Scripts/python.exe -m json.tool`分别解析JCI汇总、JCI独立核对、JCI组件清单和Graph组件清单：全部成功。
- 只读状态与身份核对：`VERIFIED_EXISTING_JOINT_INPUTS`；384项评价、204项比较、132项诊断，JCI独立核对状态与汇总SHA256一致，Graph为二十项固定任务、240项计划分配、表示未制作、代码生成未执行。
- `tar -tzf results/graph-jci-goal-20261103-frozen.tar.gz`：十九个成员，无重复路径，成员集合与固定列表完全一致。
- `Get-FileHash -Algorithm SHA256 results/graph-jci-goal-20261103-frozen.tar.gz`：`54297b6ae0ccf6433f9cd68ad11ad09942e65035545d7360724a99fa609cfe5c`，字节数2,403,969,788。
- 归档解出后逐成员执行`Get-FileHash -Algorithm SHA256`：19/19匹配，错误零项。
