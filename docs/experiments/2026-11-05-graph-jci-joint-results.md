# Graph/JCI联合冻结结果

## 科学状态

- JCI组件：`JCI_ROUND1_SUCCESS`，适用范围限于已核对的reference模拟。
- Graph组件：`FIXED_240_COMPLETE_GRAPH_PRIMARY_OBJECTIVE_FAILED`。
- Graph机制测量：`UNEXECUTED_PROSPECTIVE_SEMANTIC_BINDING_AND_ATTRIBUTE_MEASUREMENT`。
- 联合判定：`JOINT_SCIENTIFIC_BOUNDED_UNMET`。
- 正式协议：`formal_claim_allowed=false`。
- 后续轮次：当前研究身份没有额外修订或评价轮次。

本结果使用2026-11-03冻结的JCI第一轮和2026-11-05授权的新Graph
修订评价。2026-11-03 Graph来源边界包继续记录
`BLOCKED_SOURCE_BOUNDARY`，旧联合包继续记录
`JOINT_SCIENTIFIC_BOUNDED_UNMET`。Brotli修复资格、新Graph准备和固定240项
评价分别使用新的证据身份，没有改写旧结果。

## 七个研究阶段

1. **Representation**：固定二十项任务、完整Atomic政策、共同来源输入、
   Raw/Flat/Graph表示、独立端点说明和六维自动隔离参考。Prompt TSG关系
   只描述表示结构，不能解释为因果边。
2. **Prioritization**：JCI在Atomic臂内使用来源上下文查询，为共享平均结果
   预测器提供有限惩罚建议。
3. **Hypothesis freeze**：Graph固定二十项任务、三种表示、四个种子、240项
   分配、端点、门槛和多重性；JCI固定四个条件、三个机制、两个批次和
   204项共同比较。
4. **Intervention/randomization**：Atomic流程一次只改变一项完整要求；Graph
   表示请求顺序使用固定种子，全部失败仍保留原分配。
5. **Measurement**：安全、局部功能、Oracle支持、unknown、生成失败和非目标
   漂移分别记录。生成代码只提供独立测量结果，不能作为primary-PAG变量或
   因果中介。
6. **Outcome assembly**：Graph每个任务与表示先平均四个种子，再对二十项任务
   等权；JCI保留384项模拟分母、方向错误、覆盖未知和损害。
7. **Inference/reporting**：Graph使用精确任务级符号翻转和固定任务bootstrap；
   JCI使用204项共同Bonferroni区间及两个批次判定。报告保留全部失败、零值、
   unknown和适用限制。

## JCI冻结结果

四个条件各完成96项，共384项。四份独立核对均重放96个原生图并核对全部
单元。最终汇总含204项预定比较和132项诊断。

| 条件与机制 | 十项JCI比较 | 相对方差减少范围 | 判定 |
| --- | ---: | ---: | --- |
| reference / downstream_signal | 10/10通过 | +12.51%至+18.38% | 达到至少5%、校正区间下界大于零、两个批次均改善 |
| reference / target_new_attribute | 10/10通过 | +5.19%至+7.92% | 达到全部预定标准 |
| reference / upstream_control | 0/10通过 | -13.78%至+2.16% | 保留损害与一个精确零比较 |
| weak_context / 三个机制 | 0/30通过 | -8.53%至+3.18% | 没有方向收益支持，包含区间支持的损害 |
| measurement_error / 三个机制 | 0/30通过 | -4.06%至+2.45% | 没有方向收益支持，属性翻转不能解释为真实Graph错误率 |
| limited_structure_data / 三个机制 | 0/30通过 | -11.23%至+1.93% | 没有方向收益支持，包含三项区间支持的损害 |

reference上游、weak_context下游、measurement_error上游及三个
limited_structure_data比较保留七项Bonferroni区间支持的损害。132项诊断
保留偏差、均方误差、名义Wald覆盖、两个方向无效单元和一个
`integration_boundary_unknown`。来源上下文分离不能证明未来环境稳定。
JCI模拟成功不能扩大为自然任务、策略价值、代码安全、完整功能或Graph/JCI
集成收益。

## Graph准备、执行与测量

新Brotli修复测量完成162/162项，三个角色各54项。`reference`安全15/15、
功能39/39；`original`和`late`分别保留预定控制语义；执行失败和unknown均为
零。共享测量程序改用已交付输出长度的增量计数，10秒CPU、20秒墙钟和
512MiB地址空间限制保持。internetarchive完成135项局部测量，Gradio完成
132项局部测量，三项来源均只支持各自固定端点。

二十项共同任务、六维自动隔离参考、六十个独立作者会话、六十份表示和
六十份最终提示均已冻结。三种表示共享完整输入和8,192-token输出预算。
实际最大输入为37,621 tokens；加输出额度和256-token边界保留后为46,069，
低于49,152服务窗口。该预算结果不能建立超过模型配置32,768原生位置长度
后的质量结论。

固定240项请求均返回HTTP 200，239项`finish_reason=stop`，一项为`length`。
全部响应的首个非空行都是Markdown围栏，Raw、Flat和Graph各80项均以
`RESPONSE_IS_NOT_A_BARE_UNIFIED_DIFF`终止。安全程序和功能程序均未取得
可执行候选，检查计数分别为0/0和0/0。

| assigned-arm结果 | Raw | Flat | Graph | 合计 |
| --- | ---: | ---: | ---: | ---: |
| 分配 | 80 | 80 | 80 | 240 |
| 生成失败 | 80 | 80 | 80 | 240 |
| 安全代码产出 | 0 | 0 | 0 | 0 |
| 局部功能成功 | 0 | 0 | 0 | 0 |
| 安全并且功能成功 | 0 | 0 | 0 | 0 |
| 安全unknown | 0 | 0 | 0 | 0 |
| 功能unknown | 0 | 0 | 0 | 0 |
| Oracle不支持 | 0 | 0 | 0 | 0 |
| 观察到的非目标漂移 | 0 | 0 | 0 | 0 |
| 非目标漂移unknown | 80 | 80 | 80 | 240 |

安全unknown、功能unknown和Oracle不支持为零来自冻结的应用前生成失败分类。
这些零值不能证明候选安全、完整功能或Oracle支持。观察漂移为零且漂移状态
全部未知，不能建立漂移缺失。

## Graph预定判定

Graph减Raw安全点差为0.00，低于+0.10门槛；单侧0.025下界约为
`-8.333333074159524e-14`，没有大于零。Graph减Raw局部功能的同一下界大于
-0.10，因此形式上的非劣性通过。安全条件失败后，主要代码目标失败。

Graph减Flat安全点差为0.00，Bonferroni单侧0.0125下界约为
`-9.9999998245167e-14`，安全条件失败；局部功能非劣性形式上通过。
Graph减Raw主要标准和Graph减Flat安全标准均未满足，图关系额外贡献没有获得
支持。Flat减Raw安全点差同样为零，功能非劣性形式上通过。全部形式非劣性
结果来自共同失败规则下的全零端点，不能用于表示等价或可应用代码功能声明。

216项请求含较早完整模块输出措辞和末尾统一补丁合同冲突。末尾条款明确控制
响应格式，其余24项没有该早期冲突的请求也全部失败，现有证据不能量化文本
冲突的因果贡献。Git只读解析得到损坏195项、缺少补丁头20项、零路径17项、
没有有效补丁3项和解析出路径5项；五项路径均不等于声明目标。没有执行
`git apply --check`或实际应用，不能声称存在可应用候选。

## 表示机制证据边界

二十项六维自动隔离参考均先于表示作者工作冻结，十七项旧参考与当前输入身份
17/17匹配。当前`preparation-verification.json`把十七项输入审查摘要同时写入
绑定参考字段，没有记录实际独立参考文件身份。三项新增参考保存十项分歧，
参考均为`human_gold_reference=false`。评价完成后形成的
`reference-freeze-v2/reference-identity-index-v2.json`逐项记录十个原冻结归档、
二十个精确成员、文件字节与摘要、二十份原字节副本，以及任务、来源和锚点
20/20匹配。该索引补齐当前交付身份追踪，保留旧准备清单的历史错误，也不追认
生成前审查已经执行。

六十份表示的共同输入、公平性、作者隔离、结构格式、字符预算和候选代码缺失
具有直接证据。六十份表示没有原设计要求的单独事实清单；生成前独立语义信息
一致性停止条件缺少执行证据。完整绑定、对象与操作绑定、条件归属、政策来源、
量词、保留义务、unknown处理和前处理属性准确性均未测量。241项unknown属于
作者自行声明，不能作为独立准确性结果。评分单位、分母、unknown与分歧处理、
裁决、聚合、门槛、区间和多重性规则也没有前瞻冻结。

该缺口限制Graph主要结果的机制解释。固定240项代码端点仍按原规则完整报告；
现有材料不能把共同格式失败归因于表示质量，也不能形成完整Graph机制成功。

## 原九项范围

| 序号 | 原研究目标 | 当前证据状态 |
| ---: | --- | --- |
| 1 | JCI第一轮384项与主要机制标准 | 已完成；reference两个机制通过，上游损害和三个压力条件失败完整保留 |
| 2 | internetarchive、Gradio、Brotli真实来源资格 | 已完成；采用各自固定端点，Brotli新身份完成162/162，旧失败身份保持 |
| 3 | 二十项共同输入、独立输入审查与绑定参考 | 共同输入、参考存在性及评价后20/20准确身份索引已完成；旧准备清单仍保留十七项历史登记错误，独立表示语义比较未执行 |
| 4 | 六十份表示、提示、信息一致性和预算 | 表示、提示和预算已完成；原定生成前独立语义一致性审查未执行 |
| 5 | 固定240项新生成 | 已完成；240项HTTP 200，240项共同格式失败 |
| 6 | 安全、功能、unknown、失败和漂移测量 | 全分母结果已完成；安全与功能程序检查为0/0，漂移unknown为240/240 |
| 7 | Graph减Raw主要判定与Flat结构归因 | 已完成；主要目标失败，Graph关系额外贡献没有获得支持 |
| 8 | JCI与Graph联合活动方法、结果和判定 | 已完成；联合状态为`JOINT_SCIENTIFIC_BOUNDED_UNMET` |
| 9 | 一次前瞻修订及停止边界 | 2026-11-05修订已使用且没有额外轮次；生成前独立语义一致性停止条件缺少执行证据，因此该项未完整完成，当前身份停止 |

## V2干净环境审阅复现

项目专用新源码、资料和结果目录使用独立Python 3.12.13环境执行了当前默认四单元smoke及其独立核对、从新提取Graph归档执行的240项独立格式核对、原冻结JCI组件的`summarize.py`与`verify_aggregate.py`。Rscript 4.1.2、pcalg 2.7.12、jsonlite 1.7.3及固定原生依赖按实际身份复用；完整操作系统没有重建。全部命令采用单个工作进程、`OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`和项目内临时目录。没有新增被试模型请求，也没有重新执行384个JCI学习单元或native-R逐单元核对。

六项执行的退出状态均为0。smoke保持`NON_CLAIM_PROGNOSTIC_STRUCTURE_LEARNING`，独立核对覆盖4个单元、816个模型和2,840项条件独立查询。Graph重建覆盖240项逐项记录，所有文件、内容、目标身份、首行规则和全分母一致；仅`assignments_path`、`graph_root`和`measurement_protocol_path`三个提取路径字段经过显式归一化。JCI新汇总与冻结汇总原字节相同，均为137,932字节和`af02ef80…b6ac2`；新独立核对与冻结核对原字节相同，均为320字节和`424a68ae…79270`。综合核对状态为`CLEAN_SUPPORTED_ENVIRONMENT_REPRODUCTION_VERIFIED`。

完整环境身份、精确命令、退出状态和输出摘要位于`data/method/graph-representation-repaired-20261105/joint-reporting-coordinator-20261105/CLEAN_ENV_VALIDATION_RUN_V2.md`及其`verification/clean-*-v2.json`文件。该复现验证冻结输出和审阅入口，不增加科学证据轮次。

## 数值与实现映射

| 科学值 | 冻结输入 | 实现与结果字段 | 报告生成路径 | 复现入口 |
| --- | --- | --- | --- | --- |
| internetarchive 135项来源资格 | `results/internetarchive-path-contract-20261103-frozen.tar.gz`，SHA-256 `7db7b0fe…d0d9f8` | `run.py`写入`result.json`；`verify.py`独立读取请求、子进程与文件观察并写入`verification.json` | `2026-11-03-internetarchive-path-contract-results.md`的完整控制结果表 | 在冻结服务器输入中执行报告所列`run.py ... full`与`verify.py ...`两条完整命令 |
| Gradio 132项来源资格 | `results/gradio-path-contract-20261103-frozen.tar.gz`，SHA-256 `d4139e97…aa9045` | `run.py`的`total_checks`与`local_path_measurement_qualified`；`verify.py`的`controls`、`total_checks`和`result_sha256` | `2026-11-03-gradio-path-contract-results.md`的三项真实控制表 | 在报告登记的固定镜像和输入中执行`run.py OUTPUT`，随后执行`verify.py OUTPUT VERIFICATION` |
| Brotli 162项修复资格 | 修复冻结包`f768a90c…e5ff1c`及固定`protocol.json` | `case_worker.py::observe_valid`增量累计已交付长度；`run_measurement.py`与`verify.py`结果中的162项、三个54项角色及unknown字段 | `codex-cli-completion-report.md`的162项结果与控制语义表 | 完成报告“完整复现命令”中的固定构建、执行和独立核对命令 |
| 六十份提示预算 | 表示冻结包`a7928111…e6c46`内六十份提示与真实tokenizer记录 | 表示阶段预算记录的`input_tokens`、`max_tokens=8192`、`context_limit=49152`和`boundary_reserve_tokens=256` | `REPRESENTATION_FINAL_REPORT.md`的真实token预算核对 | 解开表示冻结包，逐条核对冻结提示及预算记录；包身份与成员规则由`REPRESENTATION_FREEZE_VERIFICATION.json`固定 |
| 二十份实际独立参考身份 | 九个旧冻结归档与前生成冻结包`d5d9d16a…67f499`中的精确参考成员 | `verify_reference_identity_index.py`；索引的`original_member_path`、文件摘要、冻结副本和三类`identity_match`字段 | `reference-identity-verification-v2.json`的20/20唯一任务、原字节和身份核对 | `python verify_reference_identity_index.py --repo-root C:\MyCode\causal --index reference-freeze-v2\reference-identity-index-v2.json --output reference-freeze-v2\reference-identity-verification-v2.json` |
| Graph 240项分母与失败计数 | `plan.json`、`bindings/future-assignments.json`、`measurement-protocol.json` | `analyze_results.py::build_rows`; `counts.assigned`、`counts.generation_failures` | `GRAPH_EVALUATION_FINAL_REPORT.md`“全分母结果” | `analyze_results.py --protocol ... --result-root ... --output ...` |
| Graph任务等权点估计与精确区间 | 同上及240份`outcome.json` | `task_method_values`、`binary_analysis`、`exact_lower_bound`; `binary.<metric>` | `GRAPH_EVALUATION_FINAL_REPORT.md`“预定统计结果” | 同一分析命令及独立核对命令 |
| Graph主要与关系判定 | `design.md`与`measurement-protocol.json` | `scientific_decision`; `scientific_decision.*` | `GRAPH_EVALUATION_FINAL_REPORT.md`判定条目 | `independent_verify_repaired.py`重建全部字段 |
| 240项首行格式失败 | 原始`raw-response.txt`、`response.json`、`candidate-response.txt`和应用记录 | `verify_frozen_graph_format.py`; `counts.markdown_fence_first_nonempty_line`与`counts.format_failures` | `FORMAT_FAILURE_FINAL_REPORT.md`及新核对JSON | `verify_frozen_graph_format.py --assignments ... --graph-root ... --output ...` |
| 216项提示合同冲突和Git解析分类 | 固定240项`request.json`与原始响应 | `FORMAT_FAILURE_FINAL_REPORT.md`登记的独立只读检查；`request_conflicts=216`及Git分类195/20/17/3/5 | 同报告“240项请求合同核对”和“Git只读解析” | 按该报告执行记录重新读取全部请求与响应；不调用应用程序、不执行`git apply --check` |
| JCI 384项、204项比较与132项诊断 | 四份冻结计划和`results/jci-robustness-round1-20261103-complete-results.tar.gz`内四组96项结果 | `summarize.py`; `cells`、`comparisons`、`descriptive_diagnostics`、`reference_gate_passed` | `codex-cli-final-review-result.md`直接读取冻结`summary.json`形成主要比较表和诊断表 | `python data/method/jci-robustness-round1-20261103/summarize.py results/jci-robustness-round1-20261103-results results/jci-robustness-round1-20261103-analysis-reproduced/summary.json` |
| JCI独立汇总核对 | 同一四组已核对结果和上一步汇总 | `verify_aggregate.py::diagnostic`与`main`; `aggregate_sha256` | JCI最终科学审查“证据完整性” | `python data/method/jci-robustness-round1-20261103/verify_aggregate.py results/jci-robustness-round1-20261103-results results/jci-robustness-round1-20261103-analysis-reproduced/summary.json results/jci-robustness-round1-20261103-analysis-reproduced/verification.json` |
| 联合判定 | Graph的`scientific_decision`、JCI清单的`component_decision`及两份冻结设计 | 两个组件预定标准的逻辑合取；字段为`FIXED_240_COMPLETE_GRAPH_PRIMARY_OBJECTIVE_FAILED`和`JCI_ROUND1_SUCCESS` | 本文“研究状态”和“原九项范围” | 分别运行Graph独立核对与JCI独立汇总核对，然后核对两个组件判定；不合并端点或分母 |

Graph报告表格直接读取冻结`production-analysis.json`字段，没有单独论文表格构建器。
JCI表格直接读取`summary.json`中的`comparisons`和`descriptive_diagnostics`。
本结果没有修改论文LaTeX或建立图表。

## 冻结身份与适用范围

- 新Graph结果归档：9,340,198字节，SHA-256
  `4ea939de468368590e074c3ca1db2c587444d043663167b663a02f5752942584`。
- JCI组件归档：2,191,231,231字节，SHA-256
  `44db172714253be7787a4e375c3dcf7365d12f7c6b80473f937823817069eb1f`。
- Brotli修复归档：142,848,724字节，SHA-256
  `f768a90c5a66fb8102a7125aa08792ed7f543585f9dd9e412540618f90e5ff1c`。
- 旧Graph来源边界包：211,926,740字节，SHA-256
  `838d2c753ac04eb4e696e7800fe463a59971b5e22ae7e82916fe9c5cc57a8093`。
- 旧2026-11-03联合包：2,403,969,788字节，SHA-256
  `54297b6ae0ccf6433f9cd68ad11ad09942e65035545d7360724a99fa609cfe5c`。

证据范围限于冻结模拟条件、二十项程序任务、三种表示、四个固定种子、指定
Qwen服务和自动局部测量。程序测量不能建立完整功能或普遍安全覆盖。自动隔离
参考与表示作者共享模型系列，相关错误仍可能存在。该结果不建立自然任务JCI
效用、Graph完整语义准确性、集成系统收益、未来环境稳定性或正式确认结论。
