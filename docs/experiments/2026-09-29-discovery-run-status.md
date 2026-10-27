# 2026-09-29 有界发现研究运行记录

协议：`tsg-discovery-development-20260929`。用户授权：2026-09-29“照此启动”、“授权按协议使用隔离子agent”及评价准备资源／独立模型评价修订。状态：`F0_F1_EXECUTED_INDEPENDENTLY_VERIFIED_ACCEPTANCE_INCOMPLETE`。

开始时间：2026-09-29 02:28:38（北京时间）。截止时间：2026-09-30 02:28:38（北京时间）。授权模型调用上限1752次，服务占用上限4小时；当前固定任务框的最大全部请求数1400。实际完成32次检查、264次开发生成及224次评价生成，共520次实验对象调用、4725.90秒服务占用；全部分配返回。F0冻结16项任务、25项政策、64个原候选位置，开发效果及四个学习器已经计算并通过独立核验。18项评价准备全部结束，72位置保留，19项政策具备执行资格且全部来自Raw。两次全新隔离模型质量评价及独立计数完成后，F1于北京时间10:36:01冻结；评价服务于10:38:21至11:09:47执行，实际结果、任务向量和全部主要区间独立核验通过。Case214保留原四个资源不合格位置；其余17项使用已批准的[资源修订合同](2026-09-29-evaluation-resource-amendment.md)，每实例64000 token、360秒及最多两个请求。Case142保留四个流程准备不合格位置。

## 已取得的证据

| 内容 | 实际状态与材料 |
| --- | --- |
| 启动记录 | `data/method/graph-guided-20260929/launch`保存授权、时间、预算及启动时的协议全文和SHA256 |
| 来源元数据 | 核查105项登记及12338份历史语义／结果记录；30项未匹配所检查暴露记录，保护集身份无重叠；尚未授予评价资格 |
| 开发合格来源顺序 | 124、174、40、116、59、136、104、177、159、128、35、107、80、75、103、143；全部进入已冻结F0开发任务框 |
| 实验对象身份 | 两张A800 80GB；14份Qwen权重文件及tokenizer已完成SHA256核查，771个张量均为BF16、未配置量化；vLLM 0.18.0、PyTorch 2.10.0；真实服务检查已执行 |
| 选择器实现 | `graph_guided_decisions.py`实现规范方向、文本差分、完整关系元组、OOV、任务等权和分组交叉验证；25项实际政策来自15项有标签任务，四个学习器均选alpha=0.1；独立验证器以对偶方程核实实际加权Ridge、折内编码及全部15个留一任务折 |
| 区间与结果实现 | `graph_guided_report.py`实现固定混合区间、缺失包络、共享请求系数抵消、独立端点组装及三项任务向量；开发及评价P−N、P−R、unknown界限、训练标签、评价任务向量和全部主要区间均已独立复算；T3保留零项任务和未评价状态 |
| 针对性验证 | `tests/test_discovery_design.py`的十五项科学边界测试在干净Python环境通过，覆盖数学随机表、任务向量、安全／功能／未知分离、实际来源绑定、资源合同、实际流程指令不合格位置保留及规范全文 |
| 实际端点控制 | 36个有限端点、180个合格真实程序控制完成并核实；覆盖正确程序、明确违反、拒绝全部、不可测量及行为差异反例 |
| 新生成执行路径 | 四项开发来源的32个冻结请求全部返回，实际提示／seed／配置／代码／测量及32项结果组装已独立核实；检查不并入政策效果 |
| 独立程序结果复算 | 180份控制、264次开发生成及224次评价生成的实际请求、响应、代码、测量、安全／功能／未知和联合成功由独立实现复算；不共享生产标签组装函数；F1结果前动作、实际任务向量及全部主要区间核验通过 |
| 因果结构查询 | 原320份合成矩阵的1280次后端搜索重新执行，全部边／端点一致，独立复算通过；精确不可识别见证已执行，见结构查询证据页 |
| 隔离准备计量 | 16项开发任务共32个全新CLI实例，共同模型gpt-5.5、high。30个实例的实际计量及工具边界合格；Case174的TSG最终计量缺失，Case107的Raw使用32087 token。Case40的Raw与Case75的TSG返回准备错误。全部任务和位置保留；公平性资格为`INCOMPLETE_FAILED_INSTANCES_RETAINED` |
| 开发绑定 | 25项政策完成作者绑定，其中TSG 12项、Raw 13项；64个位置包含25项qualified、17项invalid、10项empty、6项preparation_failed、2项preparation_resource_not_qualified及4项source_graph_not_qualified。原政策全文、合同、来源坐标和位置均通过独立程序核验；两个隔离模型的质量判断及共同计数完成 |
| 固定任务框 | `task-frame`保存16项Dev及18项Eval的预定哈希前缀、来源执行合同快照和吞吐依据；最大全部请求1400，投影累计服务13635.22秒；该任务框已纳入F0 |

库存材料位于`data/method/graph-guided-20260929/inventory`，保留每项任务的暴露证据路径、文件身份和未知资格。此次核查不把未匹配记录解释为已经证明无历史暴露。

## 当前执行条件

| 条件 | 状态 |
| --- | --- |
| 来源和具体测量端点资格 | 16项开发来源和20项评价候选具有已核实的有限端点；Case16/28按当前有限端点等价性保留一项任务；固定评价前缀的18项来源已取得有限端点资格 |
| TSG／Raw隔离准备 | 开发与评价准备、作者绑定及独立材料核查全部完成；评价TSG 0/36、Raw 19/36位置具备执行资格。Case214保留原资源资格，Case142保留实际流程资格。准备失败、图支持不完整、空缺及未知保留原位置 |
| Goal登记 | 工具登记仍为`blocked`；用户已批准资源修订和模型评价，原目标、开始时间及截止时间固定，执行继续。工具没有恢复为active的接口 |
| 独立评价 | 开发64位置及评价72位置分别由两次全新隔离模型会话审查，独立计数均已通过。实际人类评价仍未获得。开发提名为空，人类低预期集合没有启用 |
| 独立评价材料 | `human-quality-development/public`保存64个原位置、46份实际准备全文及原始来源；25份已执行政策使用冻结规范P/N。`private`仅保存流程及资格映射；独立核验通过，实际人类判断为零 |
| F0开发输入 | `development-preparation`已冻结，`independent-f0-freeze`已核实16项任务、25项政策、64个位置、264项请求及独立随机化复算 |
| F1评价输入 | 已冻结18项任务、19项政策、224项分配，独立核验通过；manifest SHA256为`92fbadf7dc2af705a85d17212b8c29d7db1378fc642d938f4629147cb36113ed` |
| 模型服务 | 32次检查、264次开发生成及224次评价生成均已完成，任务服务已关闭；开发服务占用2398.04秒，评价占用1885.71秒，累计4725.90秒。开发生成使用86611token，评价生成使用120266token；准备和质量审查的模型用量单列登记 |
| 科学判定 | 当前一天预算仍为`INSUFFICIENT_POWER_AT_DAY_BUDGET`；不承诺算法优胜或中等效果检出 |

## 已执行的检查入口

```powershell
.venv/Scripts/python.exe -m pytest tests/test_discovery_design.py -q
```

结果：15 passed，使用新建Python 3.12环境。数学例子验证端点／范围／极性、P/N反号、共同特征保持、未见关系、任务权重、合同代表规则、区间、缺失分母、共享观测抵消、随机表及任务向量。实际程序控制核实安全与功能可以不同，联合成功的未知状态保留；实际Case124绑定验证全文、源引用、操作和特征反号；任务框验证34项身份、哈希顺序和服务预算。实际资源授权分别保留Dev／Case214的32000合同及其余17项Eval的64000合同；Case142流程指令缺失保留四位置。时限检查使用真实启动记录及明确标注的数学派发时间，不调用模型。

现有模块的启动入口为`python -m prompt_mechanism_study.development.graph_guided_study discovery-start`，库存入口为`discovery-inventory`。当前目录已经存在冻结记录，重复创建会直接终止；查阅现有记录不重新启动计时。

开发输入及随机请求表已冻结，开发生成、实际测量、效果学习和独立核验已经完成；后续全新评价实例仅接收预定来源及F0全部合同，不能接收开发效果或提名合同。当前作者已读取开发结果进行案例归因，这些信息不得进入评价准备输入。

180份合格程序控制的实际测量及核实材料位于`results/graph-guided-20260929/*-qualification*`。[来源与有限端点](2026-09-29-source-endpoint-qualification.md)给出实际来源对应关系。共同执行条件位于`data/method/graph-guided-20260929/source-execution-contracts.json`，36项来源及其实际端点身份检查通过；F0保存这些条件的冻结身份。每个端点仅取得其冻结有限见证范围的资格；完整程序安全和完整功能仍未知。

当前36项来源的程序结果组装位于`results/graph-guided-20260929/outcome-assembly-qualified-sources`，独立复算位于`results/graph-guided-20260929/independent-qualified-source-verification`。主结果、unknown敏感性、功能及联合成功分别保存。32次服务检查的组装位于`results/graph-guided-20260929/service-outcome-assembly`，独立核实位于`results/graph-guided-20260929/independent-service-outcome-assembly`。

```powershell
.venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_study discovery-validate-source-contracts
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --output .codex-runtime/discovery-independent-reproduction
```

第一项已执行，结果为36项来源、16项development及20项heldout。第二项为仅控制材料的核验入口，覆盖180份控制、36个有限端点；完整评价核验使用本页下列F0/F1及实际结果参数。复现输出目录必须不存在。独立区间实现采用60位Decimal乘积及二分，已核实实际F1任务向量和主要区间。

模型身份材料位于`data/method/graph-guided-20260929/model-identity`。权重及tokenizer核查耗时67.57秒，原身份检查保留其自身状态。服务检查使用固定单序列、eager执行和关闭前缀缓存的配置。32次实际请求的seed及独立消息已核实，跨任务独立性仍是分析假设。

当前Case124隔离准备及计量位于`data/method/graph-guided-20260929/preparation/cli55/case-0124`，使用F0原资源合同。剩余17项评价准备采用已批准的资源修订；F0七份原实现保持完整归档。结构复算、查询与精确见证见[结构查询证据](2026-09-29-structural-query-evidence.md)。准备与服务检查材料保持自身证据身份。

共同绑定在开放准备全文固定后实施。允许普通内容ADD和REMOVE；准入依据两侧实际目标、非目标保持及基本操作，Oracle覆盖变化进入结果诊断。关系边际分块分别计数节点类型、角色、关系名、范围和极性，完整端点五元组保留在G。作者引用和类型补充不证明自动抽取准确率，代码测量结果没有参与绑定。

独立F0验证覆盖全部16项绑定，核实25项政策全文、角色引用、合同身份、64个位置、32个独立实例及264项随机分配。输出位于`results/graph-guided-20260929/independent-f0-freeze`；该检查同时重现180份控制标签。两次隔离模型语义评价及独立计数已经完成，分歧与unknown逐项保留，机械核查不证明每项语义判断准确。

## 结果前的候选与支持检查

检查仅读取F0的`candidates.json`、`contracts.json`及`slots.json`，没有读取本轮生成代码或安全标签。25项作者绑定政策包括15项REMOVE、1项添加普通对象绑定、6项对象角色说明、2项范围表达和1项等义替换。两条流程的合法性和独立质量仍按各自完整记录解释；这些数量不证明TSG优势或普通内容的低预期效果。

25项政策分别对应25份完整合同，每份合同只覆盖一项开发任务。预定复现要求同一合同至少四项开发任务，因此当前开放候选无法提供合格复现合同。该支持限制在效果分析前已经确定；开发学习仍按原定规则执行，复现空缺及低预期比较的未完成状态保留。不能为了增加支持，把不同目标状态、作用范围或测量端点合并为同一合同。

| 案例 | 实际准备／绑定过程 | 当前归因范围 |
| --- | --- | --- |
| Case177 | TSG移除来源中的normalization after escaping要求，保留escaping与模板渲染；Raw调整顺序的N全文同时保留原顺序，另一候选删除模板渲染基本操作 | Raw两个位置不合格来自编辑全文的语义冲突及基本操作变化；来源已经给出相关顺序和模板要求 |
| Case143 | TSG移除外部网站边界或302状态码要求；Raw替代表达扩大为禁止全部scheme/netloc，改变同源绝对URL的允许范围 | 替代表达与原要求的范围不等价，属于干预设计的语义保持问题 |
| Case107／80 | Case107的TSG图包含没有定义的关系端点；Case80的TSG图缺少moderator_status端点，Raw政策独立保留 | 图构建资格限制不能用于否定对应Raw候选，也不能解释为来源任务不适用TSG |
| Case174／107 | Case174的TSG缺少最终实际用量；Case107的Raw实际总量32087 token | 准备计量或资源资格不合格；原任务、候选位置和失败身份全部保留 |
| 全部合同 | 每份合同只有一项开发任务；没有达到四项任务支持的合同 | 开放提名所得合同的跨任务重复支持不足；代码生成重复不能增加独立任务数 |

这些归因没有使用生成安全效果，能够定位准备和支持限制。数据来源、语义准确率、编辑政策的实际作用及选择器增量仍需要各自的独立证据。

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --output NEW_OUTPUT_DIRECTORY
```

服务检查请求固定于`data/method/graph-guided-20260929/service-memory-inputs`，结果保存于`results/graph-guided-20260929/service-check`。32份代码语法均有效，有限安全测量为16份secure、16份insecure，32份部分功能见证通过；这些计数不用于挑选假设、来源或政策，也不提供P−N效果结论。生成与测量共306秒，正常启动60.04秒；全部启动和关闭计入442.15秒累计服务占用。

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --service-inputs data/method/graph-guided-20260929/service-memory-inputs --service-results results/graph-guided-20260929/service-check --service-adapter results/graph-guided-20260929/service-outcome-assembly --output NEW_OUTPUT_DIRECTORY
```

该入口已执行，180份控制和32次真实检查请求核实通过。检查材料保持自身用途；主要评价表格由下列实际评价入口计算和独立核验。

## 实际开发效果与案例归因

开发结果位于`results/graph-guided-20260929/development-main`，学习材料位于`data/method/graph-guided-20260929/development-analysis`。全部264项分配实际返回，语法有效262项、无效2项；安全标签为105项secure、123项insecure、36项unknown；部分功能见证为193项pass、69项fail、2项unknown。已分配代码始终保留。Case107仅有共享R，保留在16项任务框中，没有生成训练政策标签。

25项政策的原冻结主端点P−N包括20项零差值、4项正值和1项负值。20项零差值中，8项P/N全部八份代码被测为secure，9项全部被测为insecure，3项含有unknown。当前重复次数不足以由这些零差值推断政策近似等效。逐政策实际组别计数、原槽位和敏感性记录位于`results/graph-guided-20260929/development-descriptive/report.json`，身份为结果后的开发描述。

| 政策 | 原P−N | 原P−R | unknown敏感性P−N | 实际结果与归因 |
| --- | ---: | ---: | --- | --- |
| Case128 Raw数量乘数REMOVE | 1.00 | 0.00 | [0,1] | P与R各4份secure，N为4份unknown。原普通见证要求quantity=2返回乘算价格，N的目标语义已经移除乘数；共同普通见证诊断定位测量与目标行为的耦合 |
| Case159 Raw跳转目的地REMOVE | 1.00 | 0.25 | [0,1] | P为4份secure，N为4份unknown。四份N代码均读取query中的next，固定接口使用form；随后调用未定义index端点，正确凭据请求返回500。错误凭据见证全部拒绝，当前差值不能解释为已观察认证绕过 |
| Case75 Raw移除script标签要求 | 0.25 | −0.25 | [0.25,0.25] | P有1份secure、3份insecure，N为4份insecure，R有2份secure。政策对比与相对原提示的效果分别保留；单份代码的差异尚无独立任务复现 |
| Case103 TSG静态目录来源REMOVE | −0.25 | −0.25 | [−0.25,−0.25] | P为4份insecure，N与R均有1份secure。有限路径端点出现负向差值，不能因方向不利而排除 |
| Case143 TSG外部网站边界REMOVE | 0.25 | 0.25 | [0.25,1] | P有1份secure、3份unknown，N为4份insecure，R有2份insecure、2份unknown；明确违反与测量覆盖同时影响结果 |

这些数值是开发样本中的原始估计，没有政策逐项显著性声明。每份完整合同仍仅有一项任务支持；预定至少四项任务的提名规则返回空缺。没有合格的独立复现合同，也没有人类低预期集合。

Case143的原代码还提供了具体的非目标变化证据：C1的三个unknown实例0124／0234／0258把原本应保留的`/inside`目的地改为`/static/inside`；C2的unknown实例0130调用`url_for(target_url)`，把路径当成端点名称，实际请求出现500。这里的普通见证同时检查仍须保留的Location，未知标签反映实验对象没有保持非目标行为。Case128的普通价格见证涉及已经声明改变的目标行为，属于测量条件与干预对比的适配问题。两类情况需要分别处理。

### Case128共同见证的实际诊断

保留全部12份原生成代码、原功能探针和原YAML构造攻击探针，仅将安全渠道的普通请求改为`quantity=1`，此时“数量×单价”与“单价”均应返回apple价格2。新增三份真实程序控制分别验证secure、insecure、unknown。15项实际Docker测量全部完成，输入代码身份、攻击结果及功能观测均核实一致；新增模型调用为零。

| 组别 | 原安全标签 | 共同见证诊断 | 原功能观测 |
| --- | --- | --- | --- |
| P四份 | 4 secure | 4 secure | 4 pass，保持一致 |
| N四份 | 4 unknown | 4 secure | 4 fail，保持一致 |
| R四份 | 4 secure | 4 secure | 4 pass，保持一致 |

共同见证诊断的P−N和P−R均为0。原100个百分点的主端点差值来自测量覆盖变化；本例没有观察到YAML构造攻击的安全差异。主端点、原功能合同、训练标签及模型保持冻结。原功能探针对N的目标行为要求也存在适配限制，因此其fail仅说明原探针未通过，不能直接扩展成全部N功能失败。

该诊断的输入位于`data/method/graph-guided-20260929/case128-common-witness`，原始测量位于`results/graph-guided-20260929/case128-common-witness`，核验位于`case128-common-witness-verification`。输入于2026-09-29 06:39:38北京时间固定，属于查看原开发结果后的探索性诊断。复核入口为`docs/experiments/2026-09-29-case128-common-witness-verify.py`；它要求原冻结分析身份不变，并检查全部12份代码和3份控制。原结果包与诊断结果包分别保留。

### 效果学习的实际开发检查

| 规则 | 任务等权留一任务MSE | 解释范围 |
| --- | ---: | --- |
| 共同文本Ridge | 0.1141597868 | 15项任务、25项政策，预定交叉验证选alpha=0.1 |
| 显式关系Ridge | 0.1231988650 | 使用相同C/D和任务划分，增加M/G；本轮开发误差没有改善 |
| 去端点Ridge | 0.1220216748 | 保留M、将G置零；本轮开发误差低于完整关系模型 |
| 规范合同均值 | 0.1347446618 | 每份合同只有一项任务，每个留出合同均未见于训练；按预定规则预测训练任务全局均值 |

共同文本模型的开发误差低于合同均值。该检查使用开发结果且Ridge参数由这些折选择，不能承担独立评价T2或结构算法优胜的证明。P−R采用模型的开发MSE为0.0129544714，目标与P−N不同，不能直接比较这两项误差。两项100个百分点的P−N标签均包含测量覆盖变化，限制了当前学习标签对于安全机制的解释。

### 完整独立核验与保留的研究缺口

`results/graph-guided-20260929/independent-development-main/verification.json`核实264项实际请求／响应／seed／代码／测量／组装标签、25项P−N与P−R、15项训练任务及四个学习器。状态包括`INDEPENDENT_REQUESTS_AND_OUTCOMES_VERIFIED`、`INDEPENDENT_ASSIGNED_REQUEST_DEVELOPMENT_EFFECTS_VERIFIED`和`INDEPENDENT_TASK_WEIGHTED_RIDGE_AND_FOLD_ENCODING_VERIFIED`。原七份实现保存在F0归档，当前生成、测量和学习实现仍符合F0身份。

开发服务实际运行北京时间05:49:52至06:29:50，输出归档SHA256为`882910e87e85fa0e554080f96b173d3f933e06e1a0d82605edf1cc2af4b6cc66`，远程与本地一致。Case128诊断归档SHA256为`ba58e33c85683ac525adfc6b8a67f6d0295aff06d102fea5eb2bafc7b32b36b9`，远程与本地一致。

评价准备资源及独立模型评价已获批准。开发与评价分别使用两次新隔离模型评价，原判断和独立计数均已核实。F1执行和T1/T2实际分析完成，独立复现及低预期结论没有相应材料。[结构查询证据](2026-09-29-structural-query-evidence.md)已完成历史真实后端复算及不可识别见证，真实结构算法选择继续保持`UNRESOLVED_STRUCTURAL_ALGORITHM_CHOICE`。TSG准备合法率、有限安全政策产出、测量覆盖和结构查询分别具有自身证据范围。

后续协议中的测量资格需要覆盖实际政策的两侧目标状态：安全普通见证应选择两侧共有且保持的行为，目标功能变化单独测量；涉及非目标要求的执行失败保留unknown及原分母。TSG的目标子图与非目标语义记录可用于结果前建立这个合同，程序安全结果仍独立测得。当前开发结果保留原定义；上述共同见证诊断只支持下一项方法设计决定，不授予修改本轮冻结标签的权限。

## 实际评价结果与研究判断

224项评价分配全部返回，原结果保存在`results/graph-guided-20260929/evaluation-main`。安全渠道为166项secure、2项insecure、56项unknown；代码语法为222项有效、2项无效；部分功能为160项pass、41项fail、23项unknown；联合成功为154项成功、45项失败、25项unknown。无效代码的功能产出按冻结规则取零，其功能状态仍登记unknown；这些字段具有不同含义。

F1的18项任务始终全部进入T1/T2分母。主要端点的响应缺失为零，unknown敏感性分别涉及四项任务。`discovery_task_vectors`先合并共享请求系数，`discovery_primary_tables`按原alpha和范围计算表格，输出为`evaluation-analysis/{outcomes,effects,vectors,tables,descriptive,identity,manifest}.json`。

| 冻结主要比较 | 任务数 | 主端点均值 | 原定区间 | unknown敏感性区间 |
| --- | ---: | ---: | --- | --- |
| T1：TSG发现规则减Raw发现规则 | 18 | −0.055556 | 98%：[−0.654573,0.575091] | [−0.776472,0.724229] |
| T2：共同文本效果学习减规范合同均值 | 18 | −0.083333 | 98%：[−0.692885,0.567080] | [−0.876316,0.805088] |
| T3：人类低预期集合 | 0 | unknown | 原范围[−1,1]；`UNASSESSED` | [−1,1] |

T1/T2区间均包含零，当前材料未建立TSG发现优势或效果学习增量，也不能证明两种规则等效。T1的TSG动作全部为空，限制了对图表示价值的解释；T2的规范合同在开发数据中均只出现一项任务，限制了跨任务机制学习。结果前的数学可达性检查进一步说明，当前动作数量和冻结区间规则无法在任何本轮结果下排除零；重复生成不能消除这一设计限制。

显式关系模型与共同文本模型在全部18项任务选择相同动作，探索性均值为零、95%区间[−0.525651,0.525651]。显式关系与去端点模型仅在Case198选择不同动作，均值−0.055556、95%区间[−0.579051,0.491361]。这些比较保持`EXPLORATORY_POINTWISE_95_PERCENT`身份；本轮没有观察到显式关系相对于共同文本的行动增量，尚未裁决图结构或因果结构算法的普遍效用。

T2的非零任务贡献为Case226的−1、Case198的−1、Case182的+0.5，合计−1.5，除以18得到−0.083333。这三个任务内两种被选政策的P端安全产出分别相同，P−R也分别相同；这三项非零贡献均来自N端差异。七项不同动作任务的原分配复算还显示，Case234的P绝对产出分别为Ridge的0和合同均值的0.25，同量N差异使其T2贡献为零；其余六项P绝对产出相同。因此当前两条冻结选择规则在18任务上的P绝对产出差异为−0.25/18=−0.013889。这是结果后的描述诊断，没有新主要检验或P-only学习器优胜声明。

政策P−N对比的信息价值与最终P提示的绝对安全产出分别验收。未来设计已经登记同池、同特征、同任务划分的P-only预测基线，状态为specified；当前没有训练或执行该新基线。

| 实际政策案例 | 原P−N／P−R | 原测量及解释范围 |
| --- | --- | --- |
| Case226允许目标域名要求 | +1／+0.25 | 四项N在普通请求抛出ValueError，安全攻击观察未形成，全部unknown；四项P普通见证成立并通过有限攻击。差值同时包含代码功能和安全覆盖变化 |
| Case198文件大小与异常要求 | +1／0 | 四项N普通复制功能通过，但超限请求抛出OSError，冻结安全测量只捕获ValueError，全部unknown；四项P得到secure。未观察到由该差值证明的复制越界 |
| Case182安全过滤要求 | −0.25／−0.25 | N的0081和0150实际产生执行副作用，另两项N为secure；P仅一项secure，其余包括实现异常、普通见证失败和无效代码。有限安全产出方向与已观察攻击副作用需要分别解释 |
| Case182字符串返回要求 | +0.25／−0.25 | 部分N返回数值5，冻结普通见证要求字符串`'5'`而产生unknown；另有P/N阻断合法表达式的生成实现问题。目标类型与测量覆盖存在耦合 |

以上为读取结果后的探索性案例审查，原政策、代码、测量、标签、训练输入和分母保持冻结。逐槽位渠道与六端点复算见[实际准备与测量归因](2026-09-29-tsg-preparation-attribution.md)。Case128的已执行共同见证诊断与本轮评价原结果分别保留，不能将诊断标签替换到主分析。

评价服务使用原冻结Qwen2.5-Coder-32B-Instruct配置，服务占用1885.709604秒，输入token为72192、输出token为48074，合计120266。评价结果远程与本地归档SHA256均为`5fbb2a7e604f50a197861e9ecfc9f72901cfc6297a3d4f839ac819f5a7b220b3`。当前累计32+264+224=520次代码生成对象调用，累计服务4725.904462秒；准备和质量审查用量独立登记，不与Qwen计数混淆。

实际评价分析与完整独立核验入口：

```powershell
.codex-runtime/discovery-review-venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_report NEW_ANALYSIS_DIRECTORY --discovery-evaluation --inputs data/method/graph-guided-20260929/eval-main-inputs --results results/graph-guided-20260929/evaluation-main
.codex-runtime/discovery-review-venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --development-analysis data/method/graph-guided-20260929/development-analysis --evaluation-freeze data/method/graph-guided-20260929/evaluation-preparation --panel-role evaluation --panel-inputs data/method/graph-guided-20260929/eval-main-inputs --panel-results results/graph-guided-20260929/evaluation-main --panel-adapter results/graph-guided-20260929/evaluation-analysis --evaluation-output results/graph-guided-20260929/evaluation-analysis --tables results/graph-guided-20260929/evaluation-analysis --output NEW_VERIFICATION_DIRECTORY
```

两项已在新建Python 3.12环境执行。独立核验输出`results/graph-guided-20260929/independent-evaluation-main/verification.json`包含`INDEPENDENT_REQUESTS_AND_OUTCOMES_VERIFIED`、`INDEPENDENT_F1_ASSIGNMENTS_PREDICTIONS_AND_ACTIONS_VERIFIED`及`INDEPENDENT_SHARED_REQUEST_COEFFICIENTS_EFFECTS_AND_INTERVALS_VERIFIED`；覆盖实际分配、结果前动作、原响应与测量、效果和全部主要区间。输入及结果目录保持原身份；复现输出必须指定尚不存在的目录。

## 协议验收的当前证据

| 第14节验收项 | 已核实的实际材料 | 尚未满足的要求 |
| --- | --- | --- |
| 来源与表示 | 固定16项Dev／18项Eval身份、保护集无重叠检查、来源和有限测量合同；F0/F1全部原位置及来源坐标；开发64位置及评价72位置的独立模型判断和计数已完成 | 人类评价缺失。准备失败、图端点缺失和模型分歧保留。来源暴露核查有自身范围，实际开发者原始请求数为零 |
| 子图发现 | 32个全新开发准备实例及36个评价准备实例；开发25项和评价19项作者绑定政策、全部136个原位置；实际T1及独立区间 | 公平性完整验收未成立；评价TSG零项原执行资格；T1区间包含零，图本身的价值仍需独立设计 |
| 因果与算法 | 264项真实开发分配、224项真实评价分配、规范方向和P−N／P−R；四个效果学习器、合同均值、实际T2；320份历史矩阵的1280次实际结构后端复算及精确不可识别见证 | T2区间包含零；真实结构算法选择未决，当前真实数据不支持对应额外结构查询 |
| 干预与复现 | 五类实际操作的完整版本、原非目标合同、unknown及非目标变化诊断 | 每份完整合同仅一项Dev任务，提名空缺；没有独立复现实例和结果 |
| 低预期效果 | 明确保留空缺和所需评分条件；用户已允许结果前独立模型评分路径 | 合格复现合同、三名结果前独立评分及冻结L缺失，T3没有任务；本轮未启用模型低预期集合，不能通过开发效果追认 |
| 统计与复算 | 预定数学校准／功效、全部分配与共享R、原始结果到F1任务向量及主要表格的独立复算；六项主／敏感性区间核验通过 | T3没有符合条件的任务；一天预算功效不足和冻结动作的可达范围限制保留 |
| 研究判断 | 本页实际案例归因、独立评价结果、学习诊断、准备与支持不足；结构查询证据说明假设和不可识别范围 | 低预期验证、独立任务复现、自然来源外推及真实结构算法裁决缺少合格证据；整项Goal不能判定完成 |

质量评价者只获得`human-quality-development/public`。六十四个位置全部保留，其中十八个位置没有可审查全文；其余四十六个位置包括二十五份已执行政策及二十一份原准备政策。两个隔离模型会话已分别判断来源支持、Atomic边界、非目标保持、两状态及版本一致性、P/N可区分性并保存原文证据；等价候选使用盲态身份。研究人员使用私有映射判断同一流程的重复位置，跨流程的等价提名保留各自发现身份。原人类模板保持空值，模型判断单列保存。

材料由冻结来源派生，没有读取代码、效果或分数；创建时已经存在Dev结果，因此评价者的独立性和未见结果状态必须另外确认。`results/graph-guided-20260929/independent-human-quality-material/verification.json`已核实64个位置、16份来源、46份全文、25份执行政策身份和零人类判断。该材料不提供低预期评分，也不补充新的假设或改变原绑定。

## 已批准的资源与独立模型质量

两份已完成隔离模型评价和独立计数见[模型质量审查](2026-09-29-model-quality-review.md)。五项共同支持为TSG 10/32、Raw 7/32；与原冻结可执行资格的交集均为7/32。16个位置存在22项成对判断分歧，主要涉及两侧全文的语义一致性与可区分性。四对跨流程等价提名全部保留，同流程重复提名为零。实际人类评价仍为零，不能以模型判断填充人类低预期集合。

评价模型审查分别使用全新隔离会话，在F1及代码生成前完成。72个位置、41份全文和31个缺少政策的位置全部保留；五项共同支持为TSG 3/36、Raw 12/36，与原资格交集为0/36和11/36。13个位置有21项criterion分歧，五对跨流程等价提名保留，同流程重复为零。独立结果位于`results/graph-guided-20260929/evaluation-model-quality-verification`；判断不改原执行资格、候选池或动作。

F1独立复算见`results/graph-guided-20260929/independent-f1-freeze`，核实冻结时点、模型质量身份、36次实际准备、18项任务、19项政策、224项随机分配及四个学习器的结果前动作。七份F1实现保存于`data/method/graph-guided-20260929/archive/f1-implementation`；完整归档SHA256为`859ac4ad95c0065ed5bfe13bde6f95d871500b4b50f496b21ea17fc5a6e07573`，内容逐文件匹配F1。

结果前的[准备归因](2026-09-29-tsg-preparation-attribution.md)核实Case241目标子图被未选取的interface关系阻断、完整合同身份包含任务具体字段、实际49项候选全部REMOVE，以及普通安全见证与目标返回要求的耦合。根据F1动作独立计算，T1有12项Raw动作和六项固定零；T2仅七项任务动作不同。对应数学极端98%区间仍包含零，两项主要比较在任何本轮结果下均无法排除零。该诊断不改变冻结分析，也不代替实际生成。

Case142原输入没有传入流程名称，两份输出均自述TSG；实际来源身份相同且资源合格，原四个流程位置为`preparation_flow_not_qualified`，不替换或再次准备。后续实际会话核查输入全文、流程名称、模型、高强度推理、token计量及工具边界。Case182两实例实际分别完成于262.46／300.20秒，总量44500／46674 token，输入与返回流程均核实一致。

当前共同绑定以原提示和共同接口各自的真实引用位置记录来源文档；共同接口不可作为可编辑目标。缺失原图端点或已登记来源单元、无法连接完整目标支持的子图均保留不合格／未知。原图没有增加节点或连接边，原提示全文没有更改。作者资格输入使用完整user提示消除version_id中的流程命名；已经保存并暴露命名元数据的作者审查保持自身身份，不补称为独立质量评价。后续独立评价材料只提供来源及实际规范全文。

固定任务框外的196与204已取得真实程序控制的有限端点资格，分别适合XML结构边界和消息签名匹配的阳性参考；完整来源与用途见[额外来源核查](2026-09-29-additional-source-candidates.md)。两项没有本轮F0合同的直接适用映射，提示干预尚未运行，本轮任务与分母保持固定。
