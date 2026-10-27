# 本轮发现研究复核指南

当前协议为 `tsg-discovery-development-20260929`及用户批准的[评价资源与模型评价合同](2026-09-29-evaluation-resource-amendment.md)。正式规范保持 `SPECIFIED_DRAFT`。本轮固定16项开发任务和18项评价任务；F0及F1已冻结，264项开发分配和224项评价分配全部返回，原结果到学习器、动作、任务向量及主要区间的独立核验通过。运行状态及实际证据见[运行记录](2026-09-29-discovery-run-status.md)。

用户批准的[准备修复研究](2026-09-29-tsg-preparation-repair.md)已完成同18项已暴露任务的72次准备请求。TSG与Raw分别形成31和35项完整政策；17项TSG具有最终非空图，Case74的最终空图失败保留。此次修复复核表示、假设与编辑准备，没有新增代码生成效果。准备身份与资源的独立核验入口如下；输出目录须为新目录。

```powershell
.codex-runtime/discovery-review-venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --preparation-repair data/method/graph-guided-20260929/preparation-repair/main --output NEW_PREPARATION_VERIFICATION_DIRECTORY
```

原始主面板身份保存在`preparation-repair/freeze`，最终输入输出保存在`preparation-repair/main`；两者均位于`data/method/graph-guided-20260929`。独立结果为`results/graph-guided-20260929/preparation-repair/main-independent-verification`。机械合格、共同语义审查、全图审查和局部支持分别报告，不能相互代替。

共同语义审查已完成，TSG与Raw的双方五项支持分别为25/36和28/36。图审查另得到27/36项局部完整支持，与TSG共同语义支持交集为22/36。完整图来源覆盖和语义忠实分别为17/18和13/18。原判断、分歧、字段及复核命令见准备修复记录；共同审查结果位于`results/graph-guided-20260929/repair-model-quality-verification`，图及交集结果位于`results/graph-guided-20260929/preparation-repair/joint-quality-verification`。公共政策有15个位置暴露流程文字，流程盲态验收失败；这些质量计数保持方法开发和代码结局隔离的模型评价身份。

## 阅读顺序

1. [研究协议](../graph-guided-discovery-protocol.md)：研究问题、两个冻结时点、资源限制及三项主要比较。
2. [开发冻结协议](../../data/method/graph-guided-20260929/development-preparation/protocol.json)：实际任务范围、实现身份、模型、测量及尚缺的评价资格。
3. [来源执行合同](../../data/method/graph-guided-20260929/source-execution-contracts.json)：原始来源、共同接口及有限测量范围。
4. [研究执行模块](../../src/development/graph_guided_study.py)：来源输入、隔离准备记录、盲态绑定、F0、开发分析及F1。
5. [效果学习模块](../../src/development/graph_guided_decisions.py)：方向、文本差分、节点边际、完整关系元组、任务权重及交叉验证。
6. [代码生成模块](../../src/development/source_generation.py)：独立消息、seed、原响应、代码提取、测量及全部分配计量。
7. [独立测量程序](../../src/measurement/native_behavior.py)：安全与功能的隔离渠道和真实运行环境。
8. [服务执行入口](2026-09-29-service-check.py)：固定模型配置、服务累计时限、输入冻结和关闭。
9. [结果分析模块](../../src/development/graph_guided_report.py)：ITT、共享观测抵消、未知界限、任务向量及区间。
10. [独立验证器](2026-09-29-discovery-verify.py)：来源与全文身份、独立随机化复算、实际原响应、对偶Ridge估计、动作及区间。

## 七阶段材料

| 阶段 | 输入与输出 | 科学边界 |
| --- | --- | --- |
| 表示 | `preparation-inputs/qualified` → `preparation/cli55` | 两条流程使用全新实例；TSG关系记录来源语义 |
| 优先选择 | 全部来源覆盖及机会 → 每流程两个固定位置 | 不拆分完整要求；失败及空位置保留 |
| 假设冻结 | `binding-review-inputs`、`binding` → `development-preparation`／`evaluation-preparation` | 先固定实际全文及语义，再生成代码；作者绑定、独立模型质量与人类评价分别登记 |
| 干预随机化 | 冻结政策 → `assignments.json`、`bindings.json` | P/N语义方向固定；版本与seed为任务内重复 |
| 测量 | 每个真实代码输出 → 原始测量记录 | 测量输入没有流程、处理或预测标签 |
| 结果组装 | 全部已分配请求 → `outcomes.json` | 无效代码、未知、安全失败及未执行分配均保留 |
| 推断报告 | 开发效果、F1动作及评价结果 → 任务向量、区间及独立核验 | 开发用于学习；评价方向不随结果改变；代码不进入主PAG |

上述准备目录均位于 `data/method/graph-guided-20260929`；生成结果位于 `results/graph-guided-20260929`。开发运行输入为 `dev-main-inputs`，生成结果为 `development-main`。评价运行输入为 `eval-main-inputs`，生成结果为 `evaluation-main`。评价F1包含19项政策，全部来自Raw；TSG原位置和流程失败完整保留。

## 研究问题与结果字段

本表给出现有实现的计算位置及证据边界。开发分析、独立模型质量计数、F1动作及实际评价主要结果均已执行并独立复算。

| 研究输出 | 冻结输入及计算函数 | 对应结果字段与验收证据 |
| --- | --- | --- |
| RQ-T的候选发现与合法性 | F0/F1的`candidates.json`、`slots.json`和`preparation-accounting.json`；`discovery_collect_prepared`；独立模型审查读取盲态public材料 | 每任务每流程两个原位置、全部空缺及失败；作者绑定和独立模型质量分别解释。开发64位置及评价72位置各自使用两次新隔离模型评价，独立计数已执行；人类评价未获得 |
| RQ-T的发现收益T1 | F1的`decisions.json`中`actions.tsg`和`actions.raw`，全部评价`assignments.json`；`discovery_task_vectors`及`discovery_primary_tables` | 结果`vectors.json.T1`；`tables.json`中`comparison='T1'`的`primary`／`sensitivity`、任务数及alpha=0.02。独立函数`verify_evaluation_outputs`复算共享请求系数，`verify_tables`复算区间 |
| RQ-C的学习增量T2 | 开发`training.json`的`delta_pn`、任务分组及规范合同；`fit_discovery_ridge`和`discovery_contract_statistics`；F1的`actions.ridge`／`actions.contract_mean` | 开发`models.json`中的参数、系数、词表及`validation`；评价`vectors.json.T2`和对应alpha=0.02的表格。独立函数`verify_development_effects`从分配重算开发标签，`verify_learning`复算任务权重、折内编码及Ridge，`verify_evaluation_freeze`复算结果前动作 |
| RQ-C的关系编码增量 | 同一开发训练记录的`common`／`relations`／`endpointless`模型，以及共同评价池；`discovery_evaluation_tables` | `descriptive.json`的`relations_minus_ridge`及`relations_minus_endpointless`，证据身份为`EXPLORATORY_POINTWISE_95_PERCENT`；该比较不裁决FCI／JCI／GFCI的优胜 |
| RQ-C的结构查询 | 历史冻结矩阵、原配置和实际后端复算；`discovery_structural_evidence`及原`context_algorithms.py::run` | [结构查询证据](2026-09-29-structural-query-evidence.md)关联`historical-backend-replay`、`structural-query-evidence`的原输出、查询与精确见证；当前真实结构算法选择保持未决 |
| RQ-E的政策效果及竞争解释 | 实际P/N/R全文、任务内版本与seed、独立程序测量；`discovery_panel_outcomes`及`discovery_evaluation_tables` | 结果`effects.json`中的`pn`／`pr`按`primary`、`sensitivity`、`code_validity`、`oracle_coverage`、`functionality`、`joint_success`分别记录；原请求及直接违反见证用于案例归因 |
| RQ-E的独立复现及低预期T3 | 开发`nomination.json`、独立任务的复现绑定、三名结果前独立评分和F1的`low_expected_task_ids`；模型评分沿用已批准修订的前提及名称 | `vectors.json.T3`及alpha=0.01的表格需要全部前提；当前每份开发合同仅一项任务支持，未达四项任务门槛；人类与模型低预期评分均未提供，T3为零项任务。空缺不构成低预期效果证据 |

主要安全端点为冻结测量范围内的安全代码产出。安全unknown仍有明确主结果取值及敏感性界限；响应或测量基础设施缺失保留区间。功能、联合成功、代码有效性和Oracle覆盖均保留自身含义，不用于删除已分配任务。

## 当前可复核入口

```powershell
.venv/Scripts/python.exe -m pytest tests/test_discovery_design.py -q
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --output NEW_OUTPUT_DIRECTORY
```

复核输出目录需要尚未存在。F0核验同时读取180份真实程序控制及16项实际绑定，独立重建264项分配。现有核验结果位于 `results/graph-guided-20260929/independent-f0-freeze`。该入口不调用模型。

F0的七份原实现保存在`data/method/graph-guided-20260929/archive/f0-implementation`，以完整归档、逐文件SHA256及F0输入身份核实。当前准备实现读取逐任务授权资源并核查实际传入的来源与流程指令；生成、学习和测量实现仍须符合F0。当前读取核验结果位于`results/graph-guided-20260929/independent-f0-and-case142-after-input-audit`，同时核实Case142四个流程不合格位置及零准入政策。

已执行的开发分析与完整核验入口为：

```powershell
.venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_study discovery-analyze-development --inputs data/method/graph-guided-20260929/dev-main-inputs --results results/graph-guided-20260929/development-main
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --development-analysis data/method/graph-guided-20260929/development-analysis --panel-role development --panel-inputs data/method/graph-guided-20260929/dev-main-inputs --panel-results results/graph-guided-20260929/development-main --panel-adapter data/method/graph-guided-20260929/development-analysis --output NEW_OUTPUT_DIRECTORY
```

该核验读取原始请求、响应、测量和全部分配，重新组装主结果及未知界限，再独立计算P−N、P−R、训练标签、任务权重和留一任务交叉验证。264项实际分配、25项政策、15项有标签任务及四个学习器核验通过；输出位于`results/graph-guided-20260929/independent-development-main`。

开发及评价生成、效果分析已完成。累计520次实验对象调用、4725.90秒服务占用，以原始派发记录和服务关闭记录核实。开发及评价各自的两次隔离模型质量判断和独立计数均已完成；主要评价表格及独立核验完成，低预期评分和独立任务复现缺失。T1均值−0.05556、98%区间[−0.65457,0.57509]；T2均值−0.08333、98%区间[−0.69288,0.56708]；T3任务数为零。

评价分析与完整核验在新建Python 3.12环境实际执行：

```powershell
.codex-runtime/discovery-review-venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_report NEW_ANALYSIS_DIRECTORY --discovery-evaluation --inputs data/method/graph-guided-20260929/eval-main-inputs --results results/graph-guided-20260929/evaluation-main
.codex-runtime/discovery-review-venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --development-analysis data/method/graph-guided-20260929/development-analysis --evaluation-freeze data/method/graph-guided-20260929/evaluation-preparation --panel-role evaluation --panel-inputs data/method/graph-guided-20260929/eval-main-inputs --panel-results results/graph-guided-20260929/evaluation-main --panel-adapter results/graph-guided-20260929/evaluation-analysis --evaluation-output results/graph-guided-20260929/evaluation-analysis --tables results/graph-guided-20260929/evaluation-analysis --output NEW_VERIFICATION_DIRECTORY
```

实际输出为`results/graph-guided-20260929/evaluation-analysis`及`independent-evaluation-main`。验证覆盖224份请求和原始测量、19项政策对比、18项任务的共享请求系数、T1/T2/T3及六项主／敏感性区间。F1七份实现的完整归档为`data/method/graph-guided-20260929/archive/f1-implementation/source.tar.gz`，SHA256为`859ac4ad95c0065ed5bfe13bde6f95d871500b4b50f496b21ea17fc5a6e07573`；归档只用于核实冻结身份。

结果后的Case128测量诊断与原冻结结果分别保存，见运行记录中的实际案例归因。共同见证诊断保留原12份代码与功能探针，另执行3份真实程序控制；其P−N为0，原冻结主端点P−N为1。诊断核验位于`results/graph-guided-20260929/case128-common-witness-verification`，不替换开发训练或评价输入。主要研究核验入口仍为本页列出的独立验证器。

独立质量评价材料位于`data/method/graph-guided-20260929/human-quality-development/public`，包含64个位置、16项完整来源及46份实际准备全文。评价者仅获得public目录；private目录中的流程、作者资格和原身份映射由研究人员保管。两名独立评价者分别填写模板中的支持／不支持／未知及来源证据，等价关系使用盲态身份登记；同一流程的重复位置依据私有映射解释。当前没有人类判断。

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --development-freeze data/method/graph-guided-20260929/development-preparation --human-quality-material data/method/graph-guided-20260929/human-quality-development --output NEW_OUTPUT_DIRECTORY
```

该入口已执行并核实材料身份、全文、全部位置、隐藏字段和模板空值，输出位于`results/graph-guided-20260929/independent-human-quality-material`。独立模型判断分别位于`model-quality-development/reviewer-a.json`及`reviewer-b.json`，不能填充人类评分或重写开发标签。固定任务框之外的额外来源与有限测量资格见[来源资格核查](2026-09-29-additional-source-candidates.md)。

评价质量材料为`model-quality-evaluation/public`，两份原模型判断保存于同目录的上一层。全部72位置的独立计数位于`results/graph-guided-20260929/evaluation-model-quality-verification`；TSG及Raw的共同五项支持为3/36和12/36，与原执行资格交集为0/36和11/36。F1独立核验位于`results/graph-guided-20260929/independent-f1-freeze`，核实18项任务、19项政策、224项分配、四个学习器及结果前动作。

目标子图、合同支持、操作单一与测量耦合的实际归因见[准备归因](2026-09-29-tsg-preparation-attribution.md)。其中T1与T2根据实际冻结动作计算的数学极端区间均包含零；该结果前检查限定本轮可达到的推断，不代替实际政策效果。

## 已暴露任务的准备修复

[准备修复记录](2026-09-29-tsg-preparation-repair.md)给出完整范围、实际请求和独立判断。当前定向修复使用原文精确编辑，在12项已暴露任务上执行15条流程、30次准备请求，固定30个候选位置。九项TSG全部非空，形成27项政策；独立机械检查通过13条流程，共同语义双支持22个位置，二者交集19个位置。原实验的代码、分配、效果与区间保持原身份。

当前准备入口为`.codex-runtime/evaluation-preparation.ps1`，准备指令为`2026-09-29-tsg-preparation-repair-instructions.md`；逐字编辑物化与诊断由`graph_guided_study.py`执行。实际执行源代码保存在定向登记同目录的`source.tar.gz`。执行后补齐的操作字段相等检查不重写原资格记录；新诊断与独立核验保留四个字段问题。

定向结果的独立复核入口如下，输出目录均需尚未存在；这些命令不发起模型请求：

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --repair-registration data/method/graph-guided-20260929/preparation-repair/targeted-20260929/registration.json --output NEW_PREPARATION_VERIFICATION_DIRECTORY
.venv/Scripts/python.exe docs/experiments/2026-09-29-model-quality-verify.py --population repair --repair-registration data/method/graph-guided-20260929/preparation-repair/targeted-20260929/registration.json --output NEW_COMMON_VERIFICATION_DIRECTORY
.venv/Scripts/python.exe docs/experiments/2026-09-29-model-quality-verify.py --population repair --repair-registration data/method/graph-guided-20260929/preparation-repair/targeted-20260929/registration.json --graph-review --output NEW_GRAPH_VERIFICATION_DIRECTORY
```

已执行结果分别位于`results/graph-guided-20260929/preparation-repair/targeted-independent-verification`及`results/graph-guided-20260929/targeted-repair-model-quality-verification`。新共同评价材料为`data/method/graph-guided-20260929/model-quality-targeted-repair/public`；两份判断在发放图材料前冻结。固定位置、空缺、unknown、否定判断和不同检查之间的差异均保留。

图审查已在独立Python 3.12环境核验，输出位于`results/graph-guided-20260929/targeted-repair-model-quality-verification-graph`。双方支持九项全图的来源忠实性与覆盖，以及15/18原位置的局部来源依据；三个空候选位置保留unknown。TSG的共同语义与局部图支持交集为12/18，计入机械检查后为10/18。图核验始终使用发放图材料前固定的共同核验身份，新复核输出不替换该身份。

## 修复后实际代码生成的复核

完整执行见[修复后Qwen生成与测量](2026-09-29-tsg-preparation-repair.md#修复后qwen生成与测量)。准备输入为`data/method/graph-guided-20260929/targeted-generation-preparation`，运行时输入为同级`targeted-gen-inputs`，实际请求结果为`results/graph-guided-20260929/targeted-generation-main`。全部12任务、30原位置、27政策及19项质量合格集合在生成前固定；256次实际调用中254次返回代码、2次截断，失败与unknown保留。

```powershell
.codex-runtime/discovery-review-venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_report NEW_TARGETED_ANALYSIS_DIRECTORY --discovery-targeted-generation --inputs data/method/graph-guided-20260929/targeted-gen-inputs --results results/graph-guided-20260929/targeted-generation-main
.codex-runtime/discovery-review-venv/Scripts/python.exe docs/experiments/2026-09-29-discovery-verify.py --targeted-generation-preparation data/method/graph-guided-20260929/targeted-generation-preparation --panel-inputs data/method/graph-guided-20260929/targeted-gen-inputs --panel-results results/graph-guided-20260929/targeted-generation-main --panel-adapter NEW_TARGETED_ANALYSIS_DIRECTORY --output NEW_TARGETED_VERIFICATION_DIRECTORY
```

这两个命令复算现有结果，不调用生成模型。实际已在独立Python 3.12.13环境完成，输出为`targeted-generation-analysis`及`targeted-generation-verification`，均位于`results/graph-guided-20260929`。`discovery_targeted_generation_tables`组装全部请求并调用既有系数与unknown界限函数；`verify_targeted_generation_preparation`独立重放来源、质量身份和随机分配；`verify_service`及`verify_targeted_generation_effects`独立检查原始响应、代码、测量和324组效果界限。

19项合格候选覆盖10项任务、18项唯一政策。P−N主端点四项正向、两项负向、十三项零差异仅为本轮描述统计，不能替代抽样不确定性、跨任务复现或因果算法比较。案例报告区分危险DOM／超长标识见证与依赖缺失、AST错误及拒绝异常覆盖；有限安全、功能合同、代码有效性与联合成功分别解释。

## 修复数据的因果算法比较

[当前因果算法比较报告](2026-09-29-causal-comparison-results.md)提供真实修复数据的1792次结构搜索、按任务留一的六种选择器比较、共同请求抵消后的增量归因和复现入口。输入独立单位为10项任务，TSG支持面板为7项任务；32次请求抽取始终保留该样本量。

结构输出为`results/graph-guided-20260929/targeted-causal-structure`，选择器输出为同级`targeted-causal-selectors`及`targeted-causal-selector-differences`。此项分析使用已暴露材料，保留事后探索身份；原生成结果与正式协议状态保持原身份。FCI/JCI/GFCI真实场景优胜、独立发现收益及图关系增量分别保持未决。
