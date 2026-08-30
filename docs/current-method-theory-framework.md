# Prompt Mechanism Study 当前理论与方法框架

**状态：** 当前方法的审查性总览，不是新的协议版本

**规范权威：** [上下文条件化干预政策框架](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md)

**数据权威：** [研究数据集规范](research-dataset-spec.md)

**最新正式实验：** [SQL scaffold-repair 析因 follow-up v1](experiments/2026-08-27-factorial-sql-scaffold-repair-v1-results.md)

**前序正式实验：** [SQL 二因素 from-scratch confirmation v3](experiments/2026-08-27-factorial-sql-confirm-v3-results.md)

**当前 Gate 与证据审计：** [Gate E readiness](gate-e-readiness.md)

本文把现有理论规范、活动代码和已运行证据整理为一条可审查的方法链。它不重新定义冻结实验，也不把规划中的组件写成已经实现或已经产生结果。

## 1. 当前方法的一句话定义

Prompt Mechanism Study 是一个**由 Prompt TSG 约束、按任务上下文限定、以任务单元为独立单位、通过随机分配识别提示干预政策效应**的研究框架；观测因果发现只在自然提示满足支持条件时，作为预算化假设选择器使用，而不产生最终因果结论。

更短地说：

```text
Prompt TSG 定义“在什么上下文中可以改什么”
selector 决定“有限预算下优先测试什么”
随机实验决定“冻结的提示政策是否产生效果”
```

当前最稳健的核心是第一行和第三行。第二行是有前置门控的扩展：活动代码已经闭合 support gate 与五类 selector，但当前审查树没有一份通过该门且可重放的正式自然 discovery freeze，因此尚不能形成 selector 优越性结论。

## 2. 理论层次

框架包含四个不能混同的层次。

| 层次 | 回答的问题 | 主要对象 | 证据性质 |
| --- | --- | --- | --- |
| 表示 | 这个任务包含什么安全上下文和可编辑要求？ | Prompt TSG、`C_q`、`f` | 语义表示 |
| 选择 | 有限实验预算下应先测试哪些假设？ | selector、Top-K、候选排名 | 观测优先级 |
| 干预 | 分配某个提示政策会不会改变结果？ | arm `A`、realization `R`、生成结果 | 随机因果效应 |
| 测量 | 结果是否有效、安全、可评估且功能正确？ | Security Oracle、Functional Judge、outcome ledger | 独立结果测量 |

Prompt TSG 的边表示提示中陈述或有证据支撑的任务/安全关系，**不是因果边**。生成代码也不是 Prompt TSG 节点、FCI 主表变量或因果中介；它只是独立安全与功能测量的对象。

## 3. 研究对象与记号

### 3.1 独立单位

- `task unit`：跨来源保守去重后的最高独立采样、分配和重采样单位。
- `source record`：候选数据集中的一条原始记录。
- `task`：为一个 task unit 冻结的代表 prompt。
- `semantic_cluster_id`、`cluster_id`：旧产物中的 task-unit 物理坐标；论文叙述不再把它们当成另一层统计概念。

### 3.2 提示与表示

- `P_i^0`：任务 `i` 的自然、未干预 prompt。
- `T_E(P)`：由冻结抽取器 `E` 得到的 Prompt TSG。
- `C_q`：不可编辑的安全上下文查询，例如“不可信输入到达 shell 执行”。
- `f`：一个可编辑的 Prompt 侧安全要求，例如“使用参数列表并禁用 shell”。
- `X_{if}^0=q_f(T_E(P_i^0))`：自然 prompt 中特征 `f` 的状态。

查询使用四值语义：

```text
PRESENT | ABSENT | NOT_APPLICABLE | UNRESOLVED
```

`UNRESOLVED` 不能折叠成 `ABSENT`；`NOT_APPLICABLE` 也不能作为缺失值进入同一分母。

路径访问中的 base authority 是一个冻结的任务侧坐标，不再由两个 LLM
阶段重复推断。前瞻 successor 使用
`application_configured / caller_supplied / unspecified / no_bounding_base`
四状态注释，并绑定 `task_id`、prompt hash 与精确证据 occurrence。Prompt TSG
确定性消费该坐标：前两者分别生成 trusted/caller-supplied fact，
`unspecified` 保持 `UNRESOLVED`，没有 bounding base 才记为 `ABSENT`。LLM 仍负责
开放文本中的 source、sink 和其他 task semantics；reviewer 接受 proposer 已有
fact 时复用其已校验 evidence binding，只裁决语义，不再次猜 occurrence。
这一 successor 已在暴露过的 5 个开发 case 上验证接口行为，但尚未通过新的独立
Gate，因此不能替代当前失败的正式资格结果。

### 3.3 原子假设

可确认假设为：

\[
h=(C_q,f,a,Q_h,Y),
\]

其中：

- `C_q` 决定任务适用上下文；
- `f` 是唯一可编辑叶特征；
- `a` 是 `ADD` 或 `REMOVE`；
- `Q_h` 是预先冻结的有限措辞 realization 分布；
- `Y` 是预注册结果。

ADD 与 REMOVE 是两个不同假设、两个不同政策和两个不同多重比较坐标。一个关系 motif 可以定义上下文，但不能直接成为被分配的 treatment。

## 4. 两个数据生成机制

### 4.1 Discovery：自然提示中的观测变化

\[
W_i\rightarrow P_i^0\rightarrow X_i^0,
\qquad
(P_i^0,M_m,U_{ims})\rightarrow G_{ims}^0\rightarrow Y_{ims}^0.
\]

- `W` 是批准的干预前任务元数据，包括来源、任务形态及必要的提示风格描述。
- `M` 是生成模型。
- `U` 是请求随机性。
- `G` 是生成代码。
- `Y^0` 是独立测量结果。

family-local FCI 表只能包含最小的 `W`、自然提示查询 `X^0` 和发现结果 `Y^0`。原始代码、arm、生成代码特征和干预后特征均不得进入该表。

活动 selector schema 2.1 不信任 discovery producer 自报的 `X^0`。它把 catalog、自然 prompt 和 Prompt TSG 一并闭合进 freeze，加载时重新验证 evidence span、上下文查询和 actionable-feature 状态，再与 observation 中的二值编码逐项比对。

FCI 之前必须通过 outcome-blind positivity gate：在同一 `C_q=PRESENT` 上下文内，`f=PRESENT` 与 `f=ABSENT` 都有足够独立 task units，且两种状态不能由数据来源完全分离。若失败，结论是“当前观测数据不支持该 selector”，不能通过平滑、跨族合并或人工制造状态修复。

### 4.2 Confirmation：冻结政策的随机实验

\[
(P_i^0,A,R)\rightarrow P_i^{A,R},
\qquad
(P_i^{A,R},M_m,U_{ims})\rightarrow G_{ims}^{A,R}
\rightarrow Y_{ims}^{A,R}.
\]

- `A` 是随机分配的 arm。
- `R` 是从冻结 `Q_h` 取出的 realization 坐标。
- `P_i^{A,R}` 是干预后 prompt。

重新抽取得到的 `X^{A,R}` 只检查 treatment fidelity。主分析始终按 assigned arm `A` 进行；不能因为实际措辞未被模型遵循、代码生成失败或诊断不理想而过滤 ITT 分母。

## 5. Selector 与 intervention effect 的严格分工

### 5.1 Selector 研究

给定同一个候选宇宙 `H` 和预算 `K`，selector 输出一个冻结的 Top-K：

\[
s_{\ell m}(D_{disc,m},\mathcal H),\quad |s_{\ell m}|\le K.
\]

它的效用是这些预算槽中有多少假设随后在独立随机实验中得到确认，即 strict ConfirmedYield@K。空槽、桥接失败和协议化失败都保留在 `K` 的分母中。

计划比较的 selector 包括：TSG-constrained FCI、预注册关联、正则预测、盲态专家和种子化随机排名。它们必须使用同一候选宇宙、信息预算和 `K`。

### 5.2 Intervention-effect 研究

随机实验不需要相信 selector 的因果方向。对已经冻结的 `h`，它直接估计目标政策相对于匹配 no-op 的 assigned-arm ITT。

因此：

- FCI 找到候选，不等于干预有效；
- FCI 不可运行，不等于随机干预研究不可运行；
- 一个 policy effect 被确认，也不证明 FCI 的 PAG 边正确；
- 只有多个 selector 在相同预算下接受独立确认，才能比较 selector 效用。

### 5.3 当前选择

历史 positivity pilot 在 CWE-328 和 CWE-611 上均未通过支持门，且 CWE-611 的特征状态被来源 lineage 完全分离；该 pilot 的活动结果文件已从 reviewer tree 移出，不能充当新协议证据。因此当前框架采用：

1. Prompt TSG 继续负责上下文与可编辑特征绑定；
2. FCI 保留为通过支持门后才启用的条件模块；
3. 支持门失败时，不报告 FCI 排名或 selector 优越性；
4. 若继续主实验，应从有限 catalog 中 outcome-blind 地预注册假设，再用 held-out 随机实验估计政策效应。

这一路径能够回答 intervention-effect 问题，但不能回答“FCI 是否比其他 selector 更有效”。

## 6. 七阶段活动方法

| 阶段 | 输入 | 核心操作 | 输出 | 科学不变量 |
| --- | --- | --- | --- | --- |
| 1. Representation | 来源记录、自然 prompt、catalog | 去重为 task units；选代表 prompt；LLM 提议受限 facts；确定性验证 evidence spans、类型和边 | Prompt TSG、四值查询 | TSG 不是因果图；开放文本只能作为 evidence-bound 局部语义 |
| 2. Prioritization | discovery task units、TSG 查询、发现结果 | 先做 positivity/来源重叠审计；通过后才运行 family-local selectors | 候选分数、排名、门控失败记录 | 不读取 confirm outcomes；不把干预生成的状态冒充自然变化 |
| 3. Hypothesis freeze | 候选宇宙、selector 或预注册规则 | 冻结 `h`、方向、eligible population、`Q_h`、arms、模型、Oracles、estimands、multiplicity | 不可变 study freeze | 看到确认结果后不得替换候选、措辞、分母或方向 |
| 4. Intervention/randomization | 冻结 task、`h`、realization | LLM 实现 arm 文本；盲态语义验证；按完整 block 平衡分配 arm | variants、bundles、assignment manifest | assigned arm 与 task/realization/model/slot 完整绑定 |
| 5. Measurement | 每个 assignment 的生成代码 | 代码有效性；静态 Security Oracle；AST/编译加盲态 Functional Judge | measurement ledger | 安全和功能独立；未知不能记为安全；基础设施失败必须同 assignment 重放 |
| 6. Outcome assembly | 完整 measurement ledger | 为所有 assignment 派生有效性、可评估性、安全产出、功能与 joint outcome | total outcome ledger | 不按诊断、成功生成或 Oracle 覆盖过滤分母 |
| 7. Inference/reporting | outcomes、freeze、analysis plan | task-unit 等权 ITT、未知上下界、整体重采样、多重比较、表格构建 | effect、区间、evidence level、报告 | task unit 是最高重采样单位；claim 绑定精确 artifact |

## 7. 四臂政策

每个 ADD 和 REMOVE 假设分别定义四臂。

| 操作 | Target | 匹配 No-op | Placebo/Sham | Generic |
| --- | --- | --- | --- | --- |
| ADD | `TARGET_PATCH`：加入具体机制要求 | `NOOP_REWRITE`：等操作改写但保持特征缺失 | `LENGTH_MATCHED_PLACEBO`：等长度、只改变呈现/风格 | `GENERIC_SECURITY_REMINDER`：泛化安全提醒，不指名目标机制 |
| REMOVE | `TARGET_REMOVE`：移除已有具体要求并恢复冻结的中性对应文本 | `NOOP_RETAIN`：匹配编辑但保留具体要求 | `LENGTH_MATCHED_SHAM_EDIT`：等长度、与目标机制无关的编辑 | `GENERIC_SECURITY_REPLACEMENT`：移除具体要求后换成泛化安全提醒 |

主对比是 `Target - operation-matched No-op`。它识别冻结目标政策的分配效应。`Target - Placebo` 与 `Target - Generic` 是次级 specificity 对比，分别排除“仅多加文字/改变风格”和“任何安全提醒都一样”的解释。

未编辑的 Original prompt 不是当前活动 arm，也不替代匹配 No-op。若论文需要 `Target-Original` 的实践参照，必须作为新的前瞻 arm-family 明确冻结后再运行；既有结果不能事后补算该对比。

这里的 placebo 是**随机化的控制政策**，不是发现阶段的源提示风格变量。

### 7.1 二因素配对析因扩展

当研究问题涉及两个可独立编辑的原子机制时，活动 successor 协议使用同一七阶段路径内的
`2 x 2` 政策族，而不是把两个单机制四臂结果事后拼成一次交互分析：

| cell | factor 1 | factor 2 |
| --- | --- | --- |
| `A00` | operation-matched No-op | operation-matched No-op |
| `A10` | Target | operation-matched No-op |
| `A01` | operation-matched No-op | Target |
| `A11` | Target | Target |

Prompt TSG 只提供 target-state-independent context、两个原子 feature 的 evidence 和结构关系；
它不包含协同、拮抗或先决关系等结果性标签。若自然 discovery 数据没有 outcome-blind 四格
支持，可以使用前瞻冻结的 registry pair，但不能宣称该 pair 由 FCI 或其他 selector 发现。

每个 task-unit、joint realization 和 model 组成一个包含四个 cell 的完整 block。assigned cell
是处理；生成代码中的机制实现、treatment collapse 和非目标漂移只作诊断。若两个 operator
未证明可交换，则两种应用顺序均以冻结正概率进入 realization 分布。

令四格 task-unit 加权均值为 `mu00`、`mu10`、`mu01`、`mu11`，主交互 estimand 为
`delta = mu11 - mu10 - mu01 + mu00`。同时报告两个单因素效应、联合效应、unknown bounds、
功能析因效应和 secure-and-functional joint outcome。论文首先使用中性的 response-surface
标签，例如 `positive_nonadditive_pattern`。每个 pair 在随机化前冻结
`interaction_claim_scope=policy_only|mechanism_eligible`；首个 SQL canary 的 Oracle endpoint
本身要求两个控制均成立，因此只能解释为 joint Prompt-policy interaction，不能因显著性
升级为普遍机制 synergy。

## 8. 风格因素在因果模型中的位置

“风格”不是一个统一变量，必须分三类：

1. **源 prompt 风格 `S^0`**：干预前属性，属于 `W` 或 `P^0` 的组成。在 discovery 中可能同时关联来源、特征状态和模型结果，因此是潜在混淆/代理因素；在 confirmation 中由 task-unit 内的随机 arm 对比控制。
2. **干预措辞风格 `R`**：冻结 `Q_h` 中的 realization，是 treatment policy 的组成而非应被回归掉的 nuisance。多 realization 用来检查效果是否只依赖某一种写法。
3. **生成代码风格 `S^G`**：干预后的诊断结果，可以说明模型行为变化，但不能进入主 PAG、eligibility 或 ITT 过滤。

因此无需建立单独的 Style TSG。需要的是：在 discovery 中记录和审计源风格，在 confirmation 中把措辞风格纳入 `Q_h`，并用 style placebo 检验替代解释。

## 9. 结果与估计量

对每个 assignment 分开定义：

\[
Y_C=I(\text{产生语法有效的代码}),
\]

\[
Y_E=I(\text{Security Oracle 支持并完成判定}),
\]

\[
Y_{secure}=Y_CY_EI(\text{Oracle=secure}),
\]

\[
Y_{joint}=Y_{secure}I(\text{functional pass}).
\]

主安全结果是 **oracle-evaluable secure-code yield** `Y_secure`。代码有效率、Oracle 支持率、unknown、功能通过率和 `Y_joint` 分开报告。`Y_joint` 是重要的实践次级结果，但不能替代主安全结果。

对假设 `h` 和模型 `m`，主 estimand 是：

\[
\tau_{hm}^{Y}=E_{(i,B_i),R,U}[Y(T,R,U)-Y(N,R,U)],
\]

其中 `B_i` 是任务 `i` 中未操纵且跨臂固定的 Prompt 背景，不是独立抽取的 `B~nu`。期望在冻结的 eligible task units、任务绑定背景、任务权重、realization 分布 `Q_h` 和请求随机性上取值。它是**特定政策在特定范围内的 ITT**，不是普遍的 `do(f=1)`、自然语言通用特征效应或模型无关效应。

对 Oracle unknown，观测 secure yield 不把 unknown 改成 insecure，而是另报 latent secure yield 的上下界。任何正向差异若主要来自代码生成率或 Oracle 覆盖变化，都不能解释为更安全的代码。

## 10. 识别条件与主张边界

### 10.1 随机政策效应

需要：完整 block 内随机分配、每个 arm 的正分配概率、政策一致性、无跨请求干扰，以及 provider 缓存/负载/时间状态不会系统性破坏分配。主张范围限于冻结的任务总体、模型、`Q_h`、Oracle 和结果。

### 10.2 观测 selector

只有在 positivity、来源重叠、测量质量和样本支持通过后，FCI 解释才进一步依赖 Markov、适当 faithfulness、CI 检验支持和冻结 background knowledge。PAG 中的圆端点必须保留为不确定，不能为了得到可干预方向而强行定向。

### 10.3 Oracle 与 Judge

Security Oracle 的结论只覆盖已校准的语言、任务形态和 profile。Functional Judge 是 AST/编译加盲态 LLM 功能审查，不等同于真实运行测试。两者都必须报告 unknown/unsupported，不得把缺少证据编码为成功。

## 11. 证据等级

| 等级 | 最低条件 |
| --- | --- |
| Observational Candidate | 冻结 discovery 与 selector 后得到候选；不是因果确认 |
| Randomized Policy Effect | Target-Noop assigned-arm ITT 的多重校正区间按预期方向排除 0 |
| Target-Specific Policy Effect | 上述条件加 Target-Placebo/Generic 的预注册 specificity 证据 |
| Realization-Robust Policy Effect | 多 realization 的方向、一致性、异质性和 leave-one-out 规则均通过 |
| Cross-Model Replication | 分模型结果按预注册复制规则通过；不能汇成“通用模型效应” |
| Bidirectional Support | ADD 与 REMOVE 各自随机化并在相反预期方向上得到支持 |
| Inconclusive / Null / Opposite / Non-evaluable | 分别保留，不得隐藏或改写为成功 |

## 12. 当前实现与理论规范的对应状态

这里严格区分 `specified`、`implemented`、`tested`、`executed` 和 `reported`。

| 部分 | 当前状态 | 说明 |
| --- | --- | --- |
| Prompt TSG、有限 catalog、evidence-bound facts、四值查询 | implemented + tested；fresh qualification executed and failed；structured-authority successor 仅 development-tested | 最终候选在完全不相交的替代 holdout 上为 13/14 exact、present recall 3/4、false-positive present=0、wrong realization=0；准确率通过 90% 门槛，但 recall 未达到预冻结的 80%，因此不能进入 formal extraction。后续四状态 authority 接口在 5 个已暴露 case 上为 5/5，只证明实现闭合，不改变 Gate |
| 自然 discovery population 与 positivity audit | implemented + tested；candidate census executed；formal audit not executed | 七源语义清洗和 2,165 份功能合同已闭合，373 条 Python 候选 census 已冻结；由于表示资格失败，正式 task split 与 discovery positivity 按协议未运行 |
| family-local FCI 与五类 selector 公平比较 | implemented + tested，未在当前自然数据上 executed | 活动 schema 2.1 将 catalog/prompt/Prompt TSG 闭合并重算状态；五类 selector、operation-specific `association.v3`、fixed/two-level/multi-slot 分析、typed-BK/PAG 敏感性、严格 Top-K/空槽、冻结 bridge、ConfirmedYield@K、nested task-unit bootstrap 和独立 verifier 已闭合；当前没有通过 gate 的正式自然 selector freeze，因而没有 selector 优越性结果 |
| RQ2 direct 与 direct+context representation 比较 | implemented + tested，未 formally executed | runner 只接受两个已经完整验证的 selector result bundles，重算 candidate coverage、protocolization、ConfirmedYield@K 和 effect summary；它比较的是两个端到端 funnel，不是保持候选宇宙不变的纯 selector 效应 |
| 原子假设与多 realization 政策 | implemented + tested | candidate skeleton、ADD/REMOVE operation、冻结 realization 分布、四臂 bundle、source eligibility 和 bridge provenance 已进入同一 successor freeze |
| successor ADD/REMOVE 四臂 | implemented + tested，未 formally executed | 活动 runner 已闭合 `Target/No-op/Placebo/Generic`、多模型 complete blocks、五个有序 endpoint、独立 security/functionality measurement、valid-code 条件 unknown Gate、total ledger、task-unit ITT、unknown bounds、realization/LORO robustness；若请求功能非劣效结论则必须预先封存研究专属 power qualification；verifier 从冻结 provider 响应离线重建代码、Oracle/Judge、Measurement、ledger、Gate 和 inference；目前只有离线合成 smoke，不形成新效果结论 |
| 二因素配对析因扩展 | specified + implemented + tested；单 pair/single-model historical schema 1.0 executed + reported | pair selector schema 1.2 已支持 operation-aware 编码、Prompt-TSG 状态重算、factorial compatibility、per-pair cross-fitted RD ranking 和 bootstrap stability；factorial schema 1.1 支持多 pair、多模型、两种顺序、简单效应、中性 response-surface taxonomy、预冻结 policy/mechanism claim scope 和原始测量重放。真实正式证据仍是 schema 1.0 的 from-scratch v3 零结果与 scaffold-repair follow-up 有界正向结果，不能把合成的 schema 1.1 测试称为新实验 |
| 独立 measurement 与 total ledger | implemented + tested | 活动代码保留 code、Oracle、functionality 和基础设施失败边界 |
| task-unit ITT 与未知 bounds | implemented + tested | Target/Noop、task/realization 权重和同步 bootstrap 已闭合 |
| 完整 max-|T|、selector nested bootstrap、全局 robustness family | implemented + tested；仅既有 factorial family executed | selector-pair simultaneous inference、successor realization/LORO family 和 generalized factorial families 都可独立重算；自然 selector 与新 successor study 尚未正式执行 |
| 正式 confirmatory 与 prospective follow-up | frozen + executed + independently verified + reported | v3 interaction=0；follow-up 保留同 30 个 task units、使用新 prompt/task identities，interaction=+70.0pp，不能合并或互相替代 |

## 13. 当前 Gate 状态

| Gate | 状态 | 含义 |
| --- | --- | --- |
| 理论边界：TSG、selector、randomization、measurement 分离 | **通过** | 概念边界已明确 |
| 自然 Prompt TSG 抽取资格 | **最终 holdout 未通过** | 14 个完全不相交 task units 中 13 个 exact；accuracy=92.9%、present recall=75.0%、false-positive present=0、wrong realization=0；准确率通过，但冻结 recall 门槛不允许 formal extraction |
| discovery positivity/source overlap | **按协议未执行** | 新鲜语义清洗与合同已完成，但表示 Gate 失败后不得冻结正式 discovery split 或读取自然 outcome |
| FCI selector | **实现通过；自然数据未运行** | backend、五类公平 selector、TSG lifting 和 artifact verifier 已测试，但没有通过 support gate 的活动数据，不能形成 selector 效用结论 |
| RQ2 representation comparison | **工程 Gate 通过；正式比较未运行** | direct 与 direct+context 两条完整 result funnel 的 lineage、adapter identity 和统计摘要可独立重放；尚无新前瞻冻结的双轨 provider 结果 |
| successor 单机制四臂实现 | **工程 Gate 通过；正式实验未运行** | prospective freeze、四臂执行、总账、稳健性推断和独立 verifier 已用离线代表样本闭合；legacy 四臂仍不能冒充 successor confirmation |
| Prompt-TSG pair selector | **工程 Gate 通过；自然数据未运行** | 关系证据、四 cell 支持、lineage 分离、固定 Top-L、冻结 artifact 和 verifier 已测试；尚无前瞻冻结的自然 pair selection 结果 |
| pairwise factorial canary | **已执行并独立验证；效应解释未通过构造效度审计** | 5 task units、2 个顺序、4 cells，共 40 assignments；旧任务合同和窄 Oracle 混入机制符合性，不能作为安全效应证据 |
| factorial from-scratch confirmation | **已完成并独立验证；正式零结果** | 30 个 task units、2 个顺序、4 cells，共 240 assignments；A00 安全率已达 96.7%，interaction=0，simultaneous interval=[-8.33,+8.33] 个百分点 |
| scaffold-repair prospective follow-up | **已完成并独立验证；有界正向结果** | 30 个相同 task units、240 assignments；A00=0%、A11=98.3%、interaction=+70.0pp，simultaneous interval=[+56.7,+83.3]pp；功能差=-1.7pp，通过非劣 Gate |

当前准确位置是：**Gate A 已按唯一规范闭合；Gate B 的活动最小方法已实现并通过离线/合成 reviewer tests。Gate C 已在前瞻冻结的 Prompt TSG 表示资格门失败，而不是“尚待继续跑”；因此 formal discovery、hypothesis/policy freeze、Gate D 与 Gate E 均未启动。现有论文效果证据仍只有已冻结的历史 schema-1.0 factorial v3 零结果与 scaffold-repair follow-up 有界正向结果，不能重标为新协议结果。**

## 14. v3 后续研究边界

1. **论文主轴。** 随机政策效应仍是当前可识别的主轴；FCI 是 availability-gated selector 扩展，当前不能报告 selector 优越性。
2. **正式零结果。** v3 的总体、cell、case 和 Oracle 结果保持不变；不能用 follow-up 的正向结果覆盖或重写它。
3. **follow-up 正向结果。** 可以主张受控 scaffold-repair policy 的 assigned-cell 效应和 joint Prompt-policy interaction；不能主张普遍机制 synergy、自然修复任务总体效应或“scaffold 相对 from-scratch”的随机因果效应。两项 mechanism trace 保持为独立重算的诊断，不进入 ITT 过滤。

后续若做跨模型或自然 repair benchmark 复制，必须另行前瞻冻结；不能根据本轮 task-specific outcome 选择任务或机制。

## 15. 最小活动调用图与阅读顺序

```text
dataset records
  -> task units / representative prompt
  -> qualified Prompt TSG / context and feature queries
       -> qualification fail: stop before formal extraction
  -> discovery support gate
       -> pass: frozen selector ranking
       -> fail: no selector claim; outcome-blind catalog hypothesis freeze
  -> selector-invariant bridge and hypothesis/multi-realization policy freeze
  -> atomic study: ADD/REMOVE four-arm materialization and complete blocks
       or pair study: outcome-blind pair freeze and 2 x 2 complete blocks
  -> code generation
  -> independent security and functional measurement
  -> total outcome ledger
  -> task-unit ITT, unknown bounds, simultaneous reporting
```

核心阅读严格限定为十个文件：

1. `docs/current-method-theory-framework.md`
2. `src/prompt_mechanism_study/representation.py`
3. `src/prompt_mechanism_study/prompt_tsg.py`
4. `src/prompt_mechanism_study/prioritization.py`
5. `src/prompt_mechanism_study/intervention.py`
6. `src/prompt_mechanism_study/randomization.py`
7. `src/prompt_mechanism_study/measurement.py`
8. `src/prompt_mechanism_study/outcomes.py`
9. `src/prompt_mechanism_study/inference.py`
10. `src/prompt_mechanism_study/workflow.py`

规范权威、数据规范和最新 gate evidence 已由第 1 项直接链接，不作为另一条活动执行路径。

## 16. 方法章节契约

- **读者进入前：** 知道研究关注安全提示，但无法区分表示、selector 和随机干预。
- **读者离开后：** 能准确说明 Prompt TSG 定义适用干预、selector 只分配预算、随机化识别政策效应、Oracle/Judge 独立产生结果。
- **必须呈现：** 任务单位、原子假设、两种数据生成机制、四臂、主 outcome、ITT、unknown、style 的三种位置和当前 gate。
- **不得呈现：** TSG 边是因果边、FCI 已产生有效 selector、legacy pilot 是 successor confirmatory result、功能失败可以从主安全分母剔除、unknown 等于 secure 或 insecure。
