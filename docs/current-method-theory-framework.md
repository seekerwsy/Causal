# Prompt Mechanism Study 当前理论与方法框架

**状态：** 当前方法的审查性总览，不是新的协议版本

**规范权威：** [上下文条件化干预政策框架](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md)

**数据权威：** [研究数据集规范](research-dataset-spec.md)

**最新门控证据：** [自然提示 positivity pilot](experiments/2026-08-26-natural-prompt-positivity-pilot.md)

本文把现有理论规范、活动代码和已运行证据整理为一条可审查的方法链。它不重新定义冻结实验，也不把规划中的组件写成已经实现或已经产生结果。

## 1. 当前方法的一句话定义

Prompt Mechanism Study 是一个**由 Prompt TSG 约束、按任务上下文限定、以任务单元为独立单位、通过随机分配识别提示干预政策效应**的研究框架；观测因果发现只在自然提示满足支持条件时，作为预算化假设选择器使用，而不产生最终因果结论。

更短地说：

```text
Prompt TSG 定义“在什么上下文中可以改什么”
selector 决定“有限预算下优先测试什么”
随机实验决定“冻结的提示政策是否产生效果”
```

当前最稳健的核心是第一行和第三行。第二行是有前置门控的扩展：最新自然提示 pilot 未通过 positivity 和来源重叠门，因此 FCI 尚未执行，也不能形成 selector 优越性结论。

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

最新 positivity pilot 在 CWE-328 和 CWE-611 上均未通过支持门，且 CWE-611 的特征状态被来源 lineage 完全分离。因此当前框架采用：

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

这里的 placebo 是**随机化的控制政策**，不是发现阶段的源提示风格变量。

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
\tau_{hm}^{Y}=E[Y(T,R,U)-Y(N,R,U)],
\]

期望在冻结的 eligible task units、任务权重、realization 分布 `Q_h` 和请求随机性上取值。它是**特定政策在特定范围内的 ITT**，不是普遍的 `do(f=1)`、自然语言通用特征效应或模型无关效应。

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
| Prompt TSG、有限 catalog、evidence-bound facts、四值查询 | implemented + tested + pilot executed | 38 个自然 prompt 完成盲态抽取；这不是 selector 或 effect 结果 |
| 自然 discovery population 与 positivity audit | implemented + tested + executed + reported | 两个 scope 均未过门；FCI 正确未运行 |
| family-local FCI 与五类 selector 公平比较 | specified，未形成当前可执行主证据 | 当前数据支持不足；活动最小代码只接受外部 score，并未闭合完整 selector benchmark |
| 原子假设与多 realization 政策 | 部分 implemented + tested | 最小 kernel 已有 candidate、realization、bundle 和 policy 绑定；完整 successor freeze 字段尚未全部闭合 |
| successor ADD/REMOVE 四臂 | specified，未在最小 kernel 完整实现 | 最小 kernel 目前只有 `TARGET/NOOP`；另一个 four-arm 路径属于已冻结 legacy/pilot 实现，不能冒充 successor 协议 |
| 独立 measurement 与 total ledger | implemented + tested | 活动代码保留 code、Oracle、functionality 和基础设施失败边界 |
| task-unit ITT 与未知 bounds | implemented + tested | Target/Noop、task/realization 权重和同步 bootstrap 已闭合 |
| 完整 max-|T|、selector nested bootstrap、全局 robustness family | specified，部分 implemented | 尚不能声称 successor 的完整多重推断已执行 |
| 正式 confirmatory study | not frozen / not authorized | 当前没有 successor confirmatory effect 结果 |

## 13. 当前 Gate 状态

| Gate | 状态 | 含义 |
| --- | --- | --- |
| 理论边界：TSG、selector、randomization、measurement 分离 | **通过** | 概念边界已明确 |
| 自然 Prompt TSG 抽取 canary | **有界通过** | 38/38 记录有效，但还有 unresolved 语义和 Python 版本风险 |
| discovery positivity/source overlap | **未通过** | CWE-328 无 positive；CWE-611 状态与来源完全分离 |
| FCI selector | **未运行** | 被前一 gate 正确阻止 |
| successor 假设/四臂/推断完全冻结 | **未通过** | 规范与活动实现仍需对齐 |
| successor confirmatory generation | **未授权** | 不能把 legacy/null pilot 当作新协议正式证据 |

当前准确位置是：**理论内核已稳定，观测 selector 分支被数据支持门阻塞，随机确认分支尚处于 successor 协议与实现对齐之前。**

## 14. 仍需正式决定的三件事

1. **论文主轴。** 若不新增具有同 lineage 双状态自然变化的数据，主论文应以“Prompt TSG 条件化的随机政策效应”为主，FCI 降为 availability-gated 的 selector 扩展；否则 RQ1/RQ2 仍无法获得所需主证据。
2. **四臂权威。** successor 规范的主对比是 Target-Noop；`README`/旧 four-arm 产物中的 `specific-placebo` 只能保留为 legacy 结果，不能继续作为新确认实验的主 estimand。
3. **实现闭合范围。** 在正式生成前，只补齐 successor 所需的四臂语义、operation-specific eligibility、freeze 字段和主推断；不要恢复部署、恢复、campaign 或历史兼容框架。

这些决定都发生在新的 confirm outcomes 之前，因此可以作为前瞻性修订；一旦正式 freeze，就不得根据效果方向再修改。

## 15. 最小活动调用图与阅读顺序

```text
dataset records
  -> task units / representative prompt
  -> Prompt TSG / context and feature queries
  -> discovery support gate
       -> pass: frozen selector ranking
       -> fail: no selector claim; outcome-blind catalog hypothesis freeze
  -> hypothesis and multi-realization policy freeze
  -> arm materialization and blocked randomization
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
