# 从图恢复转向政策效用：本轮实跑与方法决定

状态：**EXECUTED / INDEPENDENTLY VERIFIED / SYNTHETIC DEVELOPMENT ONLY**。真实任务上的算法选择收益、自动TSG优势及新模型效应均未验证。研究目标尚未整体完成。

## 这次新增了什么

[事前方案](2026-09-26-decision-value-plan.md)固定七种二元SCM、N=64/256/1024和50种子。每份矩阵为相同的随机分配A、事前任务结构M、干扰属性Z及结果Y。共1050份数据、2100次Tetrad FCI/GFCI和3150次pcalg JCI0/1/12搜索，无后端异常或CI警告。另有一份不同种子的5搜索canary，不进入主表。

比较规则事前固定：不编辑、按总体RD决定是否全部编辑、按M两组RD分别决定，以及每种图算法先要求A–Y邻接再执行同一个分层RD规则。这里研究的是图算法的一种明确使用方式，不是它原生输出政策建议，也不是正式自然状态Full/RD-only复现。

每个策略用已知SCM的精确总体期望评价，不在训练结果上自评；指标是相对不编辑的安全概率增益。总体M两组各占一半。下表每格是50份独立训练样本所得策略的平均真值收益，单位为百分点；不是50次真实模型实验。

| 机制 / N | 总体RD | 事前分层RD | FCI门控＋同一分层RD | JCI12门控＋同一分层RD | 解释 |
|---|---:|---:|---:|---:|---|
| 各组均有+20pp作用 / 64 | 18.4 | 17.6 | 6.0 | 6.0 | 小样本分层增加估计误差，门控进一步损失检出 |
| 各组均有+20pp作用 / 1024 | 20.0 | 20.0 | 20.0 | 20.0 | 不需要条件化，几种规则均达到本场景最优 |
| 一组+40pp，另一组−30pp / 1024 | 4.7 | 20.0 | 4.8 | 4.8 | 总体效应很小，但可使用的条件收益很大；门控只在12/50次允许进入分层 |
| 一组+40pp，另一组−40pp / 1024 | 0.0 | 20.0 | 1.2 | 1.2 | 精确抵消违反忠实性；这是适用边界压力例，不是合格条件下FCI失败证明 |
| 各组均有−20pp作用 / 64 | −1.2 | −3.0 | 0.0 | 0.0 | 门控在本批次减少了误建议；分层并非总更好 |
| M只影响基础成功率、政策作用均+20pp / 64 | 19.6 | 16.8 | 5.2 | 5.2 | 能预测结果的结构属性不等于有效的政策修饰属性 |

关键MC标准误：近抵消N1024总体RD为0.17pp、FCI/JCI12门控为1.22pp；各组均有效N64总体RD为0.78pp、分层0.61pp、FCI门控1.31pp；有害N64分层0.77pp。某些格子50次决策相同，经验MCSE为0；这不证明未来永不出错。

零效应机制中各规则安全增益都为0。在N64时，不必要编辑的总体质量为总体RD44%、分层48%、图门控2%；N1024分别60%、56%、0%。这是无成本安全收益下的冗余行为，不应伪称安全损害。下次应加入与门控同等保守程度的直接效应阈值/不确定性基线，才能判断其保守收益是否专属于结构学习。本轮未事后追加该基线。

JCI0/1/12在本批1050份数据上A–Y邻接准入及最终策略相同。这不否认方向信息增量；本轮选择规则本来只消费邻接。它直接说明：**若下游规则没有使用新增方向信息，仅更换为JCI并不能使方向增量转成决策增量。** FCI与GFCI在个别小样本格子不同，全表保留于结果CSV。

## 可以作出的研究决定

1. **不能继续用一个“最佳因果算法”回答不同问题。** 对已随机分配的提示政策，总体或条件政策效应是直接对象；FCI/JCI用于另外定义的结构问题。本轮进一步量化了目标错位的决策代价，而非只作概念提醒。
2. **TSG需要同时服务精确编辑和跨任务比较。** 前者保留具体对象、操作、条件与全部目标；后者输出同义的事前属性，例如生命周期、受约束对象数量、条件作用范围。只使图更丰富，却仍以总体邻接筛选，会丢掉条件政策机会。
3. **不能机械地增加所有TSG属性或每题分组。** 本轮prognostic案例显示，只预测基础结果的变量用于细分会损失小样本效用。后续需要预定义少量语义分层，或独立学习/估计的浅规则，并用留出任务验证；这不是已实现honest tree/forest的成绩。
4. **干预先保持完整Atomic和可复现版本。** 对同一合法政策适用范围保持统一随机化与测量，保证比较的要求含义一致。既有程序、输入类型、返回约定由所有臂共享；未明确的source状态保留unknown。不要故意破坏编辑以给JCI制造变异。
5. **新颖性仍是待检验问题。** 精确抵消和已知API语义不是本项目的新发现。本轮支持优先研究“语义属性如何改善选择并避免有害建议”，但尚未证明真实代码模型存在相同异质性。

## 方法地图与文献依据

下表“项目决定”是基于文献和本地证据的判断，不是文献已经证明本项目有效。

| 类别 | 能回答什么 | 项目决定与必要条件 |
|---|---|---|
| 随机分配后的任务级ITT / 预定义分层 | 固定政策平均作用、已定义子群作用 | 当前效应主线；保留去重任务、ITT及共同适用范围。分层不能自动推广为可操纵M的作用 |
| honest causal tree / causal forest | 学习效应异质性 | 下一优先级候选；需要足够独立任务、训练与估计分开，树/森林输入应为事前属性；不能随机拆散同任务生成行 [R3,R4] |
| FCI / GFCI | 潜在混杂下的结构等价类 | 自然状态有支持时可探索；GFCI改变搜索策略，不解决目标错位。原小规模比较没有普遍替换依据 [R2] |
| JCI-FCI | 多环境联合结构和背景知识 | 结构研究的首选适配候选；先明确环境、随机化/外生性、同义系统变量与新增可行动query，不能从A影响Y重新包装已知随机对比 [R1] |
| GIES / UT-IGSP | 已知/未知干预目标下的DAG结构 | 当前不直接替换：要有符合其设置的系统变量、干预与因果充分性等依据；提示要求不等于设置了代码性质 [R5,R6] |
| CD-NOD / effect-invariance | 机制随环境改变；效应跨环境迁移 | 在真正跨任务来源/环境的研究中再比较；不同来源标签本身不提供不变性保证。effect-invariance专门说明效应迁移可不依赖完整因果图 [R7,R8] |
| LIT等未知目标学习 | 推断哪些被测系统变量受到干预 | 值得作为替代设计的文献候选；潜混杂下可能只能得到目标超集。当前缺相应变量与查询，未实跑，不宣称排除所有适配可能 [R9] |

### Verified References 与 Citation-to-Claim Map

检索模式：academic-citation / targeted-citation-search。目标为方法决策，不是Introduction/Related Work写作；Exemplar Set不适用。以下条目元数据与所列范围已在一手页面核验；未宣称逐页复现全部定理。DOI/arXiv字段未核验者省略，不补造。

- **[R1] VERIFIED / primary_source** — Joris M. Mooij, Sara Magliacane, Tom Claassen. *Joint Causal Inference from Multiple Contexts*. JMLR21(99),2020. [原文](https://www.jmlr.org/papers/v21/17-123.html)。映射：JCI是可利用背景知识的多环境建模框架，支持不同干预类型；method_comparison。
- **[R2] VERIFIED / primary_source** — Juan Miguel Ogarrio, Peter Spirtes, Joe Ramsey. *A Hybrid Causal Search Algorithm for Latent Variable Models*. PGM/PMLR52:368–379,2016. [原文](https://proceedings.mlr.press/v52/ogarrio16.html)。映射：GFCI结合评分与约束搜索、面向潜变量设置；method_comparison。
- **[R3] VERIFIED / primary_source** — Susan Athey, Guido Imbens. *Recursive partitioning for heterogeneous causal effects*. PNAS113(27):7353–7360,2016. DOI10.1073/pnas.1510489113。[原文](https://www.pnas.org/doi/10.1073/pnas.1510489113)。映射：异质性分区与honest训练/估计分离；baseline。
- **[R4] VERIFIED / official_documentation** — grf项目，*Multi-arm/multi-outcome causal forest*。[官方接口](https://grf-labs.github.io/grf/reference/multi_arm_causal_forest.html)。映射：实现支持多臂及任务分组标识；只验证软件能力，不据此证明小样本有效；method_comparison。
- **[R5] VERIFIED / primary_source** — Alain Hauser, Peter Bühlmann. *Characterization and Greedy Learning of Interventional Markov Equivalence Classes of Directed Acyclic Graphs*. JMLR13(79):2409–2464,2012。[原文](https://www.jmlr.org/papers/v13/hauser12a.html)。映射：干预等价类及GIES的结构学习目标；method_comparison。
- **[R6] VERIFIED / primary_source** — Chandler Squires, Yuhao Wang, Caroline Uhler. *Permutation-Based Causal Structure Learning with Unknown Intervention Targets*. UAI/PMLR124:1039–1048,2020。[原文](https://proceedings.mlr.press/v124/squires20a.html)。映射：观测/干预混合且目标未知的DAG学习；method_comparison。
- **[R7] VERIFIED / primary_source** — Biwei Huang, Kun Zhang, Jiji Zhang, Joseph Ramsey, Ruben Sanchez-Romero, Clark Glymour, Bernhard Schölkopf. *Causal Discovery from Heterogeneous/Nonstationary Data*. JMLR21(89):1–53,2020。[原文](https://www.jmlr.org/papers/v21/19-232.html)。映射：利用跨环境机制变化探索结构；method_comparison。
- **[R8] VERIFIED / primary_source** — Sorawit Saengkyongam, Niklas Pfister, Predrag Klasnja, Susan Murphy, Jonas Peters. *Effect-Invariant Mechanisms for Policy Generalization*. JMLR25(34):1–36,2024。[原文](https://jmlr.org/papers/v25/23-0802.html)。映射：在相应假设下利用效应不变性进行政策迁移，不要求完整因果图；gap_motivation。
- **[R9] VERIFIED / primary_source** — Yuqin Yang, Saber Salehkaleybar, Negar Kiyavash. *Learning Unknown Intervention Targets in Structural Causal Models from Heterogeneous Data*. AISTATS/PMLR238:3187–3195,2024。[原文](https://proceedings.mlr.press/v238/yang24d.html)。映射：未知干预目标识别与潜混杂下的超集结果；method_comparison。

## 实施与复核

科学实现：`src/development/causal_decisions.py`（生成SCM、Tetrad搜索、明确策略与真值评分）；`docs/experiments/2026-09-26-decision-jci.R`（相同矩阵的pcalg搜索）。未修改正式研究入口、旧算法脚本或旧冻结结果。

输出：`results/decision-value-20260926/`。`frozen/`含事前配置、代码和方案快照、Python/Java后端身份；`input.csv`是所有方法共同输入；`tetrad/graphs.json`和`jci.csv`保存5250个原始图；**有效结果仅为`analysis-corrected/`**，其中含每项决策、全分组汇总和分析修复快照。

第一次汇总把字面场景名`null`按pandas默认规则转为缺失，漏掉零效应场景；账面900而非1050立即暴露该问题。只修正CSV标签解析，未更改SCM、算法、随机种子、选择规则或原始图。旧`analysis/`保留为 **INVALID_MISSING_NULL_SCENARIO**，不能引用。该问题无需重跑搜索。

独立复核使用标准库/Fraction从原始行重算均值差、8种策略、8400条决策、策略真值与全部汇总，并从R的列优先PAG矩阵重算A–Y邻接，检查哈希与1050/5250完整账。已通过；不是后端算法正确性的独立证明。R启动locale提示与CI警告分开。

执行与复核命令：

```powershell
$env:JAVA_HOME='D:\Program Files\Java\jdk-24'
.venv/Scripts/python.exe -m prompt_mechanism_study.development.causal_decisions run NEW_OUTPUT
& 'D:\R\R-4.3.1\bin\x64\Rscript.exe' docs/experiments/2026-09-26-decision-jci.R NEW_OUTPUT/input.csv NEW_OUTPUT/jci.csv
.venv/Scripts/python.exe -m prompt_mechanism_study.development.causal_decisions summarize NEW_OUTPUT
.venv/Scripts/python.exe -I -S docs/experiments/2026-09-26-decision-verify.py NEW_OUTPUT
```

重跑使用新目录。本轮没有GPU或模型请求、自然任务新增暴露、正式协议激活或真实context效应声明。结果可支持下一轮设计，不能填补尚未执行的真实政策选择研究。
