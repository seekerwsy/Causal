# FCI、FCI-JCI 与 GFCI 的有真值合成对照（探索性）

状态：**已执行，非声明、非算法选型定论**。这是夜间政策实验之后补做的独立算法检查；不读取自然任务、受保护任务或代码生成结果，不改变 `SPECIFIED_DRAFT` 正式协议。先固定两个数据生成机制、5 个种子、总样本数 200/1000 和图恢复指标；看过这两档结果后，为检验与现有七个独立任务单元的规模差距，**后加** 14/24/50 档。全部结果只作探索性诊断。

## 问题与设计

要问的是：自然观测图搜索能否发现要求状态 `X` 与安全结果 `Y` 的邻接；随机 context `C` 是否使真实 `X→Y` 与潜在混杂的零作用场景更易区分；GFCI 在本类离散数据上是否显出值得取代 FCI 的恢复优势。这里的 `X/Y` 都是模拟变量，不是 Prompt TSG 边，也不是实际代码或干预后的依从性筛选。

每行是一独立模拟任务：`C` 为随机环境，`Z` 为独立可观测协变量，`U` 为未观测混杂。两种机制均设 `C,Z,U ~ Bern(0.5)`，之后依次按下式抽样，`σ` 为 logistic 函数：

| 真值场景 | `X` | `Y` | `X` 对 `Y` 的直接作用 |
| --- | --- | --- | --- |
| causal | `Bern(σ(-1+2C))` | `Bern(σ(-2+2X+1.2Z))` | 存在 |
| latent_null | `Bern(σ(-1+2C+1.5U))` | `Bern(σ(-2+1.8U+1.2Z))` | 零；观测关联由 `U` 造成 |

两个场景的观测系统骨架真值均为 `X–Y, Y–Z`；加入 context 后均为 `C–X, X–Y, Y–Z`。端点真值不同：causal 为 `C→X→Y←Z`，latent_null 有 `C→X↔Y←Z`。`C` 随机，因而 JCI1 的外生性及 JCI2 的 context–system 无潜在混杂在这个**合成机制**中成立。

每场景 × 每总样本数 `14, 24, 50, 200, 1000` × 五个固定种子 `11,22,33,44,55`，共 50 份同源数据。FCI 与 GFCI 都只读 `C=0` 的同一批自然观测行（约总量一半），用三个系统变量 `X,Z,Y`；合并 context 的 FCI 与 `pcalg` FCI-JCI0/1/12 读全部行 `C,X,Z,Y`。因此**各组骨架分母不同，不把它们的准确率直接排座次**。评价记录每条 PAG 原始端点、真边命中、假边、漏边；没有把邻接转成效应估计。

Python FCI 使用 causal-learn 0.1.4.7、`gsq`、`α=.05`、无限深度/路径、无背景约束。GFCI 使用官方 py-tetrad/Tetrad、离散 G² 检验 `α=.05`，BDeu 分数 `ESS=10`、结构先验 0。Python 合并 context FCI 是 **JCI0 表示检查**，不冒称执行了 JCI1/2 背景约束。真正的 FCI-JCI0/1/12 用 `pcalg` 2.7-12、`disCItest`、`α=.05`、`selectionBias=FALSE`、`contextVars=C`、`NAdelete=FALSE` 执行。`pcalg` 与 causal-learn 的小样本 G² 行为不同，故其差异含实现因素。

## 实际结果

共完成 **300 次算法调用**：Python FCI、GFCI、合并 context FCI 各 50 次；`pcalg` JCI0/1/12 各 50 次。保存的 300 条记录均无后端异常。以下分母均为五个固定种子，数字是描述性计数。

| 场景与总样本量 | 观测 FCI 完整骨架 | 观测 GFCI 完整骨架 | JCI12 完整骨架 | JCI12 正确区分 `X–Y` 端点 |
| --- | ---: | ---: | ---: | ---: |
| causal, 14 / 24 / 50 | 0 / 0 / 0 | 0 / 0 / 1 | 0 / 0 / 0 | 0 / 0 / 0 |
| latent_null, 14 / 24 / 50 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| causal, 200 / 1000 | 5 / 5 | 5 / 5 | 5 / 5 | 4 / 5 |
| latent_null, 200 / 1000 | 4 / 5 | 4 / 5 | 2 / 5 | 2 / 5 |

表中最后一列的 `4 / 5` 表示 200 行 4/5、1000 行 5/5；`2 / 5` 同理。对 causal 要求 `X→Y`，对 latent_null 要求 `X↔Y`。1000 行时，JCI1/12 在两个场景的五次重复中均给出各自正确的 `X–Y` 端点；JCI0 对 causal 保留 `X o→Y`，无法作同样区分。JCI12 还在该档给出正确的 `C→X`，说明**在这套满足随机 context 假设且样本充足的简单模拟中**，context 背景约束有结构识别价值。200 行 latent_null 的 JCI12 漏掉 `X–Y` 三次，不能将大样本表现外推到中小样本。

FCI 与 GFCI 对同一观测数据的骨架在 **47/50** 份数据上一致；另三份均在 14/50 行小样本中，GFCI 多找回一条真边。两个算法在 200/1000 档的完整骨架命中计数完全相同。这个有限、简化的基准**没有证明 GFCI 比 FCI 更适合当前自然任务，也没有证明二者等效**。

尤其要注意 `pcalg::disCItest` 的明确诊断：150 次 FCI-JCI 调用中 15 次报告 `n < n.min`，分别出现在总量 14 的 12 次、总量 24 的 3 次；该检验把受影响判断**当作独立**，导致边可能被删。`NAdelete=FALSE` 不能补救该内部行为。这些图不应作为“无边”证据。即使未触发警告，14–50 行的高漏边率也显示统计力不足。`n=14` 只粗略对应约 7 个 `C=0` 独立行；它没有模拟本项目四臂配对、任务族分布或安全 Oracle。

## 研究判断与复现

本轮修正了之前“仅纸面比较”的缺口：**FCI、GFCI 和带 JCI1/12 约束的 FCI 都已真实执行**，原始矩阵、端点与失败/警告保留在结果文件。结论仍是：当前七任务夜间政策实验应直接采用已分配臂的任务级 ITT；把 FCI/GFCI 邻接设为必要前置会在小样本下排除真关系，且邻接本身不是政策效应。JCI-FCI 仅在今后有共同测量的多环境变量、可辩护的随机 context 假设和足够独立任务数时，值得作为结构问题继续研究。正式 Atomic Full/RD-only 比较仍由现行协议规定，未被此次开发诊断修改。

复现入口：

```powershell
$env:JAVA_HOME='D:\Program Files\Java\jdk-24'
.\.venv\Scripts\python.exe docs\experiments\2026-09-26-algorithm-benchmark.py results\2026-09-26-causal-algorithm-benchmark.json
& 'D:\R\R-4.3.1\bin\x64\Rscript.exe' docs\experiments\2026-09-26-jci-fci-benchmark.R results\2026-09-26-causal-algorithm-benchmark.csv results\2026-09-26-jci-fci-benchmark.csv
```

输入生成和 Python 原始记录：[基准脚本](2026-09-26-algorithm-benchmark.py)、[JSON](../../results/2026-09-26-causal-algorithm-benchmark.json)、[跨语言相同输入 CSV](../../results/2026-09-26-causal-algorithm-benchmark.csv)；R 专用 JCI 运行：[脚本](2026-09-26-jci-fci-benchmark.R)、[原始结果](../../results/2026-09-26-jci-fci-benchmark.csv)。环境为 Windows 11、Python 3.12.13、NumPy 2.5.1、py-tetrad 0.1.2（Git commit `b967024e14e4918d282130b65ee39e6936f6a9e5`）、Tetrad JAR SHA-256 `ed4b4e3da97c3bd0b1d1685d992b2116c65f10dd5800f273a16a24d90bff3d36`、Java 24.0.1、R 4.3.1、pcalg 2.7-12。以独立读取保存记录的方式复算全部 300 条 TP/FP/FN，均一致。

算法依据：[causal-learn FCI 官方文档](https://causal-learn.readthedocs.io/en/latest/search_methods_index/Constraint-based%20causal%20discovery%20methods/FCI.html)、[JCI 原论文](https://www.jmlr.org/papers/v21/17-123.html)、[pcalg FCI-JCI 文档](https://search.r-project.org/CRAN/refmans/pcalg/html/fci.html)、[GFCI 原论文](https://proceedings.mlr.press/v52/ogarrio16.html)、[Tetrad 官方 Python 接口](https://github.com/cmu-phil/py-tetrad)。
