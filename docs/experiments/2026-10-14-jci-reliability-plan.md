# JCI 非祖先误判、有限正则化与独立策略收益检验

用户于 2026-10-14 授权追查有效政策被设为零的原因、改进方法并检验相对直接方法的可靠策略收益。证据身份为 `AUTHORIZED_BOUNDED_PROSPECTIVE_SCM_METHOD_CHECK`，正式 Atomic 协议保持 `SPECIFIED_DRAFT`。研究使用已暴露结果进行错误定位，并对新计算重复前瞻性冻结方法；不调用代码生成模型，不使用受保护任务。

## 需要区分的科学对象

图形中的非祖先判定依赖输入条件独立信息和 Markov、faithfulness 等假设。有限样本检验的非拒绝、PAG 的非祖先提议、真实政策效果为零，以及最终策略收益分别保存。子样本的一致判定不授予置信水平。

原结果的诊断逐项重放真实 pcalg FCI，要求最终 PAG 与已保存 PAG 完全相同；记录实际导致上下文—结果删边的检验、精确联合分布中的条件依赖、图形 d-separation 以及时间顺序定向前后的判定。精确联合分布仅用于诊断和最终评价，学习器不读取它。

对互斥的四项政策和基线均匀分配，令 q 为 ADD 可以改变来源状态的概率。`Ci` 与结果的无条件均值差为 `q*(beta[i]-sum(beta[j],j!=i)/4)`；目标政策相对基线的 ITT 为 `q*beta[i]`。两者可以有不同强度，也可以分别为零和非零。`cancelling_dense` 专门检验这一边界，全部预定条件均报告。

JCI 原论文明确要求联合分布的 faithfulness；pcalg 的非祖先输出描述输入 PAG 等价类中的关系。这些条件不等同于有限样本的误判控制。参见 [JCI 原论文，第 4.1 节](https://www.jmlr.org/papers/volume21/17-123/17-123.pdf) 与 [pcalg 官方手册，fci、pag2anc、udag2pag](https://cran.r-project.org/web/packages/pcalg/pcalg.pdf)。

## 七阶段与改进方法

| 阶段 | 输入、操作与输出 |
| --- | --- |
| 表示 | 保存来源状态 W、准备后的要求状态 X、单项随机分配 A、实际成功次数及生成次数。Prompt TSG 不提供因果箭头，生成代码结构不进入 PAG。 |
| 优先化 | 使用真实 conservative FCI-time、JCI12、JCI123。保留模糊碰撞三元组，并在随后应用时间及 JCI 背景信息时继续传递该信息。 |
| 假设冻结 | `data/method/jci-reliability-20261014/plan.json` 固定全部机制、数量、生成次数、批次、消费者、校准及比较。运行前保存配置、源码和环境身份。 |
| 干预与随机化 | 每个任务均匀分配基线或四项完整要求 ADD 中的一项，最多改变一个要求。生成次数为一或八，全部次数属于同一独立任务。 |
| 测量 | 结果按预定 SCM 实际抽样。结构搜索读取整数成功次数；结果学习读取成功比例。全部任务保留。 |
| 结果组装 | 交叉拟合共同来源结果辅助模型，使用中心化分配特征学习效果。有限样本图形只调节正的有限惩罚，不固定效果系数为零。CAL 按预定任务划分分别选择拟合参数和策略。 |
| 推断与报告 | CAL 完成后精确评价全部来源状态中的策略价值。按独立重复成对比较全部直接方法及结构消融，完整报告正值、零值、负值和未知图形判定。 |

### 统计信息进入消费者的方式

每项结构方法的非祖先提议为 s，未知判定不产生该提议。直接基线—目标条件检验发现依赖时，取消该政策的非祖先惩罚提议。这个规则提供候选学习中的保护，不宣称独立的零效果资格。

效果系数的惩罚为 `lambda*(1-strength+strength*s)`，strength 为 0、0.5、0.9，全部惩罚保持正值。共同标量参考包含所有可能的统一惩罚值，防止通过额外的惩罚范围获得表面优势。CAL 按结果不可见的随机流划分为相同数量的拟合与策略角色。拟合角色在每项表示与强度下按实际分配结果的平方预测损失选择惩罚；策略角色使用共同训练辅助模型和已知分配概率，在这些拟合与基线动作中选择 doubly robust 收益最高的策略。所有方法共享完整的普通 Ridge 参考候选。选择过程不读取真实系数、未分配结果或最终策略价值。

`target_factorized` 使用 `tau_i(W)=(1-W_i)*theta_i`，共有四项效果系数；`full` 使用 `tau_i(W)=(1-W_i)*(theta_i0+sum(theta_ij*W_j,j!=i))`，共有十六项效果系数。两项表示均让已具有目标要求的来源状态产生零编辑差值，并保留全部任务。中心化分配设计为实际分配政策的特征减去五项均匀动作的平均特征。共同来源结果辅助模型使用变换 `2W_j-1` 的全部十五项非空乘积基函数与截距，按两个任务折交叉拟合。当前常量系数 SCM 的真实效果形式包含在 `target_factorized` 中。选择基线动作时，效果估计记录为未知。

结构消费者与直接 Ridge、ElasticNet、直接标准化效果权重、直接条件独立权重使用相同的来源表示、交叉拟合辅助结果和 CAL。`direct_envelope` 候选合集包含这四项直接方法与邻接消融的候选，全部成员也单独比较。邻接消融保留 JCI123 的完整骨架及直接依赖保护，读取 Ci—Y 是否邻接，用于检验方向信息是否提供额外作用。

已知真实零效果集合提供单独的信息上限消费者；其结果不归入实际 JCI 方法，也不参与主要增量判定。

## 前瞻性实验范围

八项机制为 sparse、weak_sparse、strong_sparse、unconfounded_sparse、signed、all_harmful、dense、cancelling_dense，完整系数和潜在结果影响见配置。signed 保留有益与有害政策同时存在的情形；all_harmful 检验基线动作最优时的错误编辑。每个 D 与 CAL 角色包含 128、512 或 2048 项独立任务；每项分配提示生成一或八次。每个条件有两个独立种子批次，各 32 个重复，共 64 个独立重复；总计 48 个条件、3072 项重复。

结构搜索每项 D 任务只提供一个成功次数观测。八次生成不增加结构样本量。D 与 CAL 的任务身份完全分离；同一重复中的各个方法共用观测。潜在变量和真实效果只用于抽样及最终评价。所有概率在抽样前验证。

主要比较为 JCI123 相对 Ridge、ElasticNet、直接标准化权重、直接条件独立权重、直接候选合集、邻接消融、FCI-time、JCI12。全部 48 个条件共 384 项成对比较，使用 Bonferroni 同时 paired-t 区间。一个条件满足可靠增量要求，需要全部八项差值区间的下限大于零，并且两个独立种子批次的平均差值均大于零。另行报告增量是否达到预定 0.5 个百分点的实际意义门槛。

这些区间描述前瞻性冻结的有界 SCM 方法研究。它们不构成真实模型安全代码产出、自然任务迁移或自动语义表示准确率的确认性证据。

## 执行与独立验证

单一命令入口为 `src/cli.py`。配置固定八个独立计算进程，每个进程限制 BLAS 为一个线程；进程执行不改变方法、随机流或比较规则。实际实验保存在 `results/jci-reliability-20261014/experiment`；诊断保存在同一研究目录的 `diagnosis`。输入、源码压缩包和逐项结果均保留独立校验值。

```text
python -m pip install -e ".[dev,analysis]"
python -m pytest tests/development/test_jci_reliability.py -q --basetemp=.test-tmp/NEW_RELIABILITY_CHECKS
python -m prompt_mechanism_study study jci-reliability results/NEW_RELIABILITY_RUN --plan data/method/jci-reliability-20261014/plan.json --rscript D:/R/R-4.3.1/bin/x64/Rscript.exe
python -m prompt_mechanism_study study verify-jci-reliability results/NEW_RELIABILITY_RUN --workers 4
```

运行前设置 `OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`、`LC_ALL=C`。使用 Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、R 4.3.1、pcalg 2.7.12；R 包位于 `.codex-runtime/r-lib`。独立验证重建随机化及任务角色、全部实际列联统计量、四项直接条件检验的 Monte Carlo 抽样、Ridge 解、ElasticNet 最优性条件、有限惩罚、CAL 选择、真实结构信息的隔离、精确策略价值及全部同时区间。

阅读顺序包含九项核心文件：本设计、配置、`src/discovery/jci_reliability.py`、`src/discovery/jci_reliability.R`、`src/discovery/jci_policy.py`、`src/discovery/jci_sharing.py`、`src/experiment/jci_reliability.py`、`src/verification/jci_reliability.py`、`tests/development/test_jci_reliability.py`。共有的随机流、特征表示、条件随机化检验和 R 通信保留在相应共享模块，精确版本随运行源码一同保存。原结果的删边重放另见 `src/verification/jci_trace.R`。
