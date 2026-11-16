# 跨环境效果共享开发研究

研究配置为 `configs/jci-transfer.json`，身份为
`POST_HOC_EXPOSED_TRANSFER_METHOD_CHECK`。本研究使用已经暴露的真实模型结果，
模型调用数量为零，正式 Atomic 协议保持原有状态。

## 统计拟合的含义

来源训练使用原有任务、随机分配、提示身份和测量结果拟合统计模型。代码生成 LLM
的参数保持固定。结构搜索估计变量之间的图形关系；结果模型估计给定任务和政策的
安全产出；共享效果模型估计政策相对 baseline 的差值。校准数据用于选择参数与策略，
最终评价数据只用于评价已经保存的选择。

## 科学问题与材料

目标是在固定目标环境请求预算下，检验 JCI 提出的属性集合是否改善跨环境策略收益。
数据沿用四个工具家族和 `local`、`example`、`reference` 三项表达政策。每项动作仍只
编辑一项政策，结果不能扩大解释为完整 Atomic 安全要求或自然任务迁移。

W 为三个编辑前初始要求状态；A 为原五值随机分配；X 为准备完成的三个提示状态；
E 为工具家族；Y 为原安全产出。Prompt TSG 的关系没有被用作因果箭头。效果伪结果
用于统计拟合，不进入主 PAG。

## 七个阶段与数据角色

1. 表示保留原任务、政策、初始状态、准备状态、提示和测量身份。
2. 优先选择从实际 JCI、FCI-time 和邻接消融产生属性集合；直接方法从共同子集总体
   中评价来源效果稳定性。各集合均为待评价模型。
3. 假设冻结保存四个目标家族、三个预算、全部角色、请求顺序、参数和主要比较。
4. 干预与随机化重放原随机混合请求，读取原分配概率 0.2，全部请求保留终止结果。
5. 测量沿用原安全产出、有限功能、Oracle 支持和未知结果，不重新评价代码。
6. 结果组装完成全部十二项策略选择后读取原 E 结果。
7. 推断按全部四百项 E 任务汇总，家族内任务重抽取时全部预算和方法共同移动。

每次保留一个家族作为目标环境。角色按结果不可见的固定散列划分：

| 角色 | 原任务 | 用途 |
| --- | --- | --- |
| 来源训练 | 三个来源家族各七十项 D 任务 | 结构、交叉拟合结果模型和共享效果拟合 |
| 来源校准 | 三个来源家族各三十项 D 任务 | 按政策选择拟合参数、评价来源效果稳定性 |
| 目标适配 | 目标家族五十项 D 任务 | 估计目标环境差异 |
| 目标校准 | 目标家族其余五十项 D 任务 | 选择属性组合、共享强度和编辑阈值 |
| 最终评价 | 目标家族全部一百项 E 任务 | 评价保存策略 |

目标预算为 128、256、512 项原始物理请求，分别等分给目标适配与目标校准。
各角色读取固定请求排列的嵌套前缀。来源角色使用其全部原随机混合请求。
重复请求按父任务合计等权，不增加独立任务数量。支持不足立即终止执行。

## 结构与属性候选

真实 conservative FCI 使用 E、四项分配指示、三个 W、三个 X 和 Y。已知随机分配
与 E、W 之间的边由设计固定为缺失。时间背景禁止 Y 指向生成前变量。JCI 方法另外
使用 E 与分配先于系统的约束，并仅对互斥随机分配指示使用 JCI123。自然环境标签
没有获得随机化外生性或无潜在混杂资格。

图形方法分别提出 W 中的确定祖先集合、可能祖先集合和完整集合。邻接消融只使用
W 与 Y 的邻接集合及完整集合。直接稳定性方法评价全部八个 W 子集：在来源校准中，
对每个属性状态计算三个来源家族的效果均值差异；缺少每家族至少两项任务支持的
集合保留支持不足。选择差异最小的两个集合，并保留完整属性集合。

每项政策可以选择不同属性集合。图形候选不是效果稳定性的证明，来源差异评分也
没有被解释为效果相等资格。若不同结构方法提出相同模型，保留其相同动作与收益。

## 结果模型、效果模型与校准

结果模型复用原重放的四十二项特征：初始状态、家族、准备状态、分配以及分配与
初始状态、家族的交互。对与 baseline 全文相同的请求保留其相同输入身份。
来源训练和目标适配按任务进行四折交叉拟合；完整拟合只用于独立的两项校准角色。
结果模型惩罚固定为 0.01。

各政策的 doubly robust 伪结果由交叉拟合的分配均值与原分配残差计算，分配概率为
0.2。重复请求在任务内部平均。两套完整提示均等同 baseline 的政策效果固定为零。

效果模型分解为共享部分和环境差异：`g_k(W_S) + r_k,E(W)`。共享部分使用 S 的
完整二元属性乘积基；环境差异使用全部 W 的乘积基和和为零的环境对比。
因此共享部分与环境部分具有明确参数定义。全部拟合采用正的有限 Ridge 惩罚。
同时保留按环境分别拟合的共同不共享候选。

每项政策独立选择共享属性和拟合参数；一个完整策略使用共同的环境差异惩罚。
来源校准以政策伪结果预测误差选择 Ridge 参数，目标校准以 doubly robust 策略收益
选择三个政策模型的组合、环境差异惩罚和 0、0.005、0.01 三个编辑阈值。
候选包含 baseline，校准收益非正时选择 baseline。各方法使用共同学习器、参数网格、
请求和最多三个候选属性集合，实际模型数量单独保留。

## 最终评价和区间

全部策略选择保存后，读取原 E 的冻结结果汇总和物理请求分配。每项任务保留两套
表达、每套两次原生成，比较所选政策与 B 的安全产出、有限功能、测量支持和未知率。
同时保存完整功能已知比例，有限功能通过不被扩大解释为完整功能。

三个预算各有四项主要比较：JCI 相对完整属性直接学习、直接稳定性、FCI-time、
邻接消融，共十二项。采用五千次家族内任务 bootstrap，并使用 alpha/12 构造双侧
同时描述区间；0.005 的实际意义门槛另行记录。四次环境留出共享训练材料，三个
预算复用请求，均不能作为独立实验重复。结论仅描述冻结选择下的原评价任务。

## 执行与独立验证

从仓库根目录执行，使用 Python 3.12、R/pcalg 2.7.12 和 jsonlite：

```text
python -m prompt_mechanism_study study jci-transfer NEW_OUTPUT --plan configs/jci-transfer.json --rscript PATH_TO_RSCRIPT --selection-only
python -m prompt_mechanism_study study verify-jci-transfer NEW_OUTPUT
```

`--selection-only` 完成并保存全部策略选择，不读取最终评价结果。对已经保存的选择
执行最终评价时，使用同一配置与输出目录，去掉该选项。配置中的材料路径指向服务器
冻结输入。服务器工作保持在 `/home/wsy/work/prompt-mechanism-study`。
`--limit 1` 执行预定代表条件，完整接续要求配置和科学源码保持相同。

独立验证重建角色与请求顺序，核对原终止记录，使用独立设计矩阵和特征分解复算
结果模型及共享效果模型，重新计算伪结果、所有校准选择、最终动作和十二项区间。
执行源码归档与验证器身份分别保存。已有冻结研究不被重新解释。

核心阅读顺序为本文、`configs/jci-transfer.json`、`src/cli.py`、
`src/discovery/jci_transfer.py`、`src/discovery/jci_transfer.R`、
`src/experiment/jci_transfer.py`、`src/verification/jci_transfer.py`，以及
`tests/jci/test_transfer.py`，共八项材料。

## 已执行的开发检查

2026-10-28 已使用全部四千项原始 D 随机混合请求，完成四个目标家族和三个预算的
十二项策略选择。执行环境为 Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、
scikit-learn 1.9.0、R 4.1.2 和 pcalg 2.7.12。默认测试全部十六项通过。

执行目录为 `/home/wsy/work/prompt-mechanism-study/inputs/jci-framework`，
结果目录为
`/home/wsy/work/prompt-mechanism-study/results/jci-transfer-development-20261028-evaluated`。
复现命令如下：

```text
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 TMPDIR="$PWD/.test-tmp" R_LIBS_USER="$PWD/.test-tmp/r-deps/usr/lib/R/site-library"
.venv/bin/python -m prompt_mechanism_study study jci-transfer /home/wsy/work/prompt-mechanism-study/results/jci-transfer-development-20261028-evaluated --plan configs/jci-transfer.json --rscript /usr/bin/Rscript
.venv/bin/python -m prompt_mechanism_study study verify-jci-transfer /home/wsy/work/prompt-mechanism-study/results/jci-transfer-development-20261028-evaluated
```

用户已明确授权本次读取原 E400 历史结果完成开发评价。独立验证状态为 `VERIFIED`：
复算一千零二十次模型拟合、三万七千七百五十四项条件独立统计，核对四千项原始训练
请求、全部角色、预算和策略选择，并复算四百项最终任务的动作、收益及十二项比较区间。
验证器 SHA256 为 `e5a3215529021cb23feed7ea161a89db20bf49aa6746ed9235003e87f8ae6524`。
全部六千四百项逻辑评价分配均保留，其中七项生成失败分配的安全产出为零，测量支持
和完整功能已知指标为零。新增生成模型调用数量为零。

[开发评价报告](experiments/2026-10-28-jci-transfer-results.md)保存全部主要比较、
功能与支持诊断，以及图形建议没有改变方法间动作的具体证据。
