# JCI 目标预算曲线结果

## 已固定输入

本轮遵循[完整设计](2026-11-02-jci-target-budget-curve-design.md)。三个预算的目标结果合计分别为64、128、256项，共96个来源学习重复、288个预算条件，预定比较家族213项。主要判定固定在最低预算的下游末端机制，另外记录使用一半目标数据的独立判定。

科学配置于首次数据生成前固定；初始输入包大小553841字节，SHA256为 `0c443cd4a700fb0deb8e0104b4ce3e8548474a88602147f473d87b87f54ea1b3`，固定时间为2026-11-01 20:15:49 UTC。共同配置摘要为 `fb681bf619232c51e035a2d5beb945bcce7f5acd373ccc147dcbc2b0ca8e148e`。新批次为2026111451、2026111452，所有数据配置、随机种子、比较规则与主要判定保持原值。

预检查状态为 `VERIFIED_BUDGET_CURVE_PREFLIGHT`：原有16与32配置的完整冻结单元均通过当前数值核对及新增的单方法积分标准误差检查，原全部51项比较区间复现一致，213项完整家族的校正区间相应扩大。该预检查不增加科学重复。

## 完整执行与独立核对

状态为 `VERIFIED_TARGET_BUDGET_CURVE`。完整288个预算条件、96个独立来源学习重复、213项预定比较均已完成。三个预算的来源观测、查询、科学图字段及来源拟合保持相同，跨预算条件按来源重复配对。每种机制的独立统计重复为32；288个预算条件不计为288个独立来源重复。

最低预算 `n16`、中等预算 `n32`、最高预算 `n64`各自96个单元均已完成独立数值核对及96张原生图重放，三项实际核对输出均为 `status=VERIFIED, cells=96, native_graphs_replayed=96`。每个预算还完成16,992次独立模型重拟合。全部单元完成后，生产汇总和独立核对分别读取全部原始单元，核对共同来源身份、实际数据数量、积分误差、完整比较集合及213项校正区间。结果摘要为 `7e522aa221f3a5f57bb7a245cad5a830a20ed014f0dd256514e96d9719b121cb`，整组核对器摘要为 `75f5425618319682e4474995265f6c9dbb28519d5ad3bbf38293cf0b24ba6135`。

实际运行输入包大小554878字节，SHA256为 `3660ee5c7ac14240b22833a792ad0bc66c022e4153a481af5783f501ab1426f4`。独立核对器为 `6343ed61bbb6b6a98b76de2204ae6e35f756c1f611f47cde39a8e82f57936605`，R结构后端为 `2ded804a3f10226d42a3cdff415835faeb8afe80f4a40c4fb24830e952c88456`。当前输入包及服务器部署内容已逐项核对摘要。

`tests/development/check_jci_runtime_temp.py`实际启动真实R后端，观察到项目结果目录中的R临时目录，并成功重放一张已有冻结图；状态为 `VERIFIED_PROJECT_SCOPED_R_TEMPORARY_DIRECTORIES`。核对记录位于 `data/method/jci-target-budget-curve-20261102/runtime-check.json`，SHA256为 `e7c0d34714f3a8367d71a7b8a887a4c06e8e767f256fcdfcbc65df0b180b0cda`。该检查不增加科学重复。

实际入口为 `data/method/jci-target-budget-curve-20261102/run.sh`。服务器输入目录为 `/home/wsy/work/prompt-mechanism-study/inputs/jci-target-budget-curve-20261102-runtime`，结果目录为同项目的 `results/jci-target-budget-curve-20261102-runtime`，其中 `driver.stdout.txt`及 `driver.stderr.txt`保存全部过程输出。八个工作进程、每个进程一个数值运算线程，使用已有处理器和依赖，没有启动代码生成模型或读取受保护数据。结构后端和原生图重放在子进程启动之前指定项目临时目录。

整组汇总使用固定八个进程读取独立单元；`tests/development/check_budget_parallel_aggregation.py`已在三个预算各一份真实冻结单元上核对生产与独立读取的一致性，没有新增科学重复。当前汇总输入为 `results/jci-target-budget-curve-20261102-parallel-aggregation-inputs.tar.gz`，摘要 `850804ed88b2a5423841ccad508300a94c63f684f1581e0875ca4624df0a936a`；其中共同科学配置与首次固定的摘要相同。生产汇总程序摘要为 `c2173e36a00fe58bec02f1877d785ea0d37971bdc28ed0da2b978600267108d7`。

## 同预算方差结果

表中通过数量为JCI相对七项直接方法与三项结构对照的十项比较。通过要求为至少5%平均方差减少、213项Bonferroni校正双侧区间下界大于零、两个批次差值均为正。方差减少范围包含全部十项，不删除未通过项。

| 目标结果合计 | 下游末端机制 | 目标新增属性机制 | 上游机制 |
| ---: | --- | --- | --- |
| 64 | 10／10；11.60%—17.43% | 6／10；4.88%—8.21% | 0／10；−10.77%—1.71% |
| 128 | 10／10；14.04%—21.73% | 8／10；7.40%—11.27% | 0／10；−13.20%—1.81% |
| 256 | 10／10；9.97%—17.05% | 9／10；5.58%—8.31% | 0／10；−15.10%—2.21% |

预定主要判定 `.low_budget_variance_gain=true`。最低预算下，JCI相对完整逻辑回归减少16.60%、稀疏逻辑回归减少11.60%、单变量筛选减少13.90%、提升树减少17.43%、PCA减少17.11%；相对同骨架几何、打乱建议及传播骨架分别减少15.56%、16.04%、15.64%。均匀惩罚和直接上下文分别减少16.60%、16.73%。这些比较使用相同属性、观测、来源交叉验证及目标校准预算，支持该模拟机制中的方向建议具有独立估计价值。

上游机制全部预算均未达到门槛，部分对照显示损害。目标新增属性机制也没有在任一预算取得全部十项通过。结果依赖结果信息集中于可识别的下游末端这一条件，不能据此声明方向筛选对全部机制均有帮助。

## 目标数据减半结果

预定主要判定 `.half_target_budget_gain=false`。下游末端机制中，JCI使用64项目标结果、对照使用128项时，十项比较全部未通过，方差相对增加65.44%—81.71%。次一级比较中，JCI使用128项、对照使用256项，也全部未通过，相对增加64.88%—78.95%。其他机制的跨预算比较均未通过；全部60项跨预算记录保持原值。

本轮支持相同预算下的条件性方差改善，没有支持减少一半目标数据。结果指标是经随机校正的效应估计方差，不是提示选择的实际策略价值。完整来源、输入、数值输出、原生图及独立核对均保留；该模拟不认证自然任务因果方向、TSG准确率、代码安全或完整功能性。`.formal_claim_allowed=false`、`.tsg_gain_established=false`，Goal保持未完成。

## 冻结资料与复算

完整原始结果为 `results/jci-target-budget-curve-20261102-verified-results.tar.gz`，992589127字节，SHA256为 `d77eaf79a8b86be8d14940c6a22798aaa86822703add2a78129f04b34e1fee24`，本地与服务器摘要一致。归档保留全部288个原始单元、各预算保存的执行源码、数值核对、原生重放及整组比较。实际运行输入与汇总输入分别使用本页记录的runtime-inputs和parallel-aggregation-inputs归档；复算需要共同保留这三份资料。

可直接阅读的本地完整汇总与核对位于 `data/method/jci-target-budget-curve-20261102/curve-study`。它从完整原始归档解压取得；其 `curve/result.json`摘要与已独立核对结果一致。表格读取该文件的 `same_budget_comparisons`，选择tested=jci，按target_size及scenario分组，计数supported并计算全部relative_reduction的最小值与最大值。跨预算表述读取 `cross_budget_comparisons`的原值。生产函数为 `src/discovery/controlled_transport.py:attribute_budget_curve`，独立核对为 `data/method/jci-target-budget-curve-20261102/verify.py:main`。

在项目内新目录解压runtime-inputs及parallel-aggregation-inputs，在另一个新目录解压完整结果。进入汇总输入目录，设置PYTHONPATH为运行输入目录、单线程数值依赖及项目内临时目录，使用已记录Python与依赖执行：

```text
python data/method/jci-target-budget-curve-20261102/verify.py NEW_RESULTS/jci-target-budget-curve-20261102-runtime --workers 8
```

重放派生核对时应保留解压副本中的 `curve-verification`原件，并在另一份副本中输出，冻结原件不修改。全部原始单元的数值重拟合及原生R重放使用运行输入中的 `attribute_verify.py`，逐个预算执行，环境与R库位置由 `run.sh`说明。无需重新生成科学数据。

配对t区间具有相应近似条件；213项校正仅覆盖本轮预定家族，不为全部自适应开发历史提供整体错误率保证。131072项共同协变量积分及其独立重建误差用于数值精度诊断，不代替新来源学习重复。此前执行与终止材料继续保存在各自归档中，不作为新增样本。
