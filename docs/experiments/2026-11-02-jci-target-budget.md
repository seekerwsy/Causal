# JCI 目标数据预算核对与代表执行

## 已冻结数据的实际数量

`audit.py`读取已冻结九十六项模拟单元，先核对父归档 SHA256 `31474c69bbdb03982d50531d3d47f08374cf747e59d608e3f3b0405249fa049f`，再逐角色读取实际属性、随机分配及结果数组。每个单元包含以下数量：

| 数据角色 | 属性记录 | 已分配结果 |
| --- | ---: | ---: |
| 辅助结构发现 | 512 | 0 |
| 来源预测模型 | 128 | 128 |
| 目标偏差拟合 | 32 | 32 |
| 独立目标校准 | 32 | 32 |
| 最终随机效应估计 | 64 | 64 |

每个单元合计128项目标结果、256项来源与目标结果。每条结果仅对应实际随机分配的一臂，不能再按两个潜在处理结果乘以二。配置中的 `target_size=32`用于拟合与校准各自的数量，最终估计使用其两倍。既有同预算的方差收益保持原结果；样本效率需要按照完整目标预算定义比较。

`budget-audit.json`状态为 `VERIFIED_ACTUAL_FROZEN_SIMULATION_BUDGET`，结果摘要为 `4a03cfc7eaee06a5819b8b7ff780ce51d0705a77391b7cf834978bf880688f22`。本次计数不增加科学重复，不重新计算效应收益，不建立样本效率增量。

## 当前核对器与原始参考

现有独立核对器根据配置读取来源、拟合、校准和最终估计数量；目标修正矩阵、效应标准误差、积分方差与积分误差均依据实际角色数组长度计算。分配、目标校准及推断的独立规则保持原方法。

原始冻结参考 `downstream_signal-b0-r00` 已通过当前核对器完整单元核验：重建17516项条件查询、2268项逻辑回归交叉验证路径，并独立重拟合177项模型；所有原始风险与当前核对一致。最大KKT残差为 `2.633024197423728e-6`。该检查使用已暴露原始数据，不创建新科学重复。

## 在新结果前指定的小预算代表检查

配置 `configs/jci-target-budget-canary.json`保持原代表检查的来源数据、随机种子、辅助512项、来源128项、64个属性、所有强直接及结构对照、有限惩罚、积分精度和方向保护规则。目标拟合改为16项，独立校准16项，最终效应估计32项，目标总结果64项。通过现有 `attribute_run.py --limit-cells 1`执行完整生成、发现、来源拟合、目标修正及汇总，再使用当前独立核对器及原生R图重放核验。

只执行第一个已暴露来源坐标的下游单元。它检查实际小预算计算与核对路径，不评价总体收益，也不检验节省一半预算是否成立。任何方法失败都保留并停止扩大；不追加种子、替换比较方法或调整门槛。

后续完整预算曲线必须单独指定新目标数据随机种子、共同源学习重复、角色数量、配对关系及整个比较家族，并在新结果之前固定。当前单元的所有统计比较保持部分执行身份，不能作为新收益证据；真实任务、安全代码、完整功能性与TSG收益均有各自的独立证据要求。默认方法及正式协议状态不变。

## 已完成的小预算执行

固定单元已完成并通过独立核对，实际数量为辅助512项、来源128项、目标拟合16项、校准16项、最终估计32项。目标结果合计64项，来源与目标结果合计192项。结构发现与独立重建分别包含25219项条件查询，核对2268项逻辑回归交叉验证路径并独立重拟合177个模型；最大KKT残差为 `2.7432431854990114e-6`。原生R重放一张图并逐项一致，最终状态为 `VERIFIED`。

汇总严格保留 `cells=1`、`partial=true`、17项实际比较及零项可靠增量；所有增量门槛因部分执行保持未通过。这个状态表达实现检查范围，不判定小预算下存在或不存在总体收益。

输入配置摘要为 `ec7a5671147b1d9196034b3be3a17350bb962124fca402c765ade1900f34289a`，当前核对器为 `190e288296b8fea823f0f6255bcf2cd68454a5e2ca33d405c426d8cd99f8c321`，传输源码包为 `4eb35922439e833485873129ac7829d5dabd4e2016f279dea0d732a6268847ed`。Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0，R 4.1.2及pcalg 2.7.12；实际版本保存在执行包中。

源码部署在 `/home/wsy/work/prompt-mechanism-study/inputs/jci-target-budget-canary-20261102`，已核对结果在同项目 `results/jci-target-budget-canary-20261102-complete`。归档保留一次依赖加载阶段的终止记录及同一固定配置的完整执行，未替换任务、种子或方法。依赖来自既有 `inputs/jci-framework/.codex-runtime/r-lib` 与 `r-deps/usr/lib/R/site-library`，不安装新服务，不使用模型调用或受保护数据。

本地完整执行包为 `results/jci-target-budget-canary-20261102-server-frozen.tar.gz`，SHA256为 `f96c5a7e482cc7d3ae82d0fca8afe61592b6298f3079b9f23fc1c72dc7fb6555`，与服务器冻结包一致。本地独立读取其中的完整结果目录，再次核对实际角色数量、部分执行身份、零可靠增量及一张原生图重放。执行及重放使用包内源码；旧研究继续使用各自冻结源码复现。

## 复现入口与结果映射

在服务器部署输入目录中设置 `PYTHONPATH=.`、`OMP_NUM_THREADS=1`、`OPENBLAS_NUM_THREADS=1`、`MKL_NUM_THREADS=1`，并令 `R_LIBS`包含上述两个既有R依赖目录。令 `PYTHON`指向项目既有Python环境、`OUTPUT`指向新的结果目录，执行：

```bash
"$PYTHON" data/method/jci-highdim-oracle-20261101/attribute_run.py "$OUTPUT" \
  --plan configs/jci-target-budget-canary.json --workers 1 \
  --rscript /usr/bin/Rscript --limit-cells 1
"$PYTHON" data/method/jci-highdim-oracle-20261101/attribute_verify.py "$OUTPUT" \
  --workers 1 --rscript /usr/bin/Rscript
```

实际预算来自每个 `cells/*/result.json.data`数组长度。部分执行及比较身份来自 `summary/result.json`，数值核对、模型重拟合及原生图重放来自 `verification/result.json`与 `native-r-replay.json`。本地 `canary-summary.json`及 `canary-verification.json`为这两份执行结果的原始副本。全部计数、原始参考检查与小预算材料另存于 `results/jci-target-budget-20261102-frozen.tar.gz`，同名 `.sha256`文件保存归档身份。
