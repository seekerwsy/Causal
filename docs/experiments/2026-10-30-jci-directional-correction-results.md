# 完整目标修正与双向 Atomic 确认验证

研究身份为 `NON_CLAIM_DIRECTIONAL_TRANSFER_SIMULATION`。本次修改遵循 Graph 与 JCI
主线：Graph 定义处理前属性，JCI 方向提出共享变量建议，完整目标属性修正共享误差，
独立目标校准选择预测模型，随机分配修正估计 Atomic 效应，独立数据确认正向或负向效果。
本研究执行声明的概率机制，不包含新的代码模型调用。

## 冻结设计

配置为 `configs/jci-directional-validation.json`，研究编号
`jci-directional-correction-20261030`，随机批次为 2026103021 和 2026103022。
六种机制各执行两个批次、每批八次重复，总计 96 次。机制方程、四项候选、两项提名、
来源 1,024、目标拟合 32、目标校准 32 和目标排序 128 项任务保持原定定义。

共享属性建议分别来自确定祖先和可能祖先。每项建议与完整目标修正组合，使用相同的
共享惩罚 0.1、1、10，以及目标修正惩罚 1、10、100。主方法、邻接消融、直接条件
不变性和直接子集搜索均保留十五个完整属性共同候选。校准最小化目标结果相对两臂
平均预测的平方误差；排序按修正效应绝对值提名两项假设，相同值按固定编号选择。

确认使用同时双侧 Hoeffding 区间。下限超过 0.04 或上限低于 -0.04 时记录确认及方向。
每项确认预算设为 32,768 个配对任务，全部方法使用同样预算。这个预算在生成新结果
前由精确概率计算确定：原 8,192 项预算对五种机制中的有效负效应只有 5%—8.3%
检出概率；新预算提供 92.6%—97.8%，满足至少 80% 的预定要求。

预算变化意味着不能把与此前正向确认数量的差异全部归因于方法修改。方法比较使用
本次同一任务、同一确认结果和同一预算。JCI 精确方差与此前研究的计算使用相同来源
及目标学习预算，但随机批次和模型目录改变，跨次结果只作开发诊断。

主要比较对象为同图邻接消融、直接条件不变性和完整属性环境偏差模型。精确方差降低
与确认数量增加共同形成六种机制乘三个比较方法乘两个指标的 36 项比较族。
报告 Bonferroni 分配下的近似配对 t 区间，以及两个随机批次各自的变化方向。
这些区间保留开发研究身份，不作为正式研究证据。

## 六种机制的执行结果

下表的相对降低为 `1 - variance_directional / variance_comparator`。正值表示 JCI
方差较低，负值表示较高。每个均值使用该机制的十六次独立学习重复及四项候选。

| 机制 | JCI 精确方差 | 相对邻接消融 | 相对直接不变性 | 相对完整环境偏差 | 相对直接子集搜索 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 代理关系改变 | 0.008063052 | +3.36% | -0.75% | +5.44% | -0.54% |
| 代理关系稳定 | 0.007719661 | -0.22% | +0.01% | +1.79% | +0.07% |
| 弱上下文 | 0.008043709 | +2.49% | -0.80% | +5.49% | -1.19% |
| 来源上下文直接影响结果 | 0.008167561 | +1.72% | -1.16% | +3.31% | -1.23% |
| 目标结果机制改变 | 0.007893184 | +1.89% | -0.01% | +3.28% | +0.12% |
| 代理属性具有因果作用 | 0.008221753 | +2.64% | -2.47% | +5.04% | -2.04% |

在预定的 36 项开发比较族中，相对邻接消融的方差降低区间在弱上下文、来源上下文
直接影响结果和目标结果机制改变三种条件下具有正下限，相对完整环境偏差方法在
五种条件下具有正下限。相对直接不变性方法的六个区间均包含零。直接子集搜索保留
描述性参照身份，没有追加到已冻结的主要比较族。

每次提名两项假设，下面是平均确认数量：

| 机制 | JCI | 邻接消融 | 直接不变性 | 完整环境偏差 | 直接子集搜索 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 代理关系改变 | 1.7500 | 1.8125 | 1.6875 | 1.6875 | 1.6875 |
| 代理关系稳定 | 1.7500 | 1.7500 | 1.7500 | 1.8125 | 1.6875 |
| 弱上下文 | 1.8125 | 1.7500 | 1.8125 | 1.7500 | 1.8750 |
| 来源上下文直接影响结果 | 1.5625 | 1.6250 | 1.5625 | 1.6250 | 1.5625 |
| 目标结果机制改变 | 2.0000 | 2.0000 | 2.0000 | 2.0000 | 2.0000 |
| 代理属性具有因果作用 | 1.9375 | 1.7500 | 1.8750 | 1.7500 | 1.9375 |

全部十八个确认数量比较区间都包含零。JCI 的 192 个提名位置实际确认 173 项，包含
141 项正效应和 32 项负效应，没有观察到错误确认。其余十九个位置提名了真实效应
绝对值未超过 0.04 的候选；本次所有提名中真正超过门槛的效应均得到确认。真实最优
提名诊断确认 192 项。上述数量是本次模拟的描述性结果，不能推出真实数据中的检出率
或错误率。

在 384 项候选拟合中，JCI 有 192 次选择结构建议的共享子集加完整目标修正，其余
192 次选择各方法共有的完整属性候选。结构建议已经实际参与选择；最终确认增益
仍然没有通过预定比较。当前证据支持特定条件下相对邻接消融的精度改善，尚未建立
相对强直接方法的独立收益。

338/384 次结构搜索返回可评价图形，46 次因条件检验支持不足保留未知结构，并使用
预定共同候选。全部 384 次仍进入结果分母。这说明随机分配提供的设计支持与具体
有限样本条件检验的支持必须分别核查。

## 冻结模型的信息损失

信息诊断及其独立验证均已完成，覆盖全部 96 次运行和 61,056 个共同预算拟合模型。
诊断使用已冻结的 159 个共同预算模型，分别计算所选模型、JCI 候选集合内最优模型
和完整有限目录内最优模型的精确方差。总体最优选择只用于解释结果，不进入学习、
校准或提名。

| 机制 | 校准选择损失 | 候选集合限制损失 | 选择损失占两项损失之和 |
| --- | ---: | ---: | ---: |
| 代理关系改变 | 0.000313563 | 0.000073838 | 80.9% |
| 代理关系稳定 | 0.000146138 | 0.000015736 | 90.3% |
| 弱上下文 | 0.000301702 | 0.000033930 | 89.9% |
| 来源上下文直接影响结果 | 0.000338600 | 0.000107202 | 76.0% |
| 目标结果机制改变 | 0.000279116 | 0.000063441 | 81.5% |
| 代理属性具有因果作用 | 0.000345972 | 0.000142024 | 70.9% |

占比按各机制的平均选择损失除以两项平均损失之和计算。本次目录内的主要损失发生在
32 项目标校准任务选择模型的环节。校准目标与效应方差已经一致，有限校准数据仍然
不能准确区分这些候选。该诊断不说明增加校准预算必然提高最终确认数量。

真实祖先集合也没有普遍提供更好的共享建议。在代理属性具有因果作用的条件下，
真实祖先建议的候选集合最小方差为 0.008033240，直接不变性集合为 0.007735693，
完整目录为 0.007733757。该机制中 N 的因果作用与其潜在共同原因的代理作用同时
存在，跨环境的条件预测关系仍可改变。这个结果进一步说明祖先身份不能认证可共享性，
图形发现误差也不能解释全部差距。

表格读取 `information-summary.json` 的 `methods.directional.selection_loss` 和
`restriction_loss`；真实结构比较读取各方法的 `pool_oracle_variance`。
实现函数为 `directional_transfer.py::catalog_risks`、`information_losses` 和
`context_validation.py::diagnose_information`，独立重算函数为
`verification/directional_transfer.py::verify_information`。

## 复现范围

完整执行和独立验证均已完成：96 次运行、62,208 个拟合模型和 36,799 次条件检验。
在新建的 Python 3.12.13 环境中，34 项默认检查全部通过。默认复现独立验证四次运行、
2,592 个拟合模型和 1,645 次条件检验。NumPy 为 2.5.1、SciPy 为 1.18.0、
scikit-learn 为 1.9.0、NetworkX 为 3.7。R 为 4.1.2、pcalg 为 2.7.12、jsonlite 为
1.7.3。全部学习方法使用同一实际 R/pcalg 后端。

执行位置为 `/home/wsy/work/prompt-mechanism-study/inputs/jci-framework`，环境为
`.codex-runtime/directional-correction-venv`。完整结果位于
`/home/wsy/work/prompt-mechanism-study/results/jci-directional-correction-20261030`，
默认复现位于同一 results 目录的 `jci-directional-correction-smoke-20261030`。
临时目录设置为项目内的 `.codex-runtime/directional-correction-tmp`，
`OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`，R 库路径为
`.codex-runtime/r-lib:.codex-runtime/r-deps/usr/lib/R/site-library`。

执行源码归档 SHA256 为
`751a549cdec815dea098e606c789ff9b4d3f5e1523a913530840fa3f131bb611`；
独立验证器 SHA256 为
`6f5118d755ed760085f0bea0a65764c7004b7513463fcf6be762c1f348d33072`。
本地归档为 `results/jci-directional-correction-20261030-source.zip`。
紧凑结果位于 `data/method/jci-directional-correction-20261030`，包含冻结配置、执行身份、
完整汇总、精确机制与检出概率、验证结果和测试记录。
信息诊断保存在服务器同一 results 目录下的
`jci-directional-correction-information-20261030`，对应的汇总、执行身份和验证结果
分别保存为紧凑结果目录中的 `information-summary.json`、`information-identity.json`
和 `information-verification.json`。

两张结果表直接使用 `summary.json` 中各机制的 `methods.*.mean_exact_effect_variance`
与 `methods.*.mean_confirmed_count`；比较区间来自 `comparisons`。汇总函数为
`src/experiment/context_validation.py::run_directional_validation`，方差计算函数为
`src/discovery/directional_transfer.py::exact_risk`。比例列使用前述明确公式，
确认数量、符号和错误确认由同一汇总函数统计，并由独立验证器逐项重算。
结构建议被选择的次数，按每个冻结 cell 的
`hypotheses[*].learned.choices.directional` 是否属于 `groups.direct_deviation` 统计；
该集合正是十五个共同候选。结构搜索的可评价数量取汇总中的 `evaluated_graphs`。

当前实现包含独立数值验证器，逐项检查随机观测、角色隔离、条件检验、完整目标修正
的唯一拟合解、校准目标、效应分数、精确方差、绝对值提名、双向确认和全部汇总。
冻结模型的信息诊断独立计算候选集合限制和校准选择带来的方差损失。

```text
python -m pytest -q --rscript=/usr/bin/Rscript
python -m prompt_mechanism_study study smoke OUTPUT_SMOKE --rscript /usr/bin/Rscript
python -m prompt_mechanism_study study verify-jci-directional-validation OUTPUT_SMOKE
python -m prompt_mechanism_study study jci-directional-validation OUTPUT --plan configs/jci-directional-validation.json --rscript /usr/bin/Rscript
python -m prompt_mechanism_study study verify-jci-directional-validation OUTPUT
python -m prompt_mechanism_study study diagnose-jci-information OUTPUT OUTPUT_AUDIT
python -m prompt_mechanism_study study verify-jci-information OUTPUT_AUDIT
```

Graph 自动表示准确性、实际编辑上下文的因果信息、自然任务的安全与功能结果仍需
各自的证据。已准备的四个原始任务及三十二份提示保留原身份，文字语义审查不提供
上述实证结论。
