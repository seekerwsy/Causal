# JCI 参与平均结果学习的开发结果

## 执行与验证

按用户授权完成 [预先固定的设计](2026-11-01-prognostic-learning-design.md)：六种机制、两个目标预算、两个独立批次各两次重复，共 48 次运行、192 项假设。51 项默认科学检查全部通过。默认命令复现四次运行，独立核对 544 个模型和 2,835 项条件检验；完整实验独立核对 6,528 个模型和 33,723 项条件检验，状态均为 `VERIFIED`。

本轮证据身份为 `NON_CLAIM_PROGNOSTIC_STRUCTURE_LEARNING`。模型服务调用为零，没有使用新的受保护任务，也没有激活正式协议。每个条件只有四次完整学习重复，统计区间属于近似、低功效的开发诊断。

## 已实施的科学改动

- 直接学习平均结果函数 g，预测基不包含处理 A；目标效应分数使用 `2*(2*A-1)*(Y-g)`。
- JCI 支持集合对三阶交互项形成有限惩罚，结构信息进入实际拟合系数。共享项惩罚乘以 `1+strength*(1-support)`，目标修正项惩罚除以同一系数。
- 来源三折交叉验证使用共同直接模型选择基础惩罚；独立目标校准在两种修正惩罚与三种结构强度中选择。全部结构方法保留零强度。
- 同时运行直接、直接条件不变性、JCI、骨架、打乱建议、真实结构及仅目标数据方法。真实结构仅用于隔离诊断。
- 新机制提供更强平均结果信号，并包含代理关系变化、目标背景风险变化、弱上下文、效应抵消和属性缺失。

## 完整比较

正百分比表示方差降低，负百分比表示方差增加。目标预算为拟合、校准与排序任务数量之和。真实结构列使用相同学习过程和校准数据。表内接近零的浮点差异按两位小数显示。

| 机制 | 目标预算 | JCI 对直接方法 | JCI 对直接不变性 | 真实结构对直接方法 | JCI 使用非零结构强度 |
| --- | ---: | ---: | ---: | ---: | ---: |
| stable_signal | 64 | -1.24% | 0.18% | -1.23% | 4/16 |
| stable_signal | 128 | 0.00% | 0.00% | -0.00% | 0/16 |
| proxy_shift | 64 | -0.38% | 1.09% | -0.79% | 1/16 |
| proxy_shift | 128 | 0.00% | 0.00% | 0.00% | 0/16 |
| background_shift | 64 | -0.14% | 0.28% | -0.00% | 1/16 |
| background_shift | 128 | 0.00% | 0.00% | 0.00% | 0/16 |
| weak_context | 64 | -0.26% | 0.20% | -1.26% | 1/16 |
| weak_context | 128 | -0.17% | -0.02% | -0.13% | 1/16 |
| cancellation | 64 | -0.60% | -0.45% | -0.46% | 2/16 |
| cancellation | 128 | -0.36% | 0.04% | -0.38% | 1/16 |
| missing_attribute | 64 | -0.41% | 0.01% | -0.49% | 1/16 |
| missing_attribute | 128 | -0.49% | 0.01% | -0.29% | 1/16 |

十二个机制与预算条件、两个主要对照共 24 项比较，全部校正区间包含零，均未达到预定 5% 精度门槛。完整区间与两个批次的差值保存在 `summary/result.json` 和 `comparisons.csv`，没有按点估计选择报告条件。

各方法共提名 96 个确认位置。JCI 确认 64 个，其中正向 41 个、负向 23 个；直接方法确认 65 个，其中正向 42 个、负向 23 个；直接不变性、真实结构和骨架方法各确认 64 个；打乱建议确认 63 个；仅目标方法确认 65 个。所有方法在本轮声明模型中均没有错误确认，确认数量差异仅作描述性诊断。

## 收益为什么没有形成

**平均结果信号已经提供更大的潜在改善空间。** 相对当前直接方法，可观测最优预测器的方差改善空间为 22.58% 至 28.96%。这一界限积分掉不可见 U，以及属性缺失机制中的 X，未使用实际方法不可观测的完整状态。

**实际拟合候选没有利用这部分空间。** 在本轮已拟合的全部方法候选中，即使使用真值选择最佳模型，相对直接方法的平均改善也只有约零至 0.51%。因此，当前学习与惩罚配置生成的候选质量构成主要限制。更大的可观测信号没有自动转化为更好的拟合结果。

**结构建议大部分未被校准采用。** 192 项假设中，JCI 只有 13 项选择非零结构强度，179 项选择零强度；47／48 次运行与直接方法提名相同。384 张图中有 380 张可评价，四张支持不足。不能把零收益解释为没有实际运行结构发现。

**支持集合到目标修正惩罚的映射缺少足够依据。** 当前支持比例描述变量集合是否得到来源分离查询支持，并不直接测量某个变量在目标环境中的机制变化。实现将低支持同时映射为更强的共享收缩与更弱的目标修正惩罚。目标拟合只有 16 或 32 项任务，完整三阶修正包含 64 个基项；属性缺失时为 42 个。JCI 有 188／192 项选择修正惩罚网格的最大值 10，直接方法有 190／192 项选择该最大值。这与目标修正需要更强收缩的解释一致，但当前实验没有单独改变两部分惩罚，不能据此确认各部分的独立因果贡献。

真实结构在相同映射下的改善为约零至 −1.26%，也没有产生正向收益。当前结果不支持这项具体的结构惩罚映射，不能解释为 JCI 的一般能力上限。与旧研究的概率机制、消费者和预算不同，不能用跨研究数值差异声称方法性能提高。

Graph 的完整要求绑定、独立属性测量、真实上下文资格与功能性保留仍缺少独立证据，状态为 `BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS`。LLM 版本扩充方案已写入设计，但本轮没有执行真实模型生成或独立语义评审。

## 复现与证据身份

本研究使用其保存的源码与匹配验证器复现。当前活动入口已经采用独立目标修正惩罚，不能用当前规则重新解释这些冻结结果。

服务器执行根目录为 `/home/wsy/work/prompt-mechanism-study/inputs/jci-framework`，环境为其中的 `.codex-runtime/directional-correction-venv`。使用 Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、NetworkX 3.7、R 4.1.2 与 pcalg 2.7.12。设置 `OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`，R 库沿用该目录的 `.codex-runtime/r-lib` 与 `.codex-runtime/r-deps/usr/lib/R/site-library`，临时文件保存在 `.codex-runtime/directional-correction-tmp`。

完整原始结果位于 `/home/wsy/work/prompt-mechanism-study/results/jci-prognostic-learning-20261101`。本地紧凑证据为 `data/method/jci-prognostic-learning-20261101`，源码归档为 `results/jci-prognostic-learning-20261101-source.zip`。

- 原配置 SHA256：`30cd9639192db6187f61c851ba77eac27a1438a1376c15f08f37df16e061dd94`。
- 执行源码 SHA256：`20000084f94e3edb96e2ff72e324d4a42c70be094f6f986139516e608d86a954`。
- 独立验证器 SHA256：`b736cb9c56712d500bc6015c2e6e316edd85de256253d7994f34d9960eb5de85`。

```text
python -m pytest -q --rscript=/usr/bin/Rscript
python -m prompt_mechanism_study study smoke results/NEW_SMOKE --rscript /usr/bin/Rscript --workers 4
python -m prompt_mechanism_study study verify-jci-directional-validation results/NEW_SMOKE --workers 4
python -m prompt_mechanism_study study jci-directional-validation results/NEW_FULL --plan configs/jci-prognostic-learning.json --rscript /usr/bin/Rscript --workers 8
python -m prompt_mechanism_study study verify-jci-directional-validation results/NEW_FULL --workers 8
python data/method/jci-prognostic-learning-20261101/build-report.py results/NEW_FULL results/NEW_REPORT
```

| 科学输出 | 实现函数 | 冻结字段与表格 |
| --- | --- | --- |
| 结构参与模型学习 | `prognostic_learning.proposals`、`support`、`fit`、`learn` | `hypotheses[].learned` 的建议、系数、实际惩罚及选择 |
| 目标效应精度 | `prognostic_learning.risks`、`run_prognostic_validation` | `risks.catalog`、`risks.groups`、`summary.rows[].comparisons` |
| 可观测与候选改善空间 | `risks`；仅隔离诊断 | `risks.observable_optimum`、全部候选方差；`derived.json` |
| 正负确认 | `_prognostic_cell` | `confirmation`、`nominations`、`decisions` |
| 独立验证 | `verification.prognostic_learning.verify_cell`、`verify_prognostic` | `verification/result.json` 与原 manifest |
| 表格与选择诊断 | `data/method/jci-prognostic-learning-20261101/build-report.py` | `comparisons.csv`、`comparisons.md`、`derived.json` |
