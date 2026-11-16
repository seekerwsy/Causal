# 独立目标收缩的机制实验结果

## 冻结设计与实际执行

按 [预定配置](2026-11-01-prognostic-correction-repair-design.md) 完成六种机制、两个预算、两个批次各两次重复，共 48 次运行、192 项假设。实际随机种子为 2026110121、2026110122。全部 51 项默认科学检查通过；四次命令行复现独立核对 816 个模型和 2,840 项条件检验；完整实验独立核对 16,320 个模型和 34,073 项条件检验，状态为 `VERIFIED`。

本轮将来源结构建议与目标修正惩罚分开：结构仅收缩共享项；全部方法共同获得 1、10、100、1000、1000000 的目标惩罚网格。来源基础惩罚选择、目标校准、排序与双侧确认保留。证据为 `NON_CLAIM_PROGNOSTIC_STRUCTURE_LEARNING`，代码生成模型调用为零。

## 全部条件

正百分比表示相对所列对照的效应方差下降。目标预算包含拟合、独立校准与独立排序。每个条件四次重复，每项假设总数为十六。

| 机制 | 目标预算 | JCI 对直接方法 | JCI 对直接不变性 | 真实结构对直接方法 | JCI 使用非零结构强度 |
| --- | ---: | ---: | ---: | ---: | ---: |
| stable_signal | 64 | 0.21% | 0.06% | 0.22% | 13/16 |
| stable_signal | 128 | 0.92% | 0.12% | 1.03% | 10/16 |
| proxy_shift | 64 | 0.45% | 0.04% | 0.55% | 10/16 |
| proxy_shift | 128 | 2.17% | 0.01% | 2.27% | 13/16 |
| background_shift | 64 | 1.19% | 0.09% | 1.19% | 12/16 |
| background_shift | 128 | 0.76% | 0.22% | 0.74% | 13/16 |
| weak_context | 64 | 0.68% | 0.05% | 0.65% | 12/16 |
| weak_context | 128 | 0.32% | -1.02% | 0.38% | 8/16 |
| cancellation | 64 | 0.47% | -0.16% | 0.76% | 6/16 |
| cancellation | 128 | 1.17% | -0.02% | 1.41% | 13/16 |
| missing_attribute | 64 | 0.44% | -0.06% | 0.50% | 9/16 |
| missing_attribute | 128 | 0.20% | -0.21% | 0.43% | 11/16 |

十二个条件相对直接方法的点估计均改善，范围为 0.20% 至 2.17%。相对直接不变性的范围为 −1.02% 至 +0.22%。全部 24 项校正近似区间包含零，均未达到 5% 实用门槛、正区间下界和两个批次均改善的预定联合条件。四次重复仅支持低功效开发诊断。

JCI 有 130／192 项选择非零结构强度，47／48 次运行与直接方法提名相同。每种方法共提名 96 个确认位置：JCI、直接方法、真实结构各确认 73 个，均为正向 49 个、负向 24 个；直接不变性、骨架和打乱建议各确认 72 个，均为正向 49 个、负向 23 个。这些确认差异属于描述性输出。

## 科学解释

上一轮冻结模型的精确投影诊断发现：固定已拟合共享系数并移除目标偏差后，直接方法在全部 192 项假设中降低方差，各条件平均降低 17.65% 至 24.74%。同一目标惩罚 10 下，原耦合规则的 JCI 强度 2、8 使平均方差增加约 3.86% 至 11.48%。这是事后、无新拟合的模型分解，不是可部署消费者的独立评价。完整诊断和恒等式检查保存在 `data/method/jci-prognostic-mechanism-audit-20261101`。

新规则下，独立校准能够更多使用结构建议，也能够选择充分收缩的目标修正。新旧实验使用不同种子，不能将两个表格直接配对推断。这里得到的是与目标修正问题相一致的开发证据，不能把共同网格修复带来的收益全部归因于 JCI。

本轮可观测最优预测器的剩余方差改善空间为 5.04% 至 11.86%；本轮已拟合目录的真值最优改善空间为 2.05% 至 6.15%。候选质量和校准选择仍限制收益。真实结构实际改善为约 0.22% 至 2.27%，与估计结构接近，表明继续提高来源图形恢复率未必能产生主要增量。

主要未解决问题是：当前消费者所需的来源条件分离信息，也可以通过直接条件检验取得。直接不变性方法在本轮取得了接近的收益。需要检查图形是否提供直接检验没有有效利用的有限样本信息，以及这种信息是否真正改变学习；当前证据尚不支持 JCI 的独立收益。

TSG 另有 [独立上下文开发比较](2026-11-01-tsg-blind-development-results.md)。冻结模拟记录保持运行时的 Graph 资格状态；新增自动化参考与四项测量不被追认为这些模拟的真实表示证据。

## 复现与定位

原始结果位于 `/home/wsy/work/prompt-mechanism-study/results/jci-prognostic-correction-repair-20261101`，本地紧凑证据位于 `data/method/jci-prognostic-correction-repair-20261101`。沿用已有 Python 3.12.13 环境、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、NetworkX 3.7、R 4.1.2 与 pcalg 2.7.12。设置 `OPENBLAS_NUM_THREADS=1`、`OMP_NUM_THREADS=1`，R 路径为 `/usr/bin/Rscript`。

- 冻结配置 SHA256：`4d20b8c0f5f03a7fc79c3053ae93d9dc09092eddcb86d486e5468ce5ae9fb976`。
- 执行源码 SHA256：`d342a10ff1d4a41b91bcad9e02cbbd69e9d4a1a53162669bf98367b1a8b5c989`。
- 独立验证器 SHA256：`8a9095ad36b1347c9b7685f538c62585fa298cf5f7327d00c55798ba1339fdeb`。

```text
python -m pytest -q --rscript=/usr/bin/Rscript
python -m prompt_mechanism_study study jci-directional-validation results/NEW_REPAIR --plan configs/jci-prognostic-correction-repair.json --rscript /usr/bin/Rscript --workers 8
python -m prompt_mechanism_study study verify-jci-directional-validation results/NEW_REPAIR --workers 8
python data/method/jci-prognostic-learning-20261101/build-report.py results/NEW_REPAIR results/NEW_REPORT
```

`prognostic_learning.fit` 负责独立目标惩罚，`learn` 保存模型与校准选择，`risks` 保存逐模型精确方差与可观测界限。`run_prognostic_validation` 写入全部 `summary.rows[].comparisons`；`verify_prognostic` 独立重算随机数据、查询、系数、校准、效应、确认及汇总。共同表格脚本只汇总已验证冻结数据，输出 `comparisons.csv`、`comparisons.md` 和 `derived.json`。旧研究必须使用各自归档源码及匹配验证器复现。
