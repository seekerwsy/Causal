# 修复生成结果的事后选择器比较

本分析使用已经查看过结果的开发材料，属于事后探索。分析执行前固定以下计算规则；这项固定不构成结果前预注册，也不产生新的独立评价任务。原始准备、代码、测量与结果保持冻结。

## 输入与独立单位

- 输入为 `targeted-generation-preparation` 的 candidates、bindings、tasks、assignments，以及 `targeted-generation-analysis` 的 effects、outcomes。
- 仅使用生成前质量判定合格的 19 个候选提名；按 binding.policy_id 去重为 18 项完整政策，覆盖 10 个任务。重复提名选 candidate_id 字典序最小的代表，保留全部别名。
- 同任务的多政策、相同提示版本和 seed 重复均不增加独立任务数。每个任务在训练损失及汇总效用中权重相同。
- 主目标沿用冻结结果的 oracle-evaluable secure-code yield，未知与生成失败保留在分母；敏感性范围沿用冻结 sensitivity。范围表示未知结局界限，不表示抽样置信区间。

## 特征、训练与选择

每次外层留下一个完整任务，其余九个任务训练。调用现有 `fit_discovery_ridge`，在九个训练任务内部留一选择 alpha，候选值为 0.1、1、10、100；并列时取较大 alpha。所有文本词表均在对应训练折拟合。使用 `common` 模式，canonical_text 为原始参考提示与完整合同的规范 JSON；P/N 文本沿用冻结政策，orientation 固定 +1，marginals 与 relations 为空。Raw 候选不补造图结构。

比较规则如下：

1. effect-ridge：学习 P−N，选择预测绝对效果最大的候选，方向取预测符号，零值方向为 +1。
2. contract-shrinkage：完整合同规范 JSON 的 SHA256 为合同身份，复用 `discovery_contract_statistics` 的收缩公式；新合同使用训练任务等权总体效果。选择绝对预测最大者及其符号。
3. global-effect-mean：所有候选获得训练任务等权总体效果，按该效果符号选择方向。
4. first-fixed：选择 candidate_id 字典序第一项，方向固定 +1。
5. uniform-positive：在任务内唯一政策中均匀选择，方向固定 +1，精确计算其期望效用，不抽取随机样本。
6. P-outcome-ridge：相同特征和内层训练规则，学习 P 组产出，按预测 P 产出最大值选择，方向固定 +1。这项关联基线使用 P 标签，其方向信息与效果学习器不同。

确定性候选并列均以 candidate_id 字典序决定。预测与选择过程只接收外层任务的无结局特征；选择完成后读取外层效果计算效用。报告预测、训练任务和政策身份、alpha 及内层分数。

## 输出及限制

报告任务等权 signed P−N utility、对应未知界限、逐任务选择和方法之间的候选/方向一致数。均匀选择器报告其分布与其他选择器的一致概率。另报告同候选预算下使用外层已知效果选择方向和政策的事后可达上限，仅用于描述候选集合，不列为可实施方法。

本分析没有新任务外部验证，没有显著性检验或常规 LOTO 置信区间，不建立 TSG 图优势，也不构成结构因果算法比较。样本包含不同有限测量端点，其平均值描述当前任务集合。

结果写入 `results/graph-guided-20260929/targeted-causal-selectors`，拒绝覆盖已有目录。
