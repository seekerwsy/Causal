# 从 TSG 局部诊断转向完整流程验证

本轮直接修复下游执行缺口并运行一次七阶段开发 smoke，没有继续追加 TSG
重复抽取。协议仍为 `SPECIFIED_DRAFT`，main 保持 Atomic-only，论文未修改。

## 发现并修复的缺口

原来的 `study smoke` 接收 fixture 中预置的十个 FCI 邻接布尔值。
`prioritization.py` 虽然已有 causal-learn 调用函数，却没有接入这条完整入口。
`study development` 则从给定政策开始执行编辑和测量，本身不做 Discovery。
因此，原先七阶段检查不能证明真实 FCI 计算已经接通。

现有 smoke 现在直接调用 `run_atomic_fci_bootstrap`，然后进入原来的
Full/RD-only 选择、固定槽位、去重分配、四臂测量和 ITT。fixture 的预置邻接结果
已删除，没有增加新的流程入口、reviewer、实验阶段或测试函数。

FCI 输入是自然状态语义的合成数据：一行一个任务单元，不把生成种子当独立任务，
也不把干预后的状态放进 Discovery。程序核对原有的结果盲折分，按共同范围和任务
家族构建矩阵。ADD/REMOVE 的同一因素共享原始状态；未知不填零，不偷偷缩小
候选总体。该开发实现只接受明确声明的分类协变量，不自动离散化连续变量。
每次重采样保留行索引、PAG 端点和失败；计算失败是不可评估，不是“没有边”。

## 实际执行结果

| 环节 | 本轮输入与结果 |
| --- | --- |
| 表征与候选 | 使用既有合成 fixture；没有执行新一轮 LLM 抽取或自动候选构建 |
| 实际 FCI | 24 个合成任务单元，因素两态各 12 个；一个因素、一个分类协变量、一个结果 |
| FCI 配置 | causal-learn 0.1.4.7；G² 检验；alpha=0.05；10 次任务单元 bootstrap；seed=2026091801；搜索深度和路径长度均为 -1 |
| FCI 结果 | 10/10 次计算有效，10/10 次保留设计中的因素—结果邻接；通过原 fixture 门槛 |
| 排序与冻结 | Full 和 RD-only 都选入同一个候选，共享一个后续效应比较 |
| 分配与测量 | 10 个合成任务单元 × 4 臂，40 次分配、40 条测量、40 条结果；代码和功能回复来自 fixture，安全测量实际执行 |
| 推断与核验 | 运行任务单元 ITT；独立保存结果核验返回 `TARGET_RESULT_BUNDLE_VERIFIED` |
| 成本 | 外部 API 调用 0 次，新增 API 费用 0 元 |

完整输出在
[`data/method/discovery-path-development-v1`](../../data/method/discovery-path-development-v1)：

- `analysis/smoke.json`：实际 FCI 矩阵、变量顺序、背景约束、每次 PAG、门槛判断和七阶段结果。
- `analysis/verify-result.json`：独立下游核验结果。
- `analysis/natural-support-audit.json`：下面的旧开发池审计及逐任务原始标注摘录。
- `analysis/environment.json`：执行命令、环境、源文件哈希；`run/` 为现有格式的完整结果包。

这证明了算法调用和后续计算相连，**没有证明自然任务的发现能力、FCI 相对
RD-only 的收益、TSG 自动准确率或安全干预效果**。这里仅有一个设计好的候选，
两种选择器选入相同对象，不能据此比较选择质量。独立 verifier 检查下游冻结、
分配和 ITT，不重新计算 FCI；FCI 执行轨迹单独保留。

## 已有自然材料能否直接进入 Discovery

只检查了已经暴露的 `local-llm-development-v1/prepared/plan-7b.json`，
没有读取新任务、保护性评估输入或生成结果。该计划已知有早期云模型结果反馈，
其旧图并非当前抽取器的新资格证据。

| 原计划因素 | 独立任务 | 旧标注：未表达 | 旧标注：表达 |
| --- | ---: | ---: | ---: |
| SQL 参数绑定 | 3 | 3 | 0 |
| 命令参数列表、无 shell | 8 | 8 | 0 |
| 路径范围限制 | 1 | 1 | 0 |

这一个 ADD 开发池对三个因素都没有自然两态支持，不能直接估计对应 Discovery
关联。继续抽取同样的任务或把目标臂补作自然正例不能解决问题。这个结论只针对
该计划，不代表整个来源库没有支持；旧标注也没有在本轮重新裁定。

## 下一轮的执行重点

1. 固定一批自然开发任务及因素定义，先看候选相关语义、原始 0/1/未知状态和
   必要的结果盲支持。优先复用已暴露材料；新增开发暴露须先记录，保留保护集。
   若需 D0，只能按预先固定的来源/任务上下文覆盖目标进行一轮自然来源准备，
   不能按这里的缺失正例、FCI 得分、排序或生成结果补样。
2. 有支持的候选进入原任务的代码生成和独立基线测量，再运行同一 FCI/RD 选择
   路径。支持不足保留明确失败，不靠加抽取次数或干预文本制造样本量。
3. 对选出的可编辑要求执行后续开发比较并核验。检查 TSG 错误是否实际改变状态、
   选择或编辑；只修复这些具体阻塞。无关局部 unknown 不再要求整图重做。

这一轮不以整图零错误、额外模型对比或新的独立重复抽取门槛作为前置条件。
开发放行仍要求当前比较依赖的要求、对象、条件和非目标约束明确；它不是正式
表征资格，也不改变此前冻结批次的失败结果。

## 复现和检查

干净的暂存 Git 源码导出使用 Python 3.12.13、causal-learn 0.1.4.7、
NumPy 2.5.3 及声明的语言依赖。既有 105 项检查一次通过（36.45 秒）；
另保存了上述一次 CLI smoke 和独立 verifier 输出。一个既有 pytest JUnit
属性格式警告不影响执行结果。没有正式参考输出需要在本轮重新解释。

安装 `.[dev,selectors,languages]` 后，在新的输出路径运行：

```text
python -m pytest -q
python -m prompt_mechanism_study study smoke NEW_OUTPUT_DIRECTORY
python -m prompt_mechanism_study study verify-result NEW_OUTPUT_DIRECTORY
```

保存 smoke 命令的 JSON 输出以保留 FCI 轨迹；不要覆盖已保存结果。
