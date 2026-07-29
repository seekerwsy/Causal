# Project-Level Agent Instructions

## Scope and Precedence

These instructions apply to the entire repository. More specific descendant
`AGENTS.md` files may add directory-scoped requirements, but they must not
silently weaken or contradict these repository-wide constraints. When a
descendant instruction appears to conflict with this file, preserve the
stricter requirement and make the conflict explicit before proceeding.

## Code Implementation Requirements

1. 动手前必须先理解需求，存在歧义时先讨论，不能擅自实现。
2. 实现方式必须说清楚，不能只用版本号或抽象名称代替解释。
3. 每次执行前，都要确认最新要求已经完整对齐，避免跑到一半才发现缺少设置。
4. 先在少量案例上验证实现和实际行为，确认正确后再扩大规模。
5. 所有配置、命令、日志、中间产物和结果都必须保存，不能过段时间忘记跑过什么。
6. 历史结果不能丢失或覆盖；新设置与旧设置必须清楚区分。
7. 环境、机器、工作目录和输出路径必须明确，不能把文件散落到不同位置。
8. 出错后不能直接停止或忽略，要定位原因、修复问题并补齐失败任务。
9. 提高并发前要观察机器、网络和接口状态，不能为了加速把整个环境拖垮。
10. 进度汇报要覆盖所有任务，说明完成、运行、错误、待运行数量，以及当前速度和预计耗时。
11. 结果异常时必须检查具体执行过程，不能直接用“随机性”或模型差异解释。
12. 已经实现过的功能应先找到原实现并复用，不能反复重写一套新的东西。
13. 每次犯过的错误都应记录下来，避免在后续任务中重复发生。
14. 实现必须形成可复现的完整流程。

## General Paper-Writing Requirements

1. 先把论文真正要回答的问题和整体故事讲清楚，再开始润色文字。
2. 写作要从研究问题出发，不能把工程实现过程直接搬进论文。
3. 用词必须清晰、稳定、专业，避免内部命名和随意创造的术语。
4. 摘要和引言需要有连贯的推进关系，不能一句话没讲完整就切换到下一点。
5. 写作应参考高质量论文的结构、叙事方式和表达习惯，而不是只做表面润色；应给出相应参考论文。
6. 实验部分必须有足够的信息量，不能只罗列少量结果，也不能只堆数字。
7. 每个实验都要说明它回答什么问题、结果是什么、说明了什么。
8. 图表必须服务于论证，并放在对应文字附近，不能全部堆在文章后面。
9. 图表需要反复检查尺寸、位置、字体、留白、对齐和可读性。
10. 正文写核心发现和关键实验，完整提示词、交互轨迹、案例和实现细节放入附录。
11. 已提出的写作要求不能因为审稿意见或后续改写而被悄悄删除。
12. 每轮修改后都要重新编译并做视觉检查，不能只确认 LaTeX 没报错。
13. 审稿反馈用于发现问题；最终仍要服从论文自身的研究目标。
