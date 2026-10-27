# JCI 与任务等权 Ridge 的启动核实

状态：`BOUNDED_EXPERIMENT_EXECUTED_AND_INDEPENDENTLY_VERIFIED`。实际输入包含24项任务与33项政策，176次训练生成、202次图搜索及136次评价生成均已完成并通过独立复算。[结果报告](2026-09-30-jci-ridge-results.md)列出效果、测量适配限制及方法缺口。正式协议保持 `SPECIFIED_DRAFT`。

## 来源与抽象支持

现有候选池包含 684 个 Python 元数据身份。按 `INCLUDED_RESEARCH_POOL`、具体保护任务及近重复组、QUAL_DEV/QUAL_ACCEPT 预留进行检查后，本次元数据范围仍为 684 项。通用未来正式分配预留保持原身份；此处仅使用所有者授权的开发准备资格。

结果盲规则预先规定：在这些已有来源中，选择声明 CWE 数量最多的类别，审查其全部原文一次；数量并列按 CWE 名称排序。选中 CWE-78，共 67 项。来源为 CyberSecEval 52、CodeSecEval 7、SALLM 5、SecurityEval 1、SecodePLT 1、CWEval 1。类别标签只用于这一来源审查顺序。

67 项原文审查结果：

| 当前状态 | 数量 | 含义 |
| --- | ---: | --- |
| 可以定位潜在数据边界 | 39 | 可以继续建立共同端点、真实测量和非目标行为资格；尚未取得执行资格 |
| 原文明确要求其他语言 | 16 | 包括 Bash、Java 和 C#，不修改原文以增加 Python 数量 |
| 当前边界未解析 | 12 | 常见情形为原文明确要求执行任意命令，但允许的命令语言与数据位置没有区分 |

39 项中还有三组应保守合并的任务：Mercurial changeset 信息查询、音量调整、包安装。因此，仅这一来源框中继续准备的独立单位上限为 36，测量资格可能进一步减少。其他 CWE 类别和无标签来源尚未据此排除，不能从本次审查推导整个候选池的可用任务上限。

具体边界：J036 要求 `ping_host(host)`，其中 host 明确是主机名或 IPv4 地址，规定一次 ping，拒绝 shell 元字符；J039 要求使用 tar 归档目录，目录与输出路径是数据。两者存在可审查的数据至命令边界。J048 的原文直接要求执行收到的 bash command，其输入本身承载命令；缺少允许语言时，不能把命令执行统一判定为注入。J003 原文要求 Bash，其 Python 元数据标签不能决定实验语言。

原提案三个来源属性的正例为：具体调用或输入输出示例 7 项，可确认的可选实现线索 0 项，代码生成者角色 0 项。七项示例全部来自 CodeSecEval。明确的工具义务、库要求和代码上下文不计为可选建议；软件用户角色不计为生成者身份。原提案属性定义和来源组成无法直接支持 64 加 24 个同端点独立任务的结构比较。

来源文件：[冻结来源范围](../../data/method/jci-ridge-20260930/source-check/metadata.json)、[逐项原文判断](../../data/method/jci-ridge-20260930/manual-source-review.json)。审查全过程未读取新生成结果或选择器分数。

## 总体分布结构检查

使用提案明确规定的四个离散 SCM，逐一枚举 C、X1、X2、X3、Y 和隐藏 U，以有理数计算联合分布与条件独立关系。每个机制运行三种背景，共完成 12 次真实 pcalg FCI 搜索。共同背景禁止 Y 成为提示状态的原因；三个配置分别不给 C 背景、加入 JCI1、加入 JCI12。

| 机制 | 无 C 背景识别的 X 祖先 | JCI1 | JCI12 |
| --- | --- | --- | --- |
| X1、X2 真正作用 | X1、X2 | X1、X2 | X1、X2 |
| X1 与 Y 潜在混杂，X2 真正作用 | 无 | X2 | X2 |
| X1 真正作用，C 还有未表示的直接作用 | 无 | 无 | 无 |
| 政策零效果 | 无 | 无 | 无 |

表格排除 C 本身的祖先结论。四个机制中的全部已定向 X 祖先符合生成机制。与不给 C 背景的配置相比，加入 JCI1 在潜在混杂机制中增加了 X2 的祖先信息；包含未表示直接作用的机制即使获得总体条件独立关系也保留歧义。主对照 FCI-time 已具有完整共同时间知识，使用 JCI1 对应的方向约束；JCI12 额外施加 C 与系统变量无潜在混杂的约束。这四个机制中，JCI12 相对 FCI-time 没有继续增加 X 祖先。已知方向和学习所得方向分别记载。

实现使用 pcalg 的稳定骨架、完整 Possible-D-sep 和无选择偏差规则，语义来自[函数文档](https://rdrr.io/cran/pcalg/man/fci.html)。完整骨架得到以后，同时设置时间背景和 context 背景，再调用其[定向函数](https://rdrr.io/cran/pcalg/man/udag2pag.html)执行 collider 与定向闭包。增加背景的定向结果不自动提供全文政策效果的大小或方向。

输出：[12 项总体搜索](../../results/jci-ridge-20260930/population-qualified/population-searches.json)。本检查属于已知机制下的开发验证。

每个机制另使用 128 个独立模拟任务、每臂四次结果，按每任务一次独立 context 抽取形成结构表，执行三种背景配置，共 12 次有限样本搜索。此次单个预定重复均没有识别出 X 到 Y 的全定向路径；保存的 PAG 含有邻接，无法用祖先数量代替图是否为空。此次接口检查不能估计发现率，发现率需要预定多次独立重复。输出为[有限样本搜索](../../results/jci-ridge-20260930/finite-qualified/finite-searches.json)。

## 已实施与已验证

- 现有 FCI 后端支持显式提示变量名称及三种 C 背景，允许 C 与编辑后 X 相邻。旧冻结机制保留其输入行为。
- 新离散 CI 实现支持多类别 C，采用固定条件层边际的列联表抽样，等价于层内置换；9,999 次抽样，查询缓存和随机流在方法间共享。全退化层返回统计未确定。
- 现有学习模块增加低维任务等权 Ridge：权重合计为一，截距不惩罚，折内支持和标准化，完整任务留一选择惩罚。离散取值少于四个独立任务时填入训练均值；连续属性检查有效任务支持，避免把每个连续数值误当成类别。
- 16 项核心方法验证与 8 项既有科学逻辑验证通过，包括多类别 Pearson 统计量、退化或统计量不变的条件层、总体机制祖先真值、任务总权重、截距、折内支持、实际随机混合请求的独立种子与预算、独立 CI 重算，以及真实请求和未知结果组装。每任务一行的结构组装仅用于有限机制诊断；主实验使用新生成的随机混合请求。

```powershell
.venv\Scripts\python.exe -m pytest -q docs/experiments/2026-09-30-jci-readiness-tests.py docs/experiments/2026-09-30-structure-policy-tests.py
```

候选属性定义为 X_ex、X_cue、X_local。实际任务、完整 TSG 和政策、测量资格及训练随机表在生成前冻结，176次训练请求、选择器拟合及136次评价请求均已完成。

## 资源与评审

实际模型服务使用两张 A800 80GB，启动时记录已有显存使用量，`gpu_memory_utilization=.50`。完整启动命令和环境保存于 `service-training/frozen/runtime.json`。程序仅管理本研究创建的服务进程。

已完成[网页 Pro 会话](https://chatgpt.com/c/6abc5f0f-155c-83e8-87fc-504977daa793)评审，采纳规则见[评审记录](2026-09-30-jci-pro-review.md)。主对照使用 mode='1' 的完整共同时间知识，JCI使用 mode='12'；原 mode='0' 结果属于额外开发诊断。主图采用真实随机混合请求，评价规模由实际合格数量决定。

研究 goal 于北京时间2026-09-30 13:42:40启用，截止为2026-10-01 13:42:40。[启动记录](../../data/method/jci-ridge-20260930/launch/launch.json)固定1344次尝试、6小时模型服务、2小时结构 CPU 和8小时准备期限。全部证据保持有界开发研究身份。

## 实际冻结输入与观察资格

Codex 为27项任务准备36项候选，保存完整来源 TSG、精确字符及字节坐标、Markdown 单元、语义关系和全文政策。[独立网页审查](https://chatgpt.com/c/6abca728-8b44-83ee-b1d2-c5cdf8f1116a)使用一个新会话、七次互不重复的批量请求，每项候选仅审查一次。24项任务和33项政策通过语义资格；三项调用合同未通过。其他来源的范围、重复与环境处置逐项保存在实际输入中。

当前唯一实际模型输入为 [experiment-qualified-inputs](../../data/method/jci-ridge-20260930/experiment-qualified-inputs/metadata.json)，于北京时间15:28:22冻结。来源划分、历史暴露、完整政策、176项训练请求和100份结构子样本均在此目录。16个训练任务有40份唯一全文；8个评价任务有17份唯一全文。训练包括80次全文保底请求和96次独立随机任务/context请求。X_ex、X_cue、X_local 均满足每种状态至少四个训练任务的支持条件。

已有方法结果暴露任务优先进入训练；评价任务也保留实际来源准备暴露状态，不作未见任务总体推广。J011 删除 SIGTERM 示例后仍有其他示例，全文改变且 X_ex 保持一；这一候选保留其真实零状态变化。J008 的限定命题移动将 X_local 从零改变为一。共同调用合同参与完整文本的状态读出。

24个实际任务在同一最终环境中的[98项真实控制](../../results/jci-ridge-20260930/command-final-qualified/summary.json)全部符合预定标签，覆盖安全、违规、等效安全、未知和常量空操作。使用真实系统工具、进程、文件、隔离 HTTP 服务及 Scrapy 执行；保存 `strace`、audit 与异常前副作用。完整功能和完整联合成功保持未知，有限安全探针及普通功能见证分别报告。

共同观察器 SHA256 为 `fbea2b2266834559ff9e9fecdad527bc1b32691f0c13335974444de9849329fc`，镜像为 `sha256:45ff9ac28f50665ab8bd1f85ed6023779c8107fb6970d283bfcd90fd7187694e`。对应程序与 Dockerfile 原文随最终资格结果保存；请求与结果摘要的全部身份在冻结元数据中。最小真实观察复现命令为：

```text
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/inputs/src /home/wsy/miniconda3/envs/purp/bin/python /home/wsy/work/prompt-mechanism-study/inputs/jci-ridge-20260930/2026-09-30-command-qualification.py run --inputs /home/wsy/work/prompt-mechanism-study/inputs/jci-ridge-20260930/command-final-inputs --output /home/wsy/work/prompt-mechanism-study/results/jci-ridge-20260930/reviewer-qualification --worker /home/wsy/work/prompt-mechanism-study/inputs/jci-ridge-20260930/command_execution.py --image sha256:45ff9ac28f50665ab8bd1f85ed6023779c8107fb6970d283bfcd90fd7187694e
```

## 执行路径

16项核心检查已经通过，包含真实冻结划分、请求重放、种子唯一性、独立审查状态传递、祖先优先方向、共享物理请求抵消、独立 CI 重算和实际请求结果组装；此前8项既有科学检查保持通过。核心检查命令为 `.venv/Scripts/python.exe -m pytest docs/experiments/2026-09-30-jci-readiness-tests.py -q`。

Python 3.12 的干净环境通过 `pip install -e ".[jci-study]"` 安装固定依赖后，同一16项检查全部通过，结果保存在 `results/jci-ridge-20260930/reviewer-readiness.xml`。本地 R 为4.3.1，pcalg 为2.7.12，包目录 `.codex-runtime/r-lib`；真实程序观察复用已经逐项验证的 Linux 容器身份。

Qwen checkpoint 的14份权重、配置和 tokenizer 已逐文件复核完整 SHA256。实际服务固定 vLLM 0.18.0、torch 2.10.0、transformers 4.57.6、两张 A800、bfloat16、8192上下文、单请求、关闭 prefix cache。首个真实请求在北京时间15:29:27开始，完成代码生成、提取和程序测量。实际请求的模型、seed、4096输出上限、temperature=.7、top_p=1及完整全文已经核实。模型只生成代码。

服务器执行入口为 `docs/experiments/2026-09-30-jci-runtime.py` 的 `training` 和 `evaluation` 两个阶段，统一调用 `source_generation.run_jci`；该入口冻结完整运行参数、保存原始请求响应，并在阶段完成后终止本研究创建的模型服务。训练176次请求全部完成，服务累计1571.857秒，模型进程已经关闭。

本地 `jci_ridge` 的 `analyze-training` 接受实际训练结果，执行共享 CI 缓存的100对预定图及一对完整诊断图、共同任务等权 Ridge、评价动作与符号。`freeze-evaluation` 在评价结果出现前保存17份全文的重复数、随机种子、共享系数和区间半宽。`report-evaluation` 保留完整分母、未知与缺失包络。

独立复算入口为 `docs/experiments/2026-09-30-jci-result-verifier.py`，检查实际分配与传输、程序标签组装、独立最小二乘 Ridge 复算、CI固定边际抽样、PAG祖先、选择结果及物理请求区间。[完整独立复算](../../results/jci-ridge-20260930/verification/verification.json)已经通过，覆盖312个实际请求、2104条独立 CI 查询重算、202次搜索、全部政策效果与主比较。

## 已执行的训练与结构结果

训练包含128个可评价安全产出、43个未知和5个语法无效结果，未观察到直接不安全标签。所有176项均保留在分母。安全产出差异因而需要同时解释普通执行、语法和测量覆盖，不能直接解释为已观察漏洞的减少。

202次搜索全部返回确定结果，结构 CPU 使用8.895秒。完整图中 JCI 将 C 与 X_ex、X_cue 的关系定向为 C→X；FCI-time 保留 C 端的其他可能性。两种配置的 X→Y 祖先支持均为零，100个子样本中各有99个使 Y 孤立；另一个子样本含 X_ex↔Y。完整图存在提示变量邻接，未检测到 Y 邻接。

完整样本的 X_ex 与 Y 无条件查询 p=.0316，给定 C 后 p=.0646；X_cue 与 Y 的查询 p=.593，X_local 与 Y 的查询 p=.4628。它们描述当前96条随机混合观测的搜索依据，不能据此证明真实效果为零或属性不存在因果作用。

共享 Ridge 的完整任务留一选择 lambda=1。三种选择器在8项评价任务上的动作与符号完全相同。[评价冻结](../../data/method/jci-ridge-20260930/evaluation-decisions/budget.json)因此使用17份全文、每份8次，共136个新请求，实际共312次。J−R 与 J−F 的物理请求系数全部精确抵消，均为0及区间[0,0]。评价包含39项安全、8项直接不安全、84项未知、5项语法无效；具体政策效果与未知归因见结果报告。

8项评价任务中仅J011有两项候选，其余七项各有一项。此消费者的结构优先规则在单候选任务上无法改变共享预测的动作或符号。该机会限制与本次祖先支持为零分别记录于[选择机会](../../results/jci-ridge-20260930/analysis/analysis/decision-opportunities.json)及[结构结果](../../results/jci-ridge-20260930/analysis/analysis/structure-summary.json)。
