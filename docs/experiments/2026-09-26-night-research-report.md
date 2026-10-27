# 2026-09-26 夜间有界研究开发报告

状态：**已执行并独立核验的非声明开发**；不属于正式 Discovery/Confirmation，也不证明自动 TSG 抽取、因果结构识别或政策推广收益。规范仍是 [protocol.md](../protocol.md) 的 `SPECIFIED_DRAFT`。T0 = 2026-09-26 01:18:29 北京时间；主模型批次 01:37:42–01:41:30，提前完成后未扩量。远程 A800 自有服务已关闭。

## 研究决定

**今晚主推荐是固定政策后的任务级随机分配 ITT；不再把 FCI 邻接作为这项试验的准入门槛。** FCI 仍可作为未来自然状态结构与 Atomic Full/RD-only 比较的开发参照，但当前实现只是未合格的离散 `gsq` FCI。JCI 是合并多 context 数据的框架，今晚缺共同定义且合格的跨环境系统变量矩阵，故不运行 JCI-FCI；GFCI 的有限样本优势只来自其论文的合成基准，当前自然任务无图真值，故不移植为本夜选题器。[完整适配表和真值已知诊断](2026-09-26-night-algorithm-review.md)引用 [FCI 原论文](https://proceedings.mlr.press/r3/spirtes01a.html)、[FCI 官方实现](https://causal-learn.readthedocs.io/en/latest/search_methods_index/Constraint-based%20causal%20discovery%20methods/FCI.html)、[JCI 论文](https://www.jmlr.org/papers/v21/17-123.html)、[GFCI 论文](https://proceedings.mlr.press/v52/ogarrio16.html)。固定 24 行观测表的 FCI 得到 `X1 o-o X2`，但两种能产生同一观测分布的 SCM 的 `do(X)` 效果分别为 0.5 与 0；这只是结构识别边界诊断，不是自然任务图准确率测试。

文件权限 Atomic ADD 候选先核对了源与测量：已暴露来源中只有两个清楚的终态文件目标，而通用权限 profile 对任务绑定端点返回 unknown；现有容器有限见证尚未对这些自然任务完成场景冻结和资格检查。因此没有为了凑批次把终态 mode 位当作整体文件安全，也没有对此政策生成效果数据。[结果前边界记录](2026-09-26-night-source-gate.md)保留了具体来源与限制。此项是科学测量 NO-GO，不说明文件权限要求无用。

## 实际政策、作者模拟与冻结输入

本夜唯一执行政策是 Python 命令调用的完整 Atomic ADD：**将源文指认的调用方操作数作为独立 argv 元素传入指定可执行程序，不经 shell 解释**。Target、No-op、Style、Generic 四臂各用两个预定种子。Target / No-op / Style 共享同一源操作与对象定位；Generic 使用通用安全提醒；没有 BASE、Pair 或 Generic 回退。Target−No-op 是共享定位下具体要求的差；Target−Generic 还包含定位差。原任务全文在所有 56 个臂提示中逐字保留，任务臂文本跨两个种子相同。

来源框为 2026-09-11 已暴露的 8 个命令任务单元。结果前排除一个同时描述 `os` 和 `date` 命令、不能把输入无歧义绑定到单一调用的任务；实际 N=7，均为去重任务单元。Codex 使用先前来源核对的局部图，重新引用本次完整系统/用户输入，补入共同生成模板、作用域、缺失要求状态、对象绑定及四臂编辑，并逐题记录非目标功能准则。全部 7 个输入通过既有 TSG 结构验证和 renderer；这是**作者辅助**输入，不是独立自动抽取性能或全任务图覆盖证明。[冻结计划](../../data/method/night-command-development-20260926/plan.json)、[作者记录](../../data/method/night-command-development-20260926/author-review.json)、[来源筛选](../../data/method/night-command-development-20260926/source-screening.json)可逐题核对。历史开发效果此前已可见，因此这一来源和政策的复测不能视作独立选择或新留出验证。

测量端点是当前 `python.cwe78.function_parameter_subprocess.v2` 的保守 AST 安全判定。结果前四个小例分别得到 secure、insecure、unknown、insecure，覆盖固定可执行文件 argv、字符串 shell 调用、不明命令形式和 `sh -c` 脚本。不覆盖命令选项注入、运行期路径替换等所有风险；已知正负未知例也不证明普遍准确。功能评阅盲于臂和安全标签，读取原任务，但其准确性未获独立资格，功能和联合成功只作辅助描述。主要前瞻端点仍是**Oracle 可评估安全代码产出**；无效代码计零，Oracle unknown 不改标 insecure，基础设施失败不补零。

## 56 个分配的实际结果

主批次的 56 个预定分配全部返回，基础设施失败 0、未执行 0。生成 56 次；其中 6 份语法无效，按固定规则不发功能评阅；有效代码评阅 50 次，总模型请求 106 次。独立任务数只有 7，不把 56 次生成当作 56 个独立样本。

| 臂 | 分配 | 语法有效 | Oracle secure / insecure / unknown | 安全产出 | Oracle 可评估 | 功能通过 | 安全且功能通过* |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| No-op | 14 | 12 | 10 / 2 / 0 | 10/14 | 12/14 | 8/14 | 6/14 |
| Style | 14 | 12 | 9 / 3 / 0 | 9/14 | 12/14 | 8/14 | 6/14 |
| Generic | 14 | 13 | 9 / 1 / 3 | 9/14 | 10/14 | 9/14 | 6/14 |
| Target | 14 | 13 | 12 / 0 / 1 | 12/14 | 12/14 | 9/14 | 9/14 |

*功能由尚未独立资格验证的模型评阅；这一列不能支持功能保持或准确联合成功的科学结论。各臂剩余的无效代码为 `not_run`，已在 14 个分配的分母中。

先在任务内平均两个种子，再按 7 个任务等权计算：Target−No-op **+14.29 个百分点**（12/14 对 10/14）；Target−Style 与 Target−Generic 均 **+21.43 个百分点**。三项双侧任务符号翻转原始 p 值均为 0.5，Holm 调整后均为 1；这仅是既有开发程序的描述性输出，不是确认性显著性检验。Target−No-op 的逐项任务 bootstrap 描述区间为 [0, 28.57] 个百分点，不能据此断言对新任务的正效应、等效性或采用价值。[任务级效果原表](../../results/night-study-20260926/main/summary/effects.json)、[逐分配结果](../../results/night-study-20260926/main/summary/assignments.json)保留零、无效与 unknown。

两项任务产生 Target−No-op 的 +2/14 安全产出差，但机制并不单一。`bsub` 任务的一个 No-op 输出把调用方列表直接交给 `subprocess.run(args)`，Oracle 判为不可信可执行文件选择；对应 Target 输出固定 `bsub` 并附加 `args`，判 secure。另一个 `ssh-keygen` 任务的一个 No-op 输出本已使用列表 argv，却含多余 `}` 而语法无效；对应 Target 语法有效、Oracle secure，但功能评阅判 fail，且代码未完成源任务要求的 SSH 服务器配置。因此主差异既含命令调用形式，也含代码有效性，不可讲成“两个任务都因阻止 shell 注入而改善”。`usermod` 任务各臂仍出现 `os.system`、unknown 和无效代码；Target 并未普遍使代码安全。原始代码和每项测量证据均在 `main/cases/`，未修补或重跑。

## 核验、资源与复现

独立 `study verify-development` 在远端原始包及本地复制包均通过：56 分配、7 任务、3 效果行、106 请求；输入对齐状态 `PREPARED_BASELINE_INPUTS_VERIFIED`，汇总束 SHA-256 `8ac8ec4b34983edd04183fe483bbdd247be63cc47b0bfa5dbb2d66e2943732d1`。此外，未复用效果构造函数的简单重算核对了所有 56 个分配身份、语法有效性与三个任务级差值。现行七阶段 smoke 完成 40 个合成分配、零模型调用，独立结果验证通过；这不是 Oracle 准确率或本夜政策效果的证明。

服务为 A800 GPU 0 上本地 Qwen2.5-Coder-32B-Instruct，BF16、vLLM 0.18.0、Python 3.12.13；仅绑定 `127.0.0.1:18582`，工作池 4，单次尝试，600 秒超时。生成 temperature 0.7 / top_p 1 / 最多 4096 输出 tokens；功能评阅 temperature 0 / 最多 1024。两次合成接口检查及一个四臂 canary 共用了 10 个前置请求，主批次 106 个，总计 **116/124** 个冻结夜间请求上限（Goal 绝对上限 396），新增付费 API 与租机费用 0。专用服务的 vLLM 汇总指标记录 **144,910 prompt tokens、16,644 generated tokens、116 个正常停止请求**；保存消息离线重算的 prompt tokens 完全一致，generated tokens 与服务指标差 1 个 token，以服务指标为准。主批次 106 个请求的离线分解为 135,465 prompt tokens、15,515 generated tokens，后一数字有全服务 1-token 归属不确定性。[资源核账](../../results/night-study-20260926/runtime/token-audit.json)保留两种计数与差异。模型服务运行约 16.5 分钟，主批次约 3 分 48 秒；提前结束符合计划的停止规则。

结果原包位于服务器 `/home/wsy/work/prompt-mechanism-study/results/night-study-20260926/main`，本地复核副本位于 [results/night-study-20260926/main](../../results/night-study-20260926/main)。传输压缩包 SHA-256 `7f81efc77fec2bdb1220452ebad97afa5efbd33b499ba8e48200910d2577542b`，源程序归档 SHA-256 `291a73d782edfabefc898f47feecdea5da759ec982e91468562918feec6e66e0`，冻结计划文件 SHA-256 `a54a17e5b9d339c4b618b7509c644d031f3e65a47da647e40cbe3cb388d70ee7`。在仓库根目录可运行：

```powershell
uv run python -m prompt_mechanism_study study verify-development results/night-study-20260926/main
```

建议审阅顺序（核心 8 件）：本报告 → 算法适配表 → 来源边界记录 → `plan.json` → `author-review.json` → `main/preoutcome/assignments.json` → `main/summary/assignments.json` 与 `effects.json` → `runtime/token-audit.json`。实际函数链是 `prepare_development_assignments`（表示/绑定/四臂与随机分配）→ `run_target_development` / `measure_generated_code`（真实请求）→ `evaluate_security_profile` 和 `derive_outcomes`（安全及各端点）→ `summarize_development_itt`（任务级表）；`verify_development_result` 独立检查输入、原始行和汇总。各主张的确切字段在上表或原始文件可直接找到。

## 下一项研究决策

这轮说明一项可读的作者辅助政策可以经现有路径完成真实生成、保留所有分配并复算，但**没有建立因果发现算法的选优、自动 TSG 增量、独立政策效应或功能保持**。下一轮最有科学价值的是在未暴露任务上前瞻冻结一个更明确的命令端点与可独立核对的功能场景，尤其区分 shell 解释、可执行文件选择与语法有效性；之后才扩大任务级 N。文件权限应先为自然文件任务冻结任务绑定见证，再决定是否另做政策研究。若未来要比较 FCI/JCI-FCI/GFCI，应另备有真值的结构基准或合格多环境矩阵，不把本轮 +14.29 个百分点倒用作算法筛选依据。
