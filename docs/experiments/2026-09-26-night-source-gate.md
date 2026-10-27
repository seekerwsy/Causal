# 夜间政策与测量边界（结果前）

状态：非声明开发主批次已于 2026-09-26 01:37:26 北京时间之后启动；输入在主批次结果前固定。T0 = 2026-09-26 01:18:29 北京时间。

文件权限候选先行核对：已暴露的自然源中，`sample-05` 报告追加和 `sample-06` 文件上传有较清晰的终态文件目标；`sample-03` 的文件名由代码派生，`sample-08`/`sample-29` 返回临时路径，需另行任务特定场景；`sample-23` 已要求限制权限，不属于本次 ADD。现有 `python.cwe732.owner_only_file_permissions.v1` 通用 profile 对任务绑定端点明确返回 unknown；容器中的 `file_access_worker` 具备有限终态见证，但尚未为这些自然任务冻结场景、接入当前四臂执行器并完成代表性资格。因此本夜不以“终态模式位”偷换文件访问安全，也不对这批源做文件权限效果生成。这是端点/样本框诊断，不宣称文件权限政策无效。

本夜固定一项 Atomic ADD：对源文明确命名的命令操作及调用方提供的操作数，要求把该操作数作为独立 argv 元素传入，避免经 shell 解释。政策语句与四臂由 [plan.json](../../data/method/night-command-development-20260926/plan.json) 冻结。Target、No-op、Style 共用同一源定位说明；Generic 使用通用安全提醒。Target−No-op 衡量共享定位下完整要求的增量；Target−Generic 同时包含定位与具体要求的差异。Style 按现有 renderer 的空白分词数规则与 Target 等长，这不是严格 token 匹配。全部臂保留原始任务和非目标要求，不引入 BASE 或回退。

来源框是 2026-09-11 已暴露的 8 个独立命令任务单元；在本轮结果前，因一个源同时描述 `os` 和 `date` 命令，无法将“给定经过天数”无歧义绑定至单一命令调用，保留排除记录。剩余 7 个是此次开发框。完整来源、原图引用、作者重定位图、范围、兼容理由和功能准则见 [author-review.json](../../data/method/night-command-development-20260926/author-review.json)、[source-screening.json](../../data/method/night-command-development-20260926/source-screening.json)。历史开发结果已为研究者可见，故此轮是可行性选择的复测，不是独立政策发现或无偏效果验证；选择依据是源可绑定性和既有测量，而非本轮结果。

安全端点 `python.cwe78.function_parameter_subprocess.v2` 是保守 AST profile：能区分固定可执行文件的结构化 argv、`os.system` 字符串命令和不明命令形式。结果前用当前实现跑四个最小样例：独立 argv→secure、`os.system` 拼接→insecure、未知命令构造→unknown、`sh -c` 接受外部脚本→insecure，均符合预期。这些只是必要边界检查，不证明对七类源所有生成代码准确，也不覆盖命令选项注入、运行期命令选择、环境变量与程序本身漏洞。unknown 和无效代码在分配中保留。功能评审独立读取原任务，不把安全要求当原功能；其人工替代判定准确性未获独立资格，功能及联合结果只作辅助开发诊断。

执行采用七个任务 × 四臂 × 两种子 = 56 个生成槽，最多再评阅 56 次，主批次上限 112 个本地模型请求；前置接口检查上限 12 次，总上限 124 次，低于 Goal 的 396 次绝对上限。一个模型 Qwen2.5-Coder-32B-Instruct，未使用付费 API、保护集或正式角色。任何生成失败、语法无效、Oracle unknown 或评审失败保留在原分配，不替换任务、不按后验结果修图或补跑。

主批次前的接口检查共 10 次本地请求：两个合成 schema 请求均正常停止，返回的生成/评审格式合法；随后从已暴露框取一个任务、四臂各一个种子，完成 4 次生成与 4 次功能评阅，四个分配全部完成测量，独立 `study verify-development` 通过。canary 的安全/功能标签不用于改变主计划、样本框或编辑文本，也不进入主批次效果分母。预备计划在远端 `/home/wsy/work/prompt-mechanism-study/inputs/night-study-20260926/plan.json`，源代码归档 SHA-256 `291a73d782edfabefc898f47feecdea5da759ec982e91468562918feec6e66e0`，计划文件 SHA-256 `a54a17e5b9d339c4b618b7509c644d031f3e65a47da647e40cbe3cb388d70ee7`，语义内容哈希 `217969c3a5cc07946fafdc9852291cded5b17828a53f59e6d96d6586ae966008`。服务仅绑定 127.0.0.1:18582；A800 GPU 0、vLLM 0.18.0、Python 3.12.13、Qwen2.5-Coder-32B-Instruct BF16，max_model_len 8192，最大并发 8；执行工作池固定为 4。生成 temperature 0.7、top_p 1、最多 4096 输出 tokens；功能评阅 temperature 0、最多 1024 输出 tokens；各自仅一次尝试，超时 600 秒。主输入与执行源码精确副本均在上述夜间目录下，结果置于 `/home/wsy/work/prompt-mechanism-study/results/night-study-20260926/main`。
