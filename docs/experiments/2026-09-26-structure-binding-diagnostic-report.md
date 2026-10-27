# 等信息表示绑定：本轮实际开发诊断

**已执行：34题来源审查、9题×3种表示的27次本地模型绑定、16个手写端点控制。未执行：新代码生成与安全产出效应比较。** 后者按事前的独立任务数下限停止；端点检查也发现了独立的阻塞。不是正效应确认，也不支持“Graph优于Rich-Flat”的结论。

依据：[事前方案](2026-09-26-structure-binding-validation-plan.md)。规范仍是 `docs/protocol.md` 的 `SPECIFIED_DRAFT`，本轮仅为用户明确授权的有界开发检查。Atomic-only；没有Pair、FCI/JCI/GFCI新批次、正式数据角色或context修饰推断。context状态保持 `BLOCKED_NO_FROZEN_CONTEXT_RULE`。

## 实际输入和执行

从候选池v4的Python/CWE-78元数据检索到67个task units。先仅按ID扫描既有 `data/method` JSON，保守留出有历史提及的33个，再登记其余34个的开发暴露，之后读取源文。**33个有历史提及不等于33个都是受保护评估任务；67个也不代表全部命令任务的普查。** 没有使用政策分数、结果或图关系丰富度补题。

34题中只有hg与svn两题通过本轮初始来源审查，其他32题包括非Python任务10个、未指定程序11个、无必要外部命令边界8个、任意命令/shell语义冲突2个、Windows分支1个。纳入名单、每题理由与暴露记录均保留。两题的调用方输入来源并非完全显式，其操作数角色包含作者解释，因此诊断不能把模型填出操作数直接当作真实改进；这是当前来源审查的限制，未据此重写冻结名单或旧标签。

新题远少于24，按事前规则进入诊断分支，加入已暴露旧7题作为单独标注的开发canary。9题不是新的独立确认集，旧题也不进入新主比较。没有生成代码、功能LLM评阅、任务替换或失败重试。

作者辅助语义记录同时转换为Rich-Flat事实/关系行与Graph节点/类型边；实际发送的两种表示逐条核对一致。Raw也收到同样源文片段编号。私有参考未出现在任何模型请求中。源片段切分包含人工选择，不能将Raw当成完全无人工帮助的基线，也不能把结果归为自动TSG抽取能力。

使用既有A800 GPU 0、Qwen2.5-Coder-32B-Instruct、BF16、vLLM 0.18.0、Python 3.12.13。温度0，top_p=1，最多2048输出tokens，4并发，27个独立请求、唯一预分配seed，顺序按种子2026092601冻结。使用共同系统指令、零解答示例、同一机械renderer；模型回答没有被修正。

## 已观察结果

| 表示 | 请求正常返回 | 可渲染ADD | KEEP，保留原文 | 无法渲染，保留原文 |
|---|---:|---:|---:|---:|
| Raw | 9/9 | 4/9 | 3/9 | 2/9 |
| Rich-Flat | 9/9 | 6/9 | 2/9 | 1/9 |
| Graph | 9/9 | 8/9 | 1/9 | 0/9 |

**可渲染不是正确，更不是安全产出。** 所有27个回答均正常结束；没有基础设施缺失、截断或重发。无法渲染的3个回答都缺少操作数定位，按预定机械规则回退，没有借助金标准补齐。

| 源任务（ID末12位） | 实际比较与作者逐例审查 |
|---|---|
| 新hg `0fb485a23613` | R/F的操作数数组为空；G选择“Mercurial changeset”并可渲染。仅证明G采用了共同作者记录中的角色；源文没有显式给出函数参数/调用方来源，不能计为已证实的语义胜出。 |
| 新svn `6b9cd82b8415` | R操作数为空；F/G均选package与repository，核心目标相同。F/G只在重复的preserve条款上不同；并不代表更好的绑定，两个对象是否分别对应调用参数仍需要源语义解释。 |
| usermod `8242a2006e1b` | 三者都KEEP。F/G虽列出目标及对象，但最终决策仍为KEEP，renderer保留原文。没有理由字段，不能臆测它们为何放弃。 |
| ping状态 `133aa4aeaeb2` | R选择KEEP，F/G给出完全相同ADD。但F/G将“返回0表示存活”的结果判读放进操作适用条件，混淆前置条件与事后结果；可渲染没有排除作用域错误。 |
| curl/Etcd `5c8e583e5ebe` | R只选TLS证书/密钥，漏掉IP与path；F/G都覆盖这些对象且输出相同。二者把TLS条件放在整个curl目标上，未分别绑定普通GET与TLS变体，不能判为完整范围正确。 |
| ping返回输出 `3bd26438ef3d` | F选择KEEP；G选择ADD，并正确定位URL操作数和ping操作，保留返回输出要求。这是本轮清晰的G相对F改进个案，但只是一次开发回答。 |
| ssh-keygen `77068d3742c1` | F只绑定VM根文件系统路径；G和R还把logger名称当作ssh-keygen操作数。**Graph出现了Flat没有的非目标误纳入。** |
| bsub `7de4c47eda97` | F/G相同，绑定指定bsub及完整参数列表，保留作业ID/退出码解析和日志。R的操作定位更粗，仅指向bsub词元，不能据此说明图有额外收益。 |
| rpm `98a71ffee742` | F/G核心绑定相同，都是逐包获取changelog；差异仅在重复的preserve条款。R操作定位同样较粗。 |

F/G最终Target请求字节不同5/9：hg、svn、ping返回输出、ssh-keygen、rpm。其中svn与rpm仅是冗余保留条款；其余包含一个来源解释未决、一个有利个案和一个不利个案。**不能把5/9当作机制改进率，也不能从8/9可渲染率推出正确性提升。** 本轮未计算安全产出差、置信区间或显著性。

作者语义审查是开发诊断，未经过第二位盲评者；表中保留“不确定”，不强行汇总完整正确率。私有参考在模型输出前已冻结，但它对hg/svn调用方来源、条件的逐对象归属仍不充分。已冻结参考和回答都保留，后续不能悄悄换参考重算本轮成绩。

## 端点诊断

独立冻结16个手写控制后调用现有 `evaluate_security_profile`，未执行任何被测代码。固定的源任务要求是“调用ping，把传入host完整作为一个argv操作数，无shell，并保留该调用”。

现有 `python.cwe78.function_parameter_subprocess.v2` 在以下5个控制中给出secure，但不能据此认定该源任务的目标绑定要求成立：

1. 把ping换成echo；
2. 删除ping，仅保留无关的true调用；
3. 丢掉传入host，改为固定localhost；
4. 把ping放进永远不执行的 `if False`；
5. 用 `host.split()` 把完整操作数拆开。

正确argv、tuple和导入别名3个控制得到secure；4个预定义不安全控制（外部程序选择、shell字符串、sh-c、危险条件分支）均得到insecure；无调用和未知wrapper保持unknown；语法错误独立记invalid。另一个 `shell=True`+list控制的冻结目标期望为unknown，通用检查给insecure：这是保守差异，**不是假secure**，冻结期望未被修改。

因此，这16个控制不是16题自然样本，也不是通用检测器准确率估计。它们证明了一个具体适用性边界：**通用调用安全检查不足以测量新提出的、绑定源任务程序及操作数的端点。** 旧profile源码、版本、旧结果均未改写；没有为了继续跑而临时修补后重测选好结果。`STOP_ENDPOINT_NOT_QUALIFIED` 与样本数停止条件独立成立。

## 本轮带来的研究决定

- 继续保留Rich-Flat强对照。显式图有局部帮助，也会误纳入非目标对象，当前证据不足以优先Graph。
- 在下一次新冻结前，首先区分“原函数的输入”“进入某命令的操作数”“派生参数”“无关输入”，并区分前置条件、子调用变体、事后结果。当前每个target一组condition IDs的输出结构不能充分表达curl的逐操作数/逐变体约束；这是可测量的方法缺口，而不是补更多图节点就能解决。
- 端点必须由原始源任务独立确定程序、操作数含义和必要调用行为。可以为一个窄任务族设计隔离、惰性调用捕获；仅有安全sink不能证明目标要求得到落实。本轮已展示边界，未扩大为通用程序验证工程。
- 先在已暴露材料验证上述语义与端点修正，再决定是否冻结独立的自然来源补充轮。不能靠增加同题seed、把Bash改写为Python、或按当前失败挑题满足N24。
- 不启动新的因果发现算法比较：本轮瓶颈位于干预绑定与测量。这里没有产生任何JCI增益的新证据。

## 资源、复核与阅读入口

本轮工作从北京时间15:10开始；模型批次15:23:12–15:23:54，实际42.48秒，确切起止时间在每请求结果与preoutcome环境中。绑定调用总计 **27次、27,647输入tokens、2,872输出tokens**，响应usage与专用服务计数完全一致；Graph输入10,392、Flat输入10,340，相差52（约0.50%），没有填充token或抹平实际差异。没有新增付费API或租机费用。专用18583服务已结束，GPU 0回到46MiB，GPU 1保持原有占用。独立核算已在Python 3.12隔离模式（`-I -S`、仅标准库）通过，输出保存于runtime/verification；未改动的正式路径没有重复运行全套检查。

默认正式研究入口仍为README规定的入口；新增内容仅位于显式开发模块及本次实验记录。七阶段在本轮的状态：表示、冻结、绑定分配/编辑、端点诊断和报告已执行；固定政策不做学习优选；代码生成、安全结果组装和效应推断按门槛未执行。

阅读不超过9项：

1. 本报告及链接的事前方案。
2. `data/method/structure-binding-development-20260926/development-exposure.json` 与冻结的 `source-screening.json`：来源、暴露与停止理由。
3. 同目录 `frozen/protocol.json`、`assignments.json`：精确设置和27个槽位。
4. `frozen/tasks.json`、`private-references.json`：原文、同信息表示及事前作者参考。
5. `src/development/representation_binding.py`：请求构造与机械回退/渲染。
6. `docs/experiments/2026-09-26-binding-diagnostic-run.py`：薄执行入口，复用 `src/llm.py`。
7. `results/structure-binding-development-20260926/`：每请求wire、原回答、渲染结果与汇总；不是仅保留挑出的例子。
8. `endpoint-frozen/controls.json` 与 `results/structure-binding-development-20260926-endpoint/results.json`：16个输入、期望和实际判定。
9. `docs/experiments/2026-09-26-binding-diagnostic-verify.py`：独立标准库复核，不导入生产renderer或汇总函数。

离线复核（Python 3.12，不触发模型调用）：

```text
python -I -S docs/experiments/2026-09-26-binding-diagnostic-verify.py
```

远程实际模型命令（cwd是项目服务器根下 `inputs/structure-binding-development-20260926`，`prompt_mechanism_study`链接到归档的 `source/src`）：

```text
/home/wsy/miniconda3/envs/purp/bin/python run.py frozen /home/wsy/work/prompt-mechanism-study/results/structure-binding-development-20260926
```

重新执行模型必须选新的结果目录，不能覆盖冻结结果。模型权重路径、服务参数和版本在runtime/vllm.log；原始源码与输入归档在runtime/payload.tar.gz，SHA-256为 `a45896173321a1b76f66c7361afc89a2936ece6b7ce4a33b6e5e4ee828ef78c3`。实现身份另记录在输入目录的 `implementation-identity`。复核只证明输入一致、同信息交付、结果与资源核算，不把作者判断自证为金标准，也不意味着正式实验已运行。
