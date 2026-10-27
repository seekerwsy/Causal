# 结构查询证据

本页对应协议第12节，记录历史合成输入的实际后端复算、逐查询裁决和精确数学见证。本页证据没有调用Qwen生成新代码。

## 输入、实现和输出身份

输入为`data/method/graph-guided-20260928/algorithm-inputs/{protocol.json,matrices.json,manifest.json}`。320份矩阵覆盖四种机制、33／72／200／1000行及20个seed（2026092801至2026092820），每份矩阵包含二元变量C、X、Z、Y。四种算法读取同一份矩阵；U仅用于生成样本，不交给算法。

| 方法 | 实际实现与配置 | 输入的背景知识 |
| --- | --- | --- |
| FCI-JCI0 | 原R文件`docs/experiments/2026-09-28-context-search.R`调用`pcalg::fci`；`disCItest`、alpha=0.05、`adaptDF=FALSE`、`selectionBias=FALSE`、`NAdelete=FALSE`、`jci='0'` | C被登记为context；不施加JCI1／2外生性和无混杂约束 |
| JCI1 | 同一R文件、同一检验和样本，`jci='1'` | 系统变量不能引起C；允许context与系统变量潜在混杂 |
| JCI12 | 同一R文件、同一检验和样本，`jci='12'` | JCI1加上context与系统变量没有潜在混杂 |
| GFCI | 原Python实现`gfci`调用`TetradSearch`；BDeu ESS=10、structure_prior=0、G² alpha=0.05；`run_gfci(depth=-1,max_degree=-1,max_disc_path_length=-1)` | 未向GFCI提供与JCI相同的context背景约束 |

JCI1／2约束的定义及FCI中的用法见[JCI原论文第3.4和4.2.4节](https://www.jmlr.org/papers/volume21/17-123/17-123.pdf)。这些约束需要根据实际设计论证；PAG中的圆圈表示尚未确定的端点，不能把圆圈计作错误的固定方向。X→Y在PAG中提供祖先方向信息，直接因果机制还需要结合变量定义和额外证据。

冻结Python实现SHA256为`7c7188eabfb943496ddbe5262e2dfe2d7da0f7635ae6be1a05f3586dcc70ceed`，其准确副本在`.codex-runtime/discovery-historical-backend/context_algorithms.py`；函数`make_rows`定义生成机制，`truth`定义真值，`gfci`执行GFCI，`score`记录端点，`run`执行四方法。R实现SHA256为`ad2c6b04680826d1600aa3d5a2194a36da24fd0105df4a756b121ec9bd068617`。环境、包版本及Tetrad JAR身份保存在输入`protocol.json`。

实际后端复算在`results/graph-guided-20260929/historical-backend-replay`完成1280次搜索，`searches.jsonl`保存逐矩阵输出，`summary/completion.json`保存320份完成记录和文件身份。全部边和端点与原`results/graph-guided-20260928/algorithm-main/searches.jsonl`一致。`independent-verification.json`独立核查输入身份、骨架和X/Y端点，覆盖64组、每组20次。`results/graph-guided-20260929/structural-query-evidence`另保存查询合同、计数复算及精确见证；该目录自身只复算已有输出，不执行后端搜索。

## 具体机制和样本支持

C、Z、U分别独立服从Bernoulli(0.5)。X和Y各使用独立随机数，按以下logit概率生成。这里的行数为独立合成系统的数量，不能用同一提示的生成重复替代。

| 机制 | X的logit | Y的logit | 被查询的X/Y真值 |
| --- | --- | --- | --- |
| soft_direct | −1+2C | −2+2X+1.2Z | X→Y；C实际改变X |
| soft_latent | −1+2C+1.5U | −2+1.8U+1.2Z | X↔Y；C实际改变X，U同时影响X和Y |
| edit_direct | −0.5+U | −2+1.5C+1.5X+1.2Z | X→Y；C直接影响Y，X不受C影响 |
| edit_latent | −0.5+U | −2+1.5C+1.8U+1.2Z | X↔Y；C直接影响Y，U同时影响X和Y |

以下计数均为20次中的次数。完整端点正确要求两个端点都与该合成机制真值相符；未定圆圈、错误固定端点、漏边分别保存。计数来自`historical-recount.json`及独立后端核验。

| 机制／样本量 | FCI-JCI0 | JCI1／JCI12，各自计数 | GFCI |
| --- | --- | --- | --- |
| soft_direct／1000 | X o→Y：20；完整端点正确0 | X→Y：20；完整端点正确20 | X o→Y：19，X o–o Y：1；完整端点正确0 |
| soft_direct／200 | X o→Y：11，X o–o Y：6，X↔Y：3；完整端点正确0 | X→Y：16，X↔Y：3，X o→Y：1；完整端点正确16 | X o→Y：9，X o–o Y：11；完整端点正确0 |
| soft_latent／1000 | X↔Y：16，漏边3，X o→Y：1 | X↔Y：16，漏边3，X→Y：1；一次X/Y固定端点错误 | X←o Y：3，X o–o Y：11，X o→Y：3，漏边3；完整端点正确0 |
| soft_latent／200 | X↔Y：4，漏边15，X←o Y：1 | 与FCI-JCI0相同 | X o–o Y：6，漏边14；完整端点正确0 |
| edit_direct／1000 | X o→Y：20；完整端点正确0 | 与FCI-JCI0相同 | X o→Y：20；完整端点正确0；七次运行另含其他边的错误固定端点 |
| edit_direct／200 | X o→Y：19，漏边1；完整端点正确0 | 与FCI-JCI0相同 | X o–o Y：6，X o→Y：11，X←Y：2，漏边1；完整端点正确0 |
| edit_latent／1000 | X o→Y：9，漏边11；完整端点正确0 | 与FCI-JCI0相同 | X←Y：5，X o–o Y：3，X o→Y：1，漏边11；完整端点正确0 |
| edit_latent／200 | X o→Y：3，漏边17；完整端点正确0 | X/Y端点与FCI-JCI0相同；各一次运行另含其他边的错误固定端点 | X o–o Y：3，漏边17；完整端点正确0 |

soft_direct的1000行结果表明，JCI的增量落在系统内部的X端点：外生C对X的扰动配合观测独立关系，把X o→Y进一步确定为X→Y。这超出了预先知道C的随机方向。soft_latent中，FCI-JCI0已有16次完整端点正确，JCI没有增加正确次数；200行时三种FCI仅四次完整端点正确，且15次漏掉X/Y边。该样本量影响取决于具体效应强度、机制和检验，不能据此设定所有真实任务通用的200／1000行门槛。

edit_direct和edit_latent的X不随context改变，JCI没有在X/Y查询中增加完整端点。GFCI没有得到相同背景约束，因此本表包含背景知识与搜索实现两种差异，无法单独归因于算法名称。完整端点正确为零也不能解释为全部输出错误：保留圆圈的输出可以准确表示当前信息不足。

## 查询、假设、输出和决策

| 查询 | 假设与样本支持 | 算法输出及额外信息 | 对当前选择的具体作用 |
| --- | --- | --- | --- |
| 固定P/N完整编辑政策是否影响有限范围内的安全代码产出 | 政策全文、任务、随机分配和测量均冻结；使用全部已分配任务位置的ITT；开发264项分配和评价224项分配全部完成，原结果到任务向量及主要区间的独立复算通过 | 已知随机分配方向结合独立结果测量可估计政策效果；结构搜索不产生本轮效果估计 | 政策的合法性和准入无需等待FCI邻接；结果前固定动作，按原定ITT及区间评价 |
| context实际改变X时，能否确定X/Y端点 | soft_direct／soft_latent的同义变量、独立行、无环和相应JCI约束；各样本量20次 | soft_direct的JCI1／12在1000行增加20次X端点确定；混杂机制中没有相同计数增量 | 支持在具有实际X扰动和合格结构查询的设计中研究JCI；这些合成端点结果没有改变当前真实候选选择 |
| 随机政策直接影响Y、来源属性X保持不变时，能否推断do(X) | edit_direct／edit_latent的有限样本搜索，以及下述两个完整观测分布相同的SCM | 搜索未增加X/Y完整端点；精确见证进一步证明仅凭该类信息无法唯一确定do(X)效果 | 当前政策选择器以完整政策效果为训练目标；不得将来源节点解释为已经识别的致因，也不以搜索圆圈淘汰候选 |
| FCI、JCI-FCI、GFCI谁更适合真实提示结构查询 | 历史真实全表13—32行，小于原检验配置必要的40行；跨任务同义变量、额外识别查询及同背景基线尚未取得资格 | 当前合成差异不能提供真实任务上的普遍优胜判定；增加重复生成不增加独立来源属性数 | 保留`UNRESOLVED_STRUCTURAL_ALGORITHM_CHOICE`；新增真实结构搜索预算为零，不调整已冻结任务框和模型请求 |

前两项明确区分政策效应估计和系统结构识别。后续真实结构比较必须给出context实际改变的系统变量、同义测量、剩余直接路径、潜在混杂、CI／score资格及同信息直接基线；这些信息缺失时无法宣布三种结构算法中的优胜者。

## 精确不可识别见证

`results/graph-guided-20260929/structural-query-evidence/exact-witness.json`保存两个非退化SCM的精确见证。本见证使用Z指代随机context，与上表四机制中C的符号不同。令Z服从Bernoulli(0.5)，U、V、W为相互独立标准正态变量，且均与Z独立，Y为是否满足潜在评分大于零：

\[
\begin{aligned}
A:\quad &X=V,\quad Y=\mathbf 1[0.4X+0.3Z+W>0],\\
B:\quad &X=0.8U+0.6V,\quad Y=\mathbf 1[0.5U+0.3Z+\sqrt{0.91}W>0].
\end{aligned}
\]

两者都满足Z的随机外生性及Z与系统变量无潜在混杂；两者的完整观测分布相同：`X|Z`为标准正态，`P(Y=1|X,Z)=Phi(0.4X+0.3Z)`。A中将X从0干预为1的平均效果为0.1477733336，B中为零。两者干预Z的效果均为0.1097022222。

因此，当前随机政策没有改变编辑前X时，政策效果与X的因果效果属于不同查询。增加相同分布的样本可以提高估计精度，仍然无法分辨上述两个机制。此结论来自精确构造，不依赖有限样本搜索的失败。需要额外识别信息时，应明确实际改变的变量、剩余直接路径及跨环境同义测量；当前结构算法选择状态仍为`UNRESOLVED_STRUCTURAL_ALGORITHM_CHOICE`。

## 复算入口与证据边界

独立验证入口：

```powershell
.venv/Scripts/python.exe docs/experiments/2026-09-28-context-verify.py --output results/graph-guided-20260929/historical-backend-replay
```

精确见证与原输出计数入口：

```powershell
.venv/Scripts/python.exe -m prompt_mechanism_study.development.graph_guided_report results/graph-guided-20260929/structural-query-evidence --discovery-structural
```

相应冻结目录已存在时不重复写入；查阅现有材料。后端复算保留原输入身份和配置。数学见证不作为自然请求、真实提示安全效果或新模型实验的证据。
