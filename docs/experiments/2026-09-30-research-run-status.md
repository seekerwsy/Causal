# 2026-09-30研究执行记录

协议：`semantic-discovery-development-20260930`，见[现行协议](../graph-guided-discovery-protocol.md)。用户授权：“启动吧，授权允许”。Goal研究执行已按生成前科学停止规则结束；实际结果见[研究报告](2026-09-30-goal-result.md)。

开始：2026-09-30 02:43:42（Asia/Shanghai）。截止：2026-10-01 02:43:42。上限：392次Qwen请求、90分钟模型服务、2小时CPU实验；一次来源审计最多60项或2小时。Qwen只生成代码，Codex准备TSG、假设、绑定与编辑。

| 研究内容 | 当前状态 | 证据位置 |
| --- | --- | --- |
| 方案、资源和授权 | specified，启动身份已冻结 | `data/method/graph-guided-20260930/launch`保存协议和规范附件全文、SHA256与起止 |
| 结果盲来源身份审计 | executed，60项身份、17项可用来源，独立校验通过 | [来源审计](2026-09-30-source-frame-audit.md)及`data/method/graph-guided-20260930/source-audit/completed` |
| 共同测量原因及代表性验证 | executed，31项控制、146份代码重新测量、38份旧环境复测；148项原分配全部核对 | `data/method/graph-guided-20260930/measurement`及`results/graph-guided-20260930/measurement/verified` |
| 结构筛选与政策消费者 | executed、reported，510项搜索和252份消费者输出；独立复算通过 | [CPU结果](2026-09-30-structure-policy-results.md)及`results/graph-guided-20260930/cpu/independent-verification.json` |
| 语义准备、学习及有限面板统计 | 学习、提名、请求共享与区间已实现；七项聚焦检查通过；已暴露案例两流程合计15项编辑取得双重语义通过，测量可区分条件未通过；71项结果盲语义映射与37项训练已冻结，类别支持门槛全部未达到 | `src/development/semantic_discovery.py`、`tests/test_semantic_discovery.py`、[训练学习](2026-09-30-training-learning.md) |
| O/V冻结与科学辨别力 | 来源面板固定O=12、V=2；十四项来源共同接口与有限端点已指定并冻结准备输入；Case 02、03、12、17、19、30、31 两流程准备与独立语义评审完成。结果前登记的二十五个百分点解释间隔与现有任务数共同触发T1/T2/T3生成停止规则；观察资格和准备资源另行保留 | [生成前辨别力核算](2026-09-30-prospective-power-audit.md)、`panel-preparation-inputs`及`results/graph-guided-20260930/panel-review-analysis` |
| 新Qwen生成 | 已暴露开发任务Case82完成12次；O/V仍为0次 | [Case82开发诊断](2026-09-30-case82-development-result.md)及`results/graph-guided-20260930/development-case82-main` |
| 科学结果与独立复算 | CPU、历史训练、Case 82 实际生成及独立复算已完成；T1/T2/T3因前瞻精度门槛未执行，原科学验收保留未完成 | [研究报告](2026-09-30-goal-result.md)、[审查指南](2026-09-30-review-guide.md)、`generation-gate/decision.json` |

来源审计、测量资格、CPU算法研究由隔离子agent执行；来源审计不接收生成输出或旧政策效果。TSG／Raw准备使用同资源、仅有允许输入的新实例。既有冻结结果保留原身份。

实现核实命令：`.venv/Scripts/python.exe -m pytest tests/test_semantic_discovery.py -q`，实际结果七项通过。检查覆盖共享请求系数抵消、缺失结果界限、真实单版本P/R共享、随机子流与重放、任务等权类别均值、两层机会抽样、特征反号及精确文本编辑；这些结果只支持相应实现边界。按冻结的六个面板位置共同错误率核算，O完整配置半宽为0.477870，V完整配置半宽为0.827696；实际准入仍需真实分配表与科学解释间隔，见[生成前辨别力核算](2026-09-30-prospective-power-audit.md)。

CPU独立验证命令：`.venv/Scripts/python.exe docs/experiments/2026-09-30-structure-policy-verify.py`。验证覆盖3085项精确条件检验、53项条件抽样检验、93项总体有理数查询、5040项调参拟合和4350项政策拟合。实测搜索耗时13.593秒，新增Qwen请求为零。结构邻接选择在部分配置优于同维度随机子集；相对全属性消费者的收益不稳定，小样本遗漏有效属性时出现负收益。总体CI也会保留纯主效应属性，因此Y邻接不能直接解释为效果修饰变量集合。

来源面板中的V采用结果前固定的`password_hashlib_import`类别，两项独立来源；O保留十二项来源。原始开发者请求谱系未知，结论范围限于经核实的公开任务。Case82准备检查使用已暴露材料、隔离的新TSG与Raw实例；每流程两次请求共720秒，检查完整义务、开放机会和实际准备资源，单独保留开发检查身份。

Case82准备机械检查得到TSG的16来源单元、18节点、17关系、11机会、8项可物化编辑；Raw有16来源单元、10机会、7项可物化编辑。两名隔离评审均确认TSG八项与Raw七项提交机会的语义和真实编辑；两流程共享一项完整政策。全部二十一项的测量可区分条件均未双重通过，最终提名为空。TSG图的十七条关系均有来源依据，一项机会的支持子图额外包含与目标无关的固定要求。两流程实际模型均为`gpt-6-astra`、高思考设置。Raw在720秒内完成；TSG最终产物在期限内写入，但实例终止记录晚于期限9.183秒，资源合同记为不通过。该检查不产生公平的TSG增量结论。

Case 02 的固定GET上传接口已经对应有限文件写入观察器。事前冻结的五个真实控制程序已在`phase-graph-guided-measurement:20260930`隔离容器中运行并通过独立标签核对：正常保存与跳转为安全，普通越界写入以及写入后抛出异常均为不安全，拒绝全部请求与缺少入口保持未知。有限观察范围为工作目录中两个固定文件名探针；其余文件名及路径仍未评价。冻结输入位于`data/method/graph-guided-20260930/measurement/panel/case-02-qualification-inputs-v3`，观察和资格结果位于`results/graph-guided-20260930/panel-case02-qualification-v3`。尚未对新生成代码执行测量。

Case 02 的TSG和Raw准备各两次请求，实际模型均为`gpt-6-sol`、高思考设置；独立执行记录显示墙钟分别为583.554秒与561.804秒，输入输出与非缓存token均在冻结上限内。公共盲审材料包含17项机会，两名隔离评审一致通过TSG六项、Raw五项的来源语义、Atomic、真实版本与有限测量条件；两流程没有完全相同且均合格的政策。TSG独立图审计发现一个固定观察限定没有进入图，两处否定范围没有体现在`polarity`字段；新增写入禁令的子图只支持来源中的保存位置，须按ADD的来源锚点解释。上述信息尚未用于估计政策效果。

统一历史训练测量已将原先三个批次的744项分配与148项新有限观察逐一连接，得到71项候选P/N效果。独立入口`.venv/Scripts/python.exe docs/experiments/2026-09-30-training-uniform-verify.py`实际通过744项分配、148项重测及71项效果复算。六字段映射在读取这些效果前冻结，37项合格候选来自23项独立任务。文本学习器已按固定规则训练，类别最大独立任务支持为2，低于事前门槛4；因此本轮类别规则没有类别专属预测。独立核验入口`.venv/Scripts/python.exe docs/experiments/2026-09-30-training-learning-verify.py`已通过。

测量核实命令：`.venv/Scripts/python.exe -m prompt_mechanism_study.development.source_remeasure verify-launch-measurement D:/MyCode/Causal`。全部148项原分配保留，包含两项原生成失败。新的有限观察得到105项安全、8项不安全、35项未知；二十项从原未知变为安全可评价。这些变化提供测量覆盖的探索证据，政策效果需按原分配和新共同端点另行计算。全部旧冻结结果身份核对通过。

Case 03 的 HTML 表单端点在固定 `name` 与 `default` 探针上完成七个真实控制程序资格核对，细节见[观察器资格记录](2026-09-30-case03-observer-qualification.md)。TSG准备16个来源单元、六项提交机会；Raw准备21个来源单元、五项提交机会。两流程各两次请求，资源计量均通过。十五项公共盲审机会中，两位独立评审一致通过TSG六项、Raw五项；两流程没有完全相同且均合格的政策。TSG图关系和六项目标支持子图的独立来源审计未发现缺口，结果记录在`data/method/graph-guided-20260930/panel-graph-audit/case-03.json`。这些结果只评估准备语义和有限测量资格，尚无面板效果。

已暴露 Case82 的真实开发生成共十二次，模型服务计量67.172秒。原始提示、商品属性示例项目列表、删除整组属性示例各四次；每组的有限安全产出均为四次、普通功能通过均为四次、直接违规均为零。十二份代码仅有两种身份，且两种身份在三个条件中都出现。独立核验`.venv/Scripts/python.exe docs/experiments/2026-09-30-case82-verify.py`通过全部十二份请求、响应、代码与观察。具体来源、冻结分配、结果和解释范围见[开发诊断记录](2026-09-30-case82-development-result.md)。本诊断不提供TSG与Raw的总体优势证据。

Case 12 的TSG与Raw分别形成九项和八项开放机会，两名独立盲审一致认可三项与两项候选达到所审查的条件；两流程没有完全相同的通过候选。双方提出的SQL安全新增目标保留来源支持，但真实SQLite状态观察器尚未获得资格，因此未取得测量条件。TSG独立图审计发现一项删除目标的“仅在”限定强于所选来源条件分支，该候选的图支持不能算作完整。Case 12 的Raw准备计量只有一次顶层请求，资源合同不通过；语义审查结果保留，公平表示增量分析不纳入该案例。审查与图证据位于`results/graph-guided-20260930/panel-review-analysis/case-12`及`data/method/graph-guided-20260930/panel-graph-audit/case-12.json`。

Case 17 两流程资源计量通过；两名独立盲审对各自五项提交机会的来源支持、完整目标、Atomic边界、非目标保持和真实版本均一致通过。来源专用HTML/refresh观察器尚未获得资格，因此双方五项机会的测量条件均未通过，完整合格提名均为零。出现方向相反而完整目标相同的跨流程政策，后续共享请求必须按全文与方向核算。审查结果位于`results/graph-guided-20260930/panel-review-analysis/case-17`。

Case 19 两流程各两次请求且资源计量通过。TSG 提交三项、Raw 提交三项可物化编辑；两名独立盲审对六项的来源支持、完整目标、Atomic边界、非目标保持和 P/N 版本均一致通过。真实 `buy_function` 调用、参数与 SQLite 状态尚无合格的非替代式观察，因此六项的测量条件均未通过，完整合格提名为零。TSG 的 SQL 安全新增机会具有表单值进入数据库的图锚点；安全关系本身是新增目标，不能写成原图既有关系。审查位于`results/graph-guided-20260930/panel-review-analysis/case-19`，图审计位于`data/method/graph-guided-20260930/panel-graph-audit/case-19.json`。

Case 30 两名独立盲审一致通过 TSG 八项、Raw 五项提交机会的来源语义、真实版本和可区分预测，双方没有完全相同的合格政策。实际准备资源中，TSG 的输入输出 token 合计为2,012,597，超过同案两流程共用的2,000,000上限；Raw为1,920,485。该案例不进入公平表示增量分析。当前日志端点仍缺少合格的真实 handler/formatter 覆盖观察器，盲审中的可区分预测不能直接转为安全效果测量资格。审查位于`results/graph-guided-20260930/panel-review-analysis/case-30`，资源计量位于`data/method/graph-guided-20260930/panel-preparation-accounting/case-30`。

Case 31 的完整 HTML 字面文本要求在共同接口中继续表达，因此 TSG 与 Raw 均将完整 REMOVE 保留为未解决。两名独立盲审一致通过 TSG 三项与 Raw 三项提交机会的来源语义和版本，双方没有完全相同的合格政策。TSG 准备输入输出 token 合计3,099,590，超过同案两流程共用的2,000,000上限；Raw为1,492,060，因此该案例不进入公平表示增量分析。来源专用返回字典与 HTML 字面文本观察器尚未获得资格。审查位于`results/graph-guided-20260930/panel-review-analysis/case-31`，资源计量位于`data/method/graph-guided-20260930/panel-preparation-accounting/case-31`。

V 的 Case 25 已完成 TSG 与 Raw 来源准备和编辑物化机械检查。`import hashlib` 线索的 N 文本仅删除来源中的导入声明，来源 KDF 参数和共同接口继续生效。两流程输入输出 token 合计分别为3,734,197与2,227,936，超过各自2,000,000的同案上限；该案例尚未进行独立语义盲审或新代码生成。V 的 Case 53 未启动准备；生成前科学辨别规则已独立阻止 V 生成。资源计量位于`data/method/graph-guided-20260930/panel-preparation-accounting/case-25`。
