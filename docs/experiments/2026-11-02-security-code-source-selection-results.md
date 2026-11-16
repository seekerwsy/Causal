# 原始安全程序来源身份固定结果

依据[固定准备设计](2026-11-02-security-code-source-design.md)，已取得公开目录100项身份，使用Git原生命令核对CSV对象 `f6e37ec7f618d391d8d1058aba47d6f9b8570229`，使用PyArrow 23.0.1解析。24项身份按固定摘要与仓库URL分组规则在任务程序、测试或补丁读取之前固定，选择未使用Graph、JCI或模型结果。

列表第一项为 `CVE-2025-22153`，来源仓库为 `zopefoundation/RestrictedPython`，修复提交身份为 `48a92c5bb617a647cffd0dadd4d5cfe626bcdb2f`，原始父提交为 `f4c1c1b5d31866de61c09143f3b009bfe8b2a0a0`。完整源码和测试已取得并逐项核对206个Git对象。该任务已完成指定语法策略及局部功能的成对测量，Atomic资格继续未建立。全部24项保留，不因后续失败替换身份。

身份列表已固定；代表资料准备状态为 `VERIFIED_SOURCE_QUALIFICATION_ACCOUNTING`。已取得一个自然任务的两个完整源码版本，合计44次原始及适配测试执行，代码生成调用为零。没有正式角色分配或新增组件收益。24个URL组不自动等于24个独立代码谱系，其余23项身份仍未取得具体任务资料，重定向、同源关系及资格缺口继续保留。

已完整阅读该任务的[上游安全公告](https://github.com/advisories/GHSA-gmj9-h825-chq2)。公告将try/except*相关的解释器问题与绕过限制联系起来，也指出部分Python版本已修复上游问题。因此，后续必须区分语法拒绝策略检查与实际绕过检查，不能默认当前Python环境能够复现漏洞。元数据保存在representative-metadata.json及representative-context.json；自然任务文本和单项干预尚未冻结，Atomic资格继续未建立。

[成对测量结果](2026-11-02-restrictedpython-source-qualification-results.md)保留了原始版本的策略断言失败，以及两个版本分别21项非目标检查通过。该结果只支持指定策略和局部功能范围，实际漏洞利用和完整功能性继续未知，尚未提供模型基线或表示比较结果。

`selection.json` SHA256为 `c1b0f8e5d73b340c5fc870e71377d8f2eb559e2b6629b086a64ea09ff6e4eab0`。冻结材料为 `results/security-code-source-selection-20261102-frozen.tar.gz`，大小15552字节，SHA256为 `00eb7ca35571eb2f0fe0fea7aee924ebed4d798a723f0248542c462ae50ddb8e`，包含完整目录、作者MIT许可证、选择程序、设计与共用记录工具。

在 `.test-tmp/security-code-source-selection-replay-20261102`独立解压，使用包内共用源码和当前Python 3.12.14、PyArrow 23.0.1重新执行 `prepare_sources.py`，实际身份列表与原输出逐字节一致。复算继续只读取元数据，没有新增具体任务资料暴露。

## 固定第三项来源的开发准备

按既有顺序继续取得 `CVE-2019-10800`，仓库为 `codecov/codecov-python`，固定修复提交为 `2a80aa434f74feb31242b6f213b75ce63ae97902`。依据在其程序读取之前保存的 `source-parent-rule.json`，原始候选为修复提交的第一父提交 `73b1b138ec40912eee6fed02636be6011105706e`；此规则不证明候选确实存在漏洞。原始提交元数据及完整文件清单已取得，目录树为 `f0371e79ebc8a370967917bd204688c7ff08e8f2`，包含18项文件。

本段在原始程序内容读取之前保存，记录新的方法开发暴露范围。随后只按该固定提交取得原始程序和公开合同，再进行来源资格判断。不会依据Kedro或其他方法结果替换来源、改变父提交、选择更有利的程序版本或增加获取轮次。修复程序、测量答案和方法输出不得进入后续表示制作上下文。该来源尚未获得语义、执行、代码生成或正式协议资格。

实际取得原始归档22938字节，SHA256为 `521bc6761dd9f012f5d3d8034e92ff0de667268ac50148dfdcf6d6c2bd5fe8d3`。完整18项文件均通过Git对象核对；方法来源记录仅包含两个原始包文件、README、安装说明及Apache许可证，不包含测试或修复实现。源记录为 `codecov-source.json`，摘要 `156386348fa90f0f672eb54a8eddd9f659aa6958839612a0cab16f5157543366`。

独立上下文仅阅读该原始来源，对操作解释、安全边界、可观察非目标行为及局部语义上下文充分性四项均判定supported，保留八项逐字证据。独立核对状态为 `VERIFIED_FIXED_CODE_COVERAGE_SOURCE_AND_REVIEW`。评审摘要为 `59a65d7022246258bc56c21d1fb608b8a963f02e5bedafd7e4ad527c62d07954`。这些判断允许准备受控任务，未执行该程序，没有Oracle或代码生成资格，也没有Graph收益。

来源可追踪 `--gcov-root`目录字符串进入find命令，并通过默认shell=True的执行过程传递。配置执行程序、普通选项、排除模式和其他git/hg操作的角色分别保留，后续干预需要明确普通配置语义及局部可观察行为。没有自然编程请求，基准要求表达状态继续unknown；不能由候选漏洞版本推断生成模型基准不安全。原始测试只核对字节对象，未进行语义评审或执行；原始候选是否实际存在所指问题仍未验证。

第三项来源准备包为 `results/codecov-source-preparation-20261102-frozen.tar.gz`，60698字节，摘要 `831488ecd7d969374e27df39a43676304cbbf23bb6298c4a5bb982ff2328d3ea`。在 `.test-tmp/codecov-source-preparation-20261102-replay`独立解压，使用包内来源、原始归档与共用记录工具重放 `verify_codecov_source.py`，核对输出与原件逐字节一致，摘要为 `ba1d21e40fe0d844b0dbf7fd2cd4d53a86e5174a676bd219f14933cdfd8a196d`。该重放只核对真实来源与评审记录，没有执行候选程序或增加实验样本。

独立的[局部执行资格检查](2026-11-02-codecov-directory-contract-results.md)已随后完成：原始模块11／14项局部功能通过，六种目录均实际产生额外命令；作者参考控制14／14项局部功能及6／6项策略检查通过。控制资格与早先静态来源核对保持不同证据身份，不更改旧资料的执行状态，也不提供模型或Graph收益。受控任务文本为 `codecov-task-source.json`，摘要 `d615435023649fcceb855a9a43a7817ae67af172b82f7f58d91dc765486e0251`；来源程序、作者基准说明与新增单项要求分别记录，独立任务审查使用单独的新上下文。

独立任务上下文只取得任务来源和审查说明，未取得测量、参考实现、修复或方法产物。六项来源条件全部supported，作者基准对完整目录shell操作隔离策略的表达状态为not_expressed。基准同时保留特殊字符目录的功能要求，该功能要求与安全策略存在联系，不能将not_expressed解释为没有任何目录功能约束。缺少自然编程请求、前导连字符、符号链接、并发改变及未声明目录条件的覆盖均保留。

任务审查摘要为 `53a168dc52bf2e87d8835f3ae190e23ebfcddd9d1f97609a1e47d04ca8464acb`，独立核对入口为 `verify_codecov_task.py`。其输出状态 `VERIFIED_INDEPENDENT_CODE_COVERAGE_TASK_REVIEW`，`.controlled_atomic_add_preparation_permitted=true`，允许准备同范围受控ADD。`.independent_human_reference=false`、`.code_generation_qualified=false`、`.graph_gain_established=false`，没有赋予总体表示收益或正式资格。

受控任务完整来源包为 `results/codecov-task-source-20261102-frozen.tar.gz`，84424字节，摘要 `2dc835c06f7c55919b6cd956ce6f6ed13bf6ccbb8d6b22d8a90a342efa149f68`。在 `.test-tmp/codecov-task-source-20261102-replay`独立解压，使用包内来源、审查和共用工具重放任务核对，输出与原件逐字节一致，摘要 `e2546ea8fd477bac42b8ed51d2e9d7c1ff8c8901eda74909121d44aa86595138`。自动上下文参考保持自动评审身份，不标记为独立人工资料。

## 固定第四项来源的开发准备

在Codecov固定生成持续执行、其候选内容与效果尚未读取时，继续按原有身份顺序取得第四项CVE-2024-52303，仓库aio-libs/aiohttp。固定修复提交为 `bc15db61615079d1b6327ba42c682f758fa96936`；依据此前冻结的第一父提交规则，原始候选为 `158bf304bdd8047eec192540fa5bf7fe3862bffd`。本段在该候选程序读取之前保存，限定新的开发暴露。

只取得该固定原始提交的元数据、完整目录和程序，不取得修复实现，不依据Graph、JCI、模型结果或测量资格更换身份或父提交。该身份尚未具有来源语义、局部Oracle、作者任务或代码生成资格。既定24项身份及全部先前结果保持原值。

实际原始归档954575字节，SHA256为 `ff07fff48e8c8a8a34bac18eb289091d8d1e148a5a2b6342c854a98d6c152e19`。完整284项Git blob均使用Git原生命令核对，其中两项符号链接只核对链接文本，没有创建或跟随链接。独立使用Git mktree重建全部19个目录对象，根目录对象为 `330c024aa3b8a3d664fd99d10c11ed10f2ec7830`，与固定提交一致。

原始树还包含一个vendor/llhttp子模块提交，源码尚未取得，状态原样保留。归档核对不认证子模块、编译依赖或运行配置完整。原始快照记录为aiohttp-source-snapshot.json，摘要 `8b38e4932db47a8238f1a3b14ec8b41da7e3d035837e5b26769d5bafdb4471a4`；独立核对为aiohttp-source-verification.json，摘要 `7cf2900743209b1472f81893a5395c935100ce744e7573602b3f21444c782a44`。这两项快照核对只认证来源字节和目录身份，没有执行来源程序，也不提供语义、Oracle或生成资格。

第四项完整快照准备包为 `results/aiohttp-source-preparation-20261102-frozen.tar.gz`，1010606字节，摘要 `0a9b1e953e72f4b61b3a58d95ccad8d5dbf40744ecaab89207d1c831dec2230a`，本地与服务器归档一致。在 `.test-tmp/aiohttp-source-preparation-20261102-replay`独立解压，使用包内原始归档与实现重新核对全部284项blob，再由独立核对器重建19个Git目录；快照与独立核对输出分别逐字节复现 `8b38e4932db47a8238f1a3b14ec8b41da7e3d035837e5b26769d5bafdb4471a4`和 `7cf2900743209b1472f81893a5395c935100ce744e7573602b3f21444c782a44`。重放没有读取程序语义、创建来源符号链接或执行来源程序。

第四项的[来源语义与真实HTTP检查](2026-11-02-aiohttp-runtime-profile-results.md)已完成：独立上下文支持局部操作、安全边界及可保留行为，上下文充分性保持unknown；缺少自然编程请求及尚未固定的任务与测量条件分别列出。原始候选在已固定纯Python aiohttp配置中完成八项真实HTTP请求，功能检查全部通过，四次错误请求分别增加一个缓存条目，重复正常请求复用原条目。该局部现象不提供内存耗尽、完整HTTP功能、Atomic、Oracle、代码生成或Graph收益。原始快照、独立语义和实际运行保持各自证据身份。

## 固定第五项来源的读取范围

2026-11-03按既有24项顺序继续准备CVE-2019-1010017，仓库savon-noir/python-libnmap。固定修复提交71b707758851e4b622f87d9a73266e06f60aeab4的第一父提交为cf1aee77980b295e2d632dbedea1cb3abf661c9a，来自既有remaining-source-metadata.json。沿用此前固定的第一父提交规则，不根据已取得的Graph或JCI结果更换来源。

本段在取得该原始提交的具体程序内容之前记录。允许读取该原始提交元数据、完整树与源码及其公开来源说明；修复代码、测试答案和后续方法产物不提供给表示制作。固定身份尚未取得来源、任务、测量或代码生成资格，其候选是否可用与是否实际存在漏洞分别保留未知。

已取得固定原始归档375614字节，摘要c9d41b365180f6e531de3ab4b27f6631ba21002d954f9feb3360dcd28c5ac4ae。完整94个blob逐项通过Git原生对象核对，独立Git mktree重建11个目录，根对象9ae8b43489dd4f5f908b93396f389a5a97f916de符合原始提交。没有执行来源、取得修复程序或建立来源语义与测量资格。

记录位于fixed-sources/CVE-2019-1010017，snapshot摘要ba4a531ec8722e89438a048804689401d34be85633c1642fc9c08e0557ae5865，独立核对摘要8f4836e0d81936eed06b440942607abd429993881950a755a99edb5eab6db10b。prepare_fixed_source.py和verify_fixed_source.py沿用同一固定身份、第一父提交规则及成熟归档解析，复用共享文件摘要逻辑，适用于后续固定身份。它们不筛选方法或模型结果。

冻结包results/libnmap-source-preparation-20261103-frozen.tar.gz大小395291字节，摘要848036b48cf5ef7016c9f248d699afd587d61160002253046684980951a42d33，本地与服务器archive相同。归档保留原始源码包、元数据、完整树、固定选择规则、核对结果及实际核对实现。字节身份核对与语义理解、实际运行、Atomic准备及组件收益分别报告。

已准备十四项原始文件及公开CVE描述的完整context.json，不包含测试和修复程序。独立自动上下文只读取该来源，支持公开XML操作及局部非目标行为；没有执行程序。三个公开入口parse、parse_fromstring、parse_fromfile共同进入XML解析操作。评审建议研究者制定单一实体声明拒绝要求，并保留四种已支持根节点、文件输入、incomplete补全、普通DOCTYPE、转义和注释等行为。该建议尚未成为固定任务或合格测量。

来源存在明确缺口：libnmap/__init__.py声明0.6.1，setup.py声明0.7.1，公开描述的受影响范围为0.6.3以前，当前提交与受影响发行版本的对应关系未知。CVE描述涉及XML解析资源消耗，没有指明实体声明机制；现代Python对放大载荷的保护也尚未测量。因此，实体声明拒绝的局部政策实验不能称为CVE利用或资源消耗改善。source-review.json保留自动身份、九项逐字引用及未知状态，原始快照与字节核对记录保持原值。

该来源随后完成[公开入口的局部控制测量](2026-11-03-libnmap-entity-contract-results.md)。Python 3.12.16、Expat 2.9.0下，原始程序实体声明拒绝0/12，作者参考12/12，两者局部功能39/39，共102项检查并完成独立核对。被引用普通实体实际进入原始返回对象的owner字段；该观察只支持规模受限输入的实体处理，不证明放大载荷或资源耗尽。版本归属、自然请求、完整功能及Graph收益的缺口继续保留。

## 固定第六项来源的读取范围

2026-11-03继续按照既有名单准备CVE-2022-29217，仓库jpadilla/pyjwt。固定修复提交9c528670c455b8d948aff95ed50e22940d1ad3fc的第一父提交为24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc，来自原有remaining-source-metadata.json及共同第一父提交规则。本段在取得该提交的具体源码之前记录。

随后只取得固定原始提交的元数据、完整树、源码和公开问题描述；不读取修复程序或测试答案，不根据Graph、JCI或先前来源结果替换身份。当前没有该来源的任务、语义、测量或生成资格。固定24项名单及此前全部结果保持原值。

实际取得原始归档62921字节，摘要2d5130b490fc41655321f162f77caf7d0b167d9a438242945d98e3f3fc0d5057。完整76个blob通过Git原生核对，独立重建九个目录对象，根对象e8496fb90c15e9f45bb89476ed70f8bd3abd72af与固定提交一致。snapshot.json摘要7ad164163a7f6dabd2c01d8353b105a750113c3cb8082e4b382feceb28699f68，verification.json摘要38fa1f1b588d34e57bbd363582d79ad3a67cd253c7bf46195d63d75893642414。

context.json保留十五项原始程序、API说明、许可证与公开CVE描述，共78185字符，摘要3fac083a005ef7c5d7bd20a9aff4adea41f5c491deedeef63b949b6f6e937fe8。没有包含测试、上游修复或模型输出。来源安全边界及Atomic语义已完成独立自动上下文审查；不能从存在安全问题推断提示要求缺失。

原始来源准备包为results/pyjwt-source-preparation-20261103-frozen.tar.gz，107681字节，摘要72f5d6e47c6b73754f47060beaa737aa30063466d2a541a9a5c9312c51bcb24d，本地与服务器archive相同。该包固定源码、共同来源规则和核对实现，没有来源执行或后续审查结论。

独立自动上下文已完成来源审查。源码明确写明非对称密钥或x509证书不应作为HMAC secret，公开API合同另规定允许算法配置及避免混用对称和非对称算法。因此，这条要求的Atomic ADD资格不成立；过滤范围不足不能改写为要求缺失。既有要求可以识别，但REMOVE提示文本、编辑范围及等价表述处理尚未固定，不能直接取得REMOVE资格。source-review.json保留十项逐字引用，全部已与原始来源核对。

本来源没有执行程序、调用模型或取得测量资格。它保留在24项来源记录中，不作为新增安全要求缺失的样本，也不根据该判断寻找替代身份。修复既有要求的实现、增加一条原本缺少的提示要求，以及测量Graph表示收益，具有不同研究含义。

## 固定第七项来源的读取范围

2026-11-03按固定顺序继续准备CVE-2025-62708，仓库py-pdf/pypdf。固定修复提交e51d07807ffcdaf18077b9486dadb3dc05b368da的第一父提交为f2864d6dd9bac7cecd3f4f54308b25ebbfa178f8，来自原有remaining-source-metadata.json及共同第一父提交规则。本段在取得该提交具体程序之前保存。

允许读取固定原始提交元数据、完整树、原始源码与公开问题描述，不取得上游修复、测试答案或模型输出。来源资格、Atomic语义、局部测量及生成资格分别检查。不能依据已取得的Graph、JCI或其他来源结果替换此身份；24项固定名单保持原值。

固定原始归档8098205字节，摘要1da478fb88ca5acd5f5203a7bb48f96628637ad67196ed68ae1668bde5c599c8。完整288个blob通过Git原生核对，独立重建25个目录，根对象becd4e9c356153c973d20b82fc5cdae42c3ca594一致。snapshot摘要f79a0e00b4f625dc322a34d65ec7fe32e015ff149683c42c0e54af1933d7875f，verification摘要89d0f9de44d9d69fff9c17785579e51d5196c7d0d8c48a5dcf0385374e380dad。

context.json保留十二项完整原始文件及公开描述，共185727字符，摘要300ef7fb7a07a2ceac859d975b76eb6a705c88d3d3e1a8e8b1a5cff2c33b695f。独立自动审查支持LZW操作、三个真实输出写入位置和外层分派。来源已经表达普通内存风险及zlib输出限额，研究者新增要求明确限定为LZW单次解码在超限写入之前终止。具体局部测量固定16384字节、等于限额允许返回，使用模块常量LZW_MAX_OUTPUT_LENGTH。自然编程请求和代码生成任务资格仍然缺少。

source-review.json保留自动身份、十一项已核对逐字引用及未知。完整进程内存、字典与临时字节对象、缓冲区内部容量、多个流的累计，以及返回后长度检查和解码期间写入限制分别解释，不能混称同一保证。来源归档为results/pypdf-source-preparation-20261103-frozen.tar.gz，8182465字节，摘要2c73febda9f38c30c6acf9ae02a58e9907d6e18efe5ca596cbba31a789548ea7，本地与服务器archive相同。归档身份只包含审查前的来源准备，不提供执行或组件收益。

[实际控制测量](2026-11-03-pypdf-lzw-contract-results.md)已完成：原始、写入前参考、解码后参考共144项，三者局部功能均33/33；安全分别0/15、15/15、0/15。解码后参考虽然抛出相同异常，仍实际保存全部超限输出，测量正确区分了执行时点。八份编码输入由独立PDFMiner解码核对，三处写入和12位码宽有实际观察。完整结果和独立核对已冻结并在新目录复核，归档摘要7d266a9e787a8026ac78164f6f9a3696baba371290754016fe4f6b6788fc647f。此资格没有模型输出、Graph或JCI收益含义。

## 固定第八至第十项来源的读取范围

2026-11-03按原名单继续取得以下三项固定原始提交。本段在具体程序取得之前保存，来源身份和第一父提交来自原有remaining-source-metadata.json，不使用方法表现选择材料。

| 序号 | 来源 | 仓库 | 固定第一父提交 |
| --- | --- | --- | --- |
| 8 | CVE-2023-25577 | pallets/werkzeug | cf275f42acad1b5950c50ffe8ef58fe62cdce028 |
| 9 | CVE-2025-54121 | encode/starlette | 540ff5f076468eb69f827e76cb020e21fb39b3ca |
| 10 | CVE-2025-24359 | lmfit/asteval | b57e8c07fe5e8cdde6e2f569e4b5a2e5e413890d |

允许取得原始提交元数据、完整树、源码和公开问题描述；修复实现、测量答案和模型结果不进入来源或表示制作。三项分别审查已有要求、研究者新增任务、非目标行为及局部测量可行性，不能从漏洞描述推断要求缺失。缺失或不合格来源保持原身份，不替换24项名单。

三项完整原始来源和独立自动审查均已取得，各自九项引用逐条通过核对。Werkzeug原始归档847766字节，摘要968b74ccb3aff926b25d7d4e6d7d245d50dbe0f282a272b70a1b122d2ea1ddc9，295项blob和57个目录通过原生Git核对；十二份上下文文件189951字符，摘要b94877852644b4abff8ed79c3ce039d0989780d80a62ce01f5627a5ed4a918f4。可准备字段与文件合计数量限制，完整任务和测量尚未固定。

Starlette原始归档2583316字节，摘要f55e956b05540eba270e22c560bbb898b87e30f8d00cb1d2c3e774dd8dc4ec62，124项blob和14个目录通过核对；十二份上下文文件65796字符，摘要e1aa440fd615464830681f34a14c2a943966e5099cdd43deb6ce44f5d4c93a16。仓库迁至Kludex/starlette，origin-location.json保留同一数字仓库身份138597372和同一原始提交，没有替换来源。其线程执行要求已经表达，不具相应Atomic ADD资格。[真实局部测量](2026-11-03-starlette-upload-contract-results.md)完成78项控制检查及独立核对，允许准备固定政策的表示组件任务，没有表示或模型收益。

Asteval原始归档47034字节，摘要9e341784b53fa061468260a3f9f0ad889323b77a43d534a500999c2d5272df69，25项blob和8个目录通过核对；九份上下文文件102088字符，摘要7761173eb91dfa2c6ed8ddf3fb8f9972fc5a226b50dca0c6ff0019eb8d3f4026。来源已有受保护属性访问限制，不具相应Atomic ADD资格；格式化与异常路径的实际测量、完整任务和表示比较尚未完成。API文档与实现对直接str.format的不同说明保留，不能将该方法擅自恢复为非目标功能。

## 固定第十一至第十三项来源的读取范围

2026-11-03按原名单继续准备以下固定原始提交。本段在对应程序取得之前保存，依据原有第一父提交规则，不使用Graph或JCI效果选择来源。

| 序号 | 来源 | 仓库 | 固定第一父提交 |
| --- | --- | --- | --- |
| 11 | CVE-2025-59940 | mondeja/mkdocs-include-markdown-plugin | 1ae8fca510cb5b18f164aaefb855a07f522ec8ff |
| 12 | CVE-2023-41040 | gitpython-developers/GitPython | 830025bbfabc079ff803491920c2453dee4ce24f |
| 13 | CVE-2022-2888 | octoprint/octoprint | b83b57406eebca60432fbdcb54f8e7791b377e5b |

读取限于固定原始元数据、完整树、原始程序与公开问题说明；不取得修复程序、原有测试语义、测量答案或模型输出。缺失、已有要求、局部测量不合格及未知均保持原身份，不增加获取轮次或替换名单。来源任务、测量与表示效果分别判定。

第十一项原始归档62663字节，摘要63bce57b7dd533e06fb6a4f74aac8a89204b451c2e59534ea0b0e04519677ada，97项blob和41个目录对象通过Git核对。十二份原始文件94695字符，context摘要20aafa0de496f28ff6cace0c3fe1ad753c183e89abc12d386c0deb19422b4bee。独立自动审查保留十项已核对引用：输入文字与内部登记位置的身份边界可解释，递归层各自编号，最终恢复按登记顺序搜索整段当前文本。公开问题已经表达碰撞要求，完整文字保留合同和真实输出测量仍未固定，没有Atomic ADD缺失要求或Graph收益证据。

第十二项原始归档484431字节，摘要9898786124e79abf1ce1e83fbdd2911734f80aef57e1331164d54e5d7922ed88，180项blob和18个目录对象通过核对。十四份文件255656字符，context摘要533866fa89c4a4978cf01c75a04e436ceeaaf191d66820902487ec6ad6ca35d1。独立自动审查保留十项已核对引用，区分工作树git_dir、共享common_dir、直接引用、递归目标和packed-refs。来源已有相对路径及越界读取问题表达；完整任务需明确可信根目录、文件系统链接及读取前拒绝的测量边界。实际读取、完整功能和Graph效果尚未评价。

第十三项原始Git归档6236053字节，摘要b877e805cf5f55db6bb28394788b60ad85a9a3974cd485eaa0806472a7b24c56，全部875项blob和218个目录对象通过核对。GitHub原始元数据给出的仓库大小写为OctoPrint/OctoPrint，与固定名单身份相同。原始.gitattributes对_version.py指定export-subst；用于Git对象核对的归档保留该文件在同一原始提交的准确blob字节，其余原始文件不变。codeload资料及逐项来源说明保存在source-acquisition.json，没有更换来源或父提交。

第十三项十一份原始上下文文件325075字符，摘要e8f5134a7e4fd6660b807fa62db4e78e8c6f53b7848282ec125b4cc41328a8df。独立自动审查保留十项已核对引用，区分内存会话删除、持久账户查找、session cookie、remember cookie及API key；来源已有条件性当前密码核验要求，没有明确规定修改密码后撤销全部旧cookie。实际重放、依赖与配置、完整任务及测量尚未完成，没有执行原始服务或取得Graph收益。

三项完整来源、独立审查、共同准备与核对程序已冻结为results/fixed-sources-11-13-20261103-frozen.tar.gz，13342733字节，摘要fac0b6afecfd260f13da3e9f1bb9e60885f1ff5275f580a04521d22d0ca65060，本地与服务器archive相同。该归档为来源准备身份，没有来源程序执行或表示效果资格。

## 固定第十四至第十六项来源的读取范围

2026-11-03继续按固定名单准备以下原始提交。本段在对应程序读取之前保存，原始身份仍来自共同第一父提交规则，不使用新方法结果筛选。

| 序号 | 来源 | 仓库 | 固定第一父提交 |
| --- | --- | --- | --- |
| 14 | CVE-2023-47163 | remarshal-project/remarshal | d95a1846b9e54efeb570ce80f93f24ab13db9976 |
| 15 | CVE-2024-34078 | matthiask/html-sanitizer | 207a8927b6d09a37054ba7304a003e1ab2da2290 |
| 16 | CVE-2023-32681 | psf/requests | 302225334678490ec66b3614a9dddb8a02c5f4fe |

只读取原始元数据、完整树、程序及公开问题描述，不获取修复实现、原有测试语义或模型输出。每项分别记录已有要求、完整研究任务、局部测量资格和表示效果，保留缺失与未知；不替换来源或增加获取轮次。

三项原始来源和独立自动审查均已完成。Remarshal原始归档27482字节，摘要9b85277bc7c2fb9a9f4fdda9b8de74e01d8cb42a5ed7acfeaeafd67dac6991ea，43项blob、四个目录；四份上下文文件31810字符，摘要5553876e1b2f88ac81c02d46d7f0d1583edac87fb3c81d0f12c6375bd96114ed，十二项引用通过核对。YAML解析、JSON/TOML递归转换及其他编码入口分别记录，有限展开和循环政策仍为待固定的研究者提议，没有实际DoS或测量资格。

html-sanitizer原始归档16573字节，摘要ca2bafeece307a4170f96f5999f6abcdcd85fdd3269722adf45e0f072643d6a4，十四项blob、四个目录；六份文件24715字符，摘要2ecb6a42ee22666ecdb684bbe2c7a38c6dfd0978df81fd31fdb2c17bbb658c22，十一项引用核对通过。来源已有安全allowlist与规范化要求，当前静态顺序为最终Cleaner、序列化、完整字符串NFKC/NFC、返回；最终结构或浏览器执行尚未测量，不具对应缺失要求ADD资格。

Requests原始归档4035299字节，摘要aea3d22a5e587b375bde91cc4efc179bd382edd92ddb5adaab26547c26dfa8fd，100项blob、十五个目录；十六份文件215496字符，摘要48c689055123576a83ba95823afc7e0ccad66203fab579675c9a685681fe4bbc，十二项引用核对通过。来源已有代理与CONNECT隧道内部认证边界，PreparedRequest头部变换为静态事实，真实目的服务是否收到凭据仍未知；需要精确依赖和实际代理传输测量，没有新模型结果或Graph收益。

三项准备资料已冻结为results/fixed-sources-14-16-20261103-frozen.tar.gz，4245218字节，摘要3f40905219ab86f01140db638f6c9be528ea6898633c4aca4466ce3eeadfa307，本地与服务器archive核对身份。来源程序未执行，尚无任务、测量或代码生成效果资格。

## 固定第十七至第二十四项来源的读取范围

2026-11-03继续读取固定名单余下八项。以下提交来自原有共同第一父提交规则，在具体程序读取之前保存；不增加获取轮次、不替换名单，不依据方法结果选择有利版本或任务。

| 序号 | 来源 | 仓库 | 固定第一父提交 |
| --- | --- | --- | --- |
| 17 | CVE-2021-32839 | andialbrecht/sqlparse | e66046785b816e5c2d22f101f36faefd19c4a771 |
| 18 | CVE-2024-47164 | gradio-app/gradio | c12f600a984bdc269ba3e6db30e3b62186170ab0 |
| 19 | CVE-2025-6176 | google/brotli | b01b63a467315186a76eae62d84bbd350ca5ccb4 |
| 20 | CVE-2020-6802 | mozilla/bleach | 8d416c5ee780efe5daa237368bd9bd1b1af75c12 |
| 21 | CVE-2017-16615 | thanethomson/MLAlchemy | 5736ec6ce1fbc9e5bd732204f04c8c01ab34415f |
| 22 | CVE-2024-37891 | urllib3/urllib3 | 29cfd02f66376c61bd20f1725477925106321f68 |
| 23 | CVE-2025-58438 | jjjake/internetarchive | a3e45e23bb9482d5049cbe3725dd7db9929298b6 |
| 24 | CVE-2024-6844 | corydolphin/flask-cors | e970988bea563e05e8b8f53fa7bcc134b5bf5c5f |

读取仍限固定原始元数据、源码和公开合同，不获取修复实现、原有测试语义、控制答案或模型输出。对每项分别判断完整任务、支持语言与具体端点、实际环境和局部Oracle资格；已有安全要求、缺失、不可执行或未知均保留。不要求实现与本项政策无关的全部服务、界面或语言功能，也不将局部资格写成完整项目安全。

余下八项完整原始身份及隔离自动审查均已完成，逐字证据已逐项核对。其控制程序和模型代码均未执行，来源资格、任务准备和实际测量保持不同状态。

| 来源 | 已核对blob/目录数量 | 原始归档SHA256 | 当前完整审查上下文SHA256 |
| --- | --- | --- | --- |
| sqlparse | 73/9 | aa428a096f6a2edb0f9be3e9dcbf815367a491a94727c4cbbaf966fd4adeb449 | 256aa12a866c18a5c7c5090fbbcfd659071e1b50d14d889883a7c89390001f60 |
| Gradio | 2483/615 | 9e99e213af5b7c96c9569afdd18fe9c4fbfb15e4bd284f524736de5e435e4890 | e3e10c129752836b1ff3e180e240963eaef6c49a91110ae2672f4e8d80e0cd47 |
| Brotli | 373/41 | d8dd99bdaea4f23d9324ed11bab38ffcaa141e0df61cfad5accd8e8686405386 | 1bfdbe6948e4b90ffd17eda98e9b83d0257d7a928af43e0564730ed7e4a2cc26 |
| Bleach | 110/15 | 34260e22cac9bd7f65b0041e664c6b33df2fe2b8b196cacd500602be1a9d85c4 | 5f3d8680818fe2d1b5ae216a76c324a7ddd7aa12593da750c49314fbb7511056 |
| MLAlchemy | 22/4 | 3ffe342047ec80da544a7e6bd97a798bf276bf75dfa962a79e3a9333c75a11f3 | e0852715fa67a69114f99c03cf91017d43ea017d0f874a422076ec480bf091f9 |
| urllib3 | 150/24 | a7ed4a306a5ea5c221bdc4daac179817649c73c38e335d195ecba49c62717db3 | 6e3c7aec968f4662c9a15c971eb0ec432d48d0a4f416dda545ab1d6f8ceb4d9d |
| internetarchive | 100/14 | 6dcc91f3d72dead3c84e9a8dd977aea13926a72f5a24a0a74cb4b78f81b1d1fc | 10534ca1f3874098e2afce80a389caf503d97a15756d0d34c7d6009c580431fc |
| Flask-CORS | 51/13 | 14d6b99f1fe3ddf924291f3aed06bfe2d2bc6e81206abbc47a62430601a59da5 | 9c9fa9a60197df44c74dcdc94b1b2b09924591ed9798cdb11ed377228fde7e57 |

Brotli原始.gitattributes定义分发归档的export-ignore规则。完整Git身份通过只取得固定原始提交的深度一仓库核对，未取得修复程序；373项blob均一致，完整归档35199445字节。公开CVE描述针对Scrapy，库本身的Python/C资源接口不能直接赋予Scrapy利用身份。source-acquisition.json记录完整取得方式及不同资料角色。

MLAlchemy当前context-complete.json包含十二份文件40881字符及同一原始提交的requirements.txt，隔离复审保留依赖最低范围与未验证运行状态。原来十一份来源的内容和摘要保持。共同prepare_fixed_context.py接受明确的--output-name参数，为补充的完整输入创建独立文件，既有输入和判断不覆盖。实际依赖版本、YAML对象构造副作用和正常查询仍未测量。

八项分别保留SQL注释缓存值、Gradio路径与文件入口、Brotli原生/Python缓冲、Bleach解析模式、MLAlchemy反序列化、urllib3头部配置、下载路径副作用及CORS请求状态的具体政策边界。全部审查为自动身份，没有人工gold、代码生成、Graph或JCI新增收益。

八项完整来源、当前审查输入、逐字证据及共同准备程序已冻结为results/fixed-sources-17-24-20261103-frozen.tar.gz，104142062字节，摘要4e05a9f58798ff3422109338e85790dbaf77a75b94f9fdc3e929de80fcad0c9a，本地与服务器archive一致。固定24项的来源取得与隔离语义审查已结束，后续只在原范围内完成任务和实际测量，不再增加来源获取轮次。
