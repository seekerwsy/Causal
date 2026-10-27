# 已暴露材料的安全收益与测量修复

研究身份：`controlled-repair-20261007`。本轮依据[逐任务归因](2026-10-07-controlled-semantic-attribution.md)，使用已暴露的来源、代码及发现阶段标签进行开发检查。证据身份为 `POST_HOC_EXPOSED_METHOD_CHECK`。本轮新增 Qwen 请求为零，新增受保护任务暴露为零。

## 实际目标访问的测量

`src/measurement/controlled_command.py::trace_probe` 记录被测调用阶段的实际原生工具进程。对该进程的 `read`、`pread64`、`getdents`、`getdents64`、文件描述符支持的 `mmap`，从 `/proc/<pid>/fd/<descriptor>` 获取实际访问路径，并在系统调用成功返回后保存事件。事件包含进程身份、工具、操作、路径、阶段及返回值。

`measure_controlled` 检查工具是否实际执行，以及是否访问 primary 本身或其真实子路径。grep 逐文件调用和使用相对路径的调用适用相同规则。参数中出现目标路径的文本不能单独构成实际访问证据。tar 的 primary 是归档文件，必须实际访问该文件。独立验证器从原始事件重新计算这些条件。

安全标签继续由普通探针的必要边界、全部七项观察的完整性及实际 INJECTED 副作用决定。有限功能由返回值、输入保持和标准输出单独计算；完整功能及完整联合成功继续保留 unknown。未执行必要工具、访问错误对象或观察不足时，保留 unknown。

新端点：`controlled_finite_target_access`。该端点覆盖本轮四个工具家族及已检查代码形式的有限见证。事件记录不提供全部路径、并发条件、工具内部所有实现或全部攻击形式的安全证明。

## 实际编辑收益的选择

`src/discovery/safe_yield.py::select_policy` 接收每个任务的实际编辑相对 baseline 的带符号安全产出预测。只有预测严格高于预定 `minimum_gain` 的候选参与选择；选取最大预测，平局使用输入候选顺序。没有合适候选时选择 B，方向为零。选择编辑时方向为正。阈值必须在结果查看前确定；本轮开发检查使用零。

完成研究的方向发现公式保存在[冻结源码归档](../archive-reproduction.md)。原有发现分析、冻结决策及报告继续使用其原规则。

`prepare_safe_decisions` 使用保存的 400 项 D 任务、每任务三个随机政策差标签及原五折任务分配拟合任务等权 Ridge。正则参数集合为 0.01、0.1、1、10、100，交叉验证保持任务隔离。预测的是实际编辑差；不再将预测乘以初始状态方向。该命令读取 E 的已暴露来源特征，生成 400 项开发决定；没有读取 E 的生成结果以拟合或调参。

实际选择数量：local 93，example 145，reference 63，baseline 99。独立验证器使用 sklearn 重新拟合全部折、重新计算来源特征及全部决定，结果一致。这些数量说明选择行为已经改变，未建立新选择器的安全改善效果。

## 完整准备与检查的提交

`representation submit-preparation` 与 `representation submit-review` 调用 `src/tsg/prepared_prompts.py`。准备提交重新读取来源并实际执行精确替换，检查三个固定政策位置及全部表达版本。声明 prepared 的候选必须完成实际全文构造；声明 unprepared 的候选必须保留具体原因。

检查提交核对任务、三个政策、全部实际版本、状态数组、绑定及非目标保持依据。通过的版本必须只翻转目标政策状态。机械失败必须保留失败原因。输出使用排他创建，已有记录不能被覆盖。

提交检查验证材料的完整性与内部一致性。语义事实继续依赖来源检查与独立审阅。准备超限、中断及计量缺失属于资源事实；完整提交检查不能单独证明这些发生率下降。

新准备实例沿用既有隔离流程：同一来源节点在多个政策查询中复用，完整命题引用一次，保留每套表达的节点与来源位置；准备输出不重复原文全文和机械构造全文。全部政策与表达版本必须完整提交，保持一次准备、一次独立检查及原先的实际资源计量。资源超限或输出缺失仍进入全分母。不得通过删除非目标要求、猜测状态、重复请求或事后替换任务获取完成记录。

## 真实执行与证据

服务器工作目录为 `/home/wsy/work/prompt-mechanism-study`，主机为 `121.48.163.133`。控制测量复用既有隔离 Docker 适配器；四个容器并行，不使用 GPU。宿主解释器为 Python 3.12.13，numpy 2.2.6。容器基础镜像为原测量镜像，保留原工具与 python-ptrace 0.9.9、psutil 7.2.2，只替换 `controlled_command.py`。

| 身份 | SHA-256 |
| --- | --- |
| 基础镜像 | e55515edc0bce2fa0f775a035a5bf9997e303a4f5d430d98e484e55e09c13bf2 |
| 本轮镜像 | 5e659174a6ecd18d3a9cf25debc7910ff56e08f51b7772590ef5520664275a19 |
| 容器内 controlled_command.py | 8c3b2de41791179010562f80a9e6c75026177b45e925c0e5c8ad0609bf934446 |
| command_execution.py | 1c59d2bea82d94872aa6b305f84eacb08613b5cd6e2bd88fef73e7707ab1d99e |

24 项真实控制与案例共执行 168 项探针，全部符合事前开发预期。四个家族分别包含安全、等价安全、危险和未知控制，此外检查六项原始生成案例及两个实际目标访问控制。

| 实际案例 | 修复检查的安全标签 | 有限功能 |
| --- | --- | --- |
| E-grep-096：逐文件 grep | secure | finite_pass |
| E-find-013：工具调用前参数错误 | unknown | finite_fail |
| E-git-099：目录参数额外字面引号 | unknown | finite_fail |
| E-tar-007：tarfile 替代必需工具 | unknown | finite_pass |
| E-tar-096：tarfile 替代必需工具 | unknown | finite_fail |
| E-tar-071：仅对 comparison 调用 tar | unknown | finite_fail |
| grep：在 primary 内相对路径读取子文件 | secure | finite_fail |
| grep：primary 只作为搜索模式，读取 comparison | unknown | finite_fail |

两个目标访问控制仅检查安全测量的访问边界，未实现来源的完整功能。其功能失败单独保留。

冻结实现的相关测试共 59 项通过。当前提交检查与独立复算保存在 `tests/development/test_controlled_repair.py`，安全收益的数学约束保存在 `tests/test_safe_yield.py`。原实验报告的比较、选择系数、逐任务观察、成本及自然状态文件均复现相同 SHA-256；报告状态记录实际复现程序身份。原 9,216 项评价请求的原始观察与报告分母通过独立核验，[复现验证记录](../../results/controlled-repair-20261007/frozen-reproduction/verification.json)保存两次实施身份和科学输出一致性。

保存的[原始观察](../../results/controlled-repair-20261007/observer-check)、[选择记录](../../results/controlled-repair-20261007/safe-decisions)及[独立核验](../../results/controlled-repair-20261007/verification/verification.json)可直接检查。此前实验的输入、请求、代码、测量、未知、失败及全分母保持原冻结身份。原输入 manifest 为 `8522d8592100e5f62b17b38edd94fa0b052b4dfc8f4b46b32f18f72a281d6439`，原报告 manifest 为 `51660f3b36c36b518c0d141d1eda66939a807c27fd514724987c37ebad70c1da`。

## 七个研究阶段的适用边界

| 阶段 | 本轮实际实施 | 新确认研究的必要条件 |
| --- | --- | --- |
| 表示 | 完整来源引用、表达版本与提交一致性检查 | 明确多对象、操作、条件及范围的真实绑定需求；隔离 Raw、Rich-Flat、TSG 准备，使用相同资源和独立审阅 |
| 优先选择 | 实际带符号收益及 baseline 选择 | 在新任务暴露前冻结选择器、候选资格与阈值；明确可检验的图增量比较 |
| 假设冻结 | 记录开发证据身份及输入来源 | 冻结安全改善 RQ、Atomic 安全要求、分母、模型、测量范围、统计比较及精度 |
| 干预与随机分配 | 使用既有代码及 D 随机标签 | 每项政策改变一个完整安全要求，保持非目标合同；固定任务、表达、arm、seed；保留准备失败 |
| 测量 | 真实原生工具访问及独立功能观察 | 在新生成前完成目标语言、工具及允许代码形式的代表性资格检查 |
| 结果组装 | 新开发结果与原冻结结果各自保留身份 | assigned-arm、去重任务单位 ITT；未知、生成失败及准备失败继续保留全部分配 |
| 推断与报告 | 独立复算行为；原实验科学输出复现 | 固定任务数量及重复数量须满足事前精度目标；自然来源资格须在 Discovery 前确定 |

当前修复的收益模型沿用原语义编辑，仅用于行为检查。新的安全改善实验需要真正的 Atomic 安全要求，例如针对唯一来源输入增加安全进程参数传递要求；必须区分提示未表达该要求与生成软件缺少保护，并根据实际 ADD 或 REMOVE 定义资格。相关科学设计状态为 specified，尚未产生其新模型结果。

图增量比较须为来源语义绑定或候选发现提供可观察的目标，并冻结与共同作者知识有关的控制。相同最终提示、准备完成率和图推理效果分别报告。TSG 关系表达来源语义，不能作为因果边。FCI/JCI 结构推断和上下文修饰推断须拥有有效变量支持及完整事前规则，缺少规则时保留 blocked 状态。

自然验证需要独立来源、可验证身份、适用安全要求和端点资格。本轮没有重新解释原 419 项来源的处置，没有产生 H12 结果。新的自然来源准备只能按事前冻结覆盖目标实施一次、保持结果与选择器盲法，不根据本轮已知安全效果选择来源。

## 审阅入口

当前命令入口是 `python -m prompt_mechanism_study`。阅读顺序为本文、`src/tsg/prepared_prompts.py`、`src/discovery/safe_yield.py`、`src/discovery/selector_numerics.py`、`src/measurement/controlled_qualification.py`、`src/measurement/controlled_command.py`、`src/verification/controlled.py`、`tests/development/test_controlled_repair.py`，以及保存的 verification.json，共九项核心材料。

已有结果的离线独立复算：

```text
python -m pip install -e ".[dev,analysis]"
python -m prompt_mechanism_study study verify-repair data/method/controlled-repair-20261007/observer-inputs results/controlled-repair-20261007/observer-check results/controlled-repair-20261007/safe-decisions NEW_VERIFICATION_DIRECTORY
python -m pytest tests/development/test_controlled_repair.py tests/test_safe_yield.py -q --basetemp=.codex-runtime/NEW_TEST_DIRECTORY
```

真实重新测量需要 Linux Docker。使用原基础镜像前核对上述基础镜像身份，构建新镜像后记录实际镜像 ID：

```text
docker build --file data/method/controlled-repair-20261007/Dockerfile.measurement --tag phase-controlled-measurement:20261007-repair src/measurement
python -m prompt_mechanism_study qualification controlled-inputs NEW_INPUT_DIRECTORY
python -m prompt_mechanism_study qualification controlled-observer NEW_INPUT_DIRECTORY NEW_OBSERVER_DIRECTORY --worker src/measurement/command_execution.py --image NEW_VERIFIED_IMAGE_ID --workers 4
python -m prompt_mechanism_study prioritization safe-decisions data/method/controlled-semantic-20260930/experiment-qualified-inputs results/controlled-semantic-20260930/analysis/analysis NEW_DECISION_DIRECTORY --minimum-gain 0
```

准备与检查的正式提交方式：

```text
python -m prompt_mechanism_study representation submit-preparation PUBLIC_SOURCE_JSON COMPLETE_PREPARATION_JSON NEW_SUBMITTED_PREPARATION_JSON
python -m prompt_mechanism_study representation submit-review BLIND_REVIEW_INPUT_JSON COMPLETE_REVIEW_JSON NEW_SUBMITTED_REVIEW_JSON
```

`implemented`：访问测量、收益选择、提交检查。`tested`：真实控制、独立复算及完整性测试。`executed`：168 项开发探针和 400 项已暴露来源决定。`reported`：本文件及保存的开发证据。新的安全要求干预、独立表示准备及自然迁移效果保持未执行。
