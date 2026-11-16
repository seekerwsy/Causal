# Graph操作约束索引的实现核查

## 已实现行为和证据角色

对应2026-11-03-graph-operation-guidance-design.md，唯一source_edit_guidance已增加operation_requirement_index。每个实际操作保留原节点和流程，并列出原生about_operation关系明确绑定的全部命题及其完整帧；没有操作绑定的命题另行保留。原representation逐字段保持，既有逻辑组成、断言状态、条件所有者和量词不改变。

该结果只支持消费者实现和输入预算，没有代码生成、独立表示语义准确率或Graph收益。本修订尚未进入第二轮效果评价；完整任务数量、预算及统计家族仍需在新结果之前固定。

## 三份真实来源记录

tests/development/check_operation_requirement_index.py读取已经暴露的真实来源与Graph，用原生关系独立核对反向绑定，并检查全部原帧与可逆显示恢复。没有创建模拟Graph或新增任务。

| 来源 | 实际操作 | 反向绑定 | 未记录操作的命题 |
| --- | ---: | ---: | ---: |
| aiohttp | 11 | 21 | 2 |
| Codecov | 5 | 20 | 0 |
| RestrictedPython | 8 | 27 | 5 |

aiohttp同一缓存构建操作明确同时包含正常链复用和不得保留错误对象的规范要求，两个条件仍属于各自原表达式。三份来源的完整Graph读出及所有帧均保持一致，没有为未绑定命题补充全局作用。

测试实际覆盖的表达式类型为and、atom、opaque及undeclared，未将这些三份材料称为OR或NOT语义效果验证。索引始终保留完整帧；LLM能否正确执行任何表达式仍需要独立代码结果。原有check_policy_dependency_guidance.py也通过，保留强Flat和Raw输入行为。

本地实现核查环境为Python 3.12.14、LibCST 1.9.0、NetworkX 3.7及NumPy 2.5.1。该核查不使用R、执行来源程序或调用代码生成模型。

显示复用既有source_prompt_chars及source_unit_ranges引用方式，完整原文始终存在，反向恢复与原始数据严格相同。具有明确evidence_start和evidence_end的节点使用其实际来源区间，避免重复文字改变出现位置。该显示行为没有引入新的来源事实。

## 完整提示的实际tokenizer检查

在已有Qwen2.5-Coder-32B-Instruct tokenizer上检查暴露aiohttp来源的三种完整提示。三种配置使用相同原文、政策、共同提示后缀和检查指令；Raw保留完整自由分析，Flat保留原有全部条目，Graph使用完整读出和反向索引。没有截断来源或政策，没有代码生成调用。

| 配置 | 实际输入tokens | 加8192输出后的总预算 |
| --- | ---: | ---: |
| Raw | 21728 | 29920 |
| Flat | 22766 | 30958 |
| Graph | 38548 | 46740 |

真实本地服务/v1/models返回max_model_len=49152，沿用此前共同静态YaRN设置。tokenizer自身32768元数据产生的提示保留在过程输出；当前检查使用已核对的实际服务49152上限，三个完整输入均满足该上限。没有修改权重、服务配置或调用生成接口。Graph实际输入成本更高，不能声称共同实际tokens，也没有识别长度的因果作用。

当前实际检查材料为.test-tmp/graph-operation-common-prompts-20261103/check.json、tokenizer-inputs.json及tokenizer-result.json。结构核对状态VERIFIED_OPERATION_INDEX_ON_EXPOSED_SOURCE_GRAPHS，摘要1404c26b63a153432d886fd36ea19820f1d99b7a5f347ecf5bda60eca5c365ce。tokenizer输入摘要5c97f312f08ed2cab12ee53fead2d9c25ea231ad439bfabd208c3d74ce94e4e1，结果摘要b247e9e36b9277df963495320acb4a7502947a14d1d51b9d54def19a38b33dd9，配置摘要959e7f1d9a1b7641a6d6ce05ca97b75c7894fcb66cbe5a040406458fb1128ee4。

科学实现src/tsg/source_representation.py摘要0c59cfe7e4e7a01dbc49864d023db065523bd49bacb04f8bb3828d1c7506dcc1，检查脚本摘要f54e04ae59c1d17436f2d9cd5fd74b080c935192640745dbf038d8fed26dd3a9。实际核查命令为：

```text
.venv/Scripts/python.exe tests/development/check_operation_requirement_index.py .test-tmp/graph-operation-common-prompts-20261103
.venv/Scripts/python.exe tests/development/check_policy_dependency_guidance.py
```

输出目录中的相应文件必须尚不存在。tokenizer使用既有check_prompt_context.py、purp环境和原始本地模型目录，具体输入、结果身份及真实服务上限已核对。该检查不证明模型能利用索引，不增加自然来源样本或JCI证据；aiohttp的十二项完整负结果继续保持原值。

实现核查包results/graph-operation-guidance-20261103-implementation.tar.gz大小291281字节，摘要8e0ce171fbccec51223ff91388d0f0bc927426038570908ea57fbbc89c49db01，本地与服务器archive相同。包内只保留所需科学源码、三份已暴露输入、机械检查、实际tokenizer输入结果和方法说明，没有新生成结果。

在.test-tmp/graph-operation-guidance-20261103-replay独立解压，原样src作为.runtime/prompt_mechanism_study导入，使用包内两个检查脚本重新核对。结构检查及完整tokenizer输入分别逐字节复现1404c26b63a153432d886fd36ea19820f1d99b7a5f347ecf5bda60eca5c365ce和5c97f312f08ed2cab12ee53fead2d9c25ea231ad439bfabd208c3d74ce94e4e1，没有重复代码生成或重新读取未见任务。
