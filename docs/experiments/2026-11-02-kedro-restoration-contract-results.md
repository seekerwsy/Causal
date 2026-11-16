# 存储恢复合同的实际测量结果

## 测量范围

按照 `2026-11-02-kedro-restoration-contract-design.md`，对固定来源CVE-2024-9701执行三种实现控制。一个自然代码单位包含原始提交、自然上游修复快照，以及在原始快照上替换一个文件的研究者控制实现。控制实现经过独立上下文的来源审查；审查没有读取测试或运行结果。

固定测试包含21项局部功能检查和21项恢复策略检查。全部测试关闭网络，使用真实序列化、数据库操作、文件系统事件和新进程导入，没有模拟对象。两个支持目标接口的实现各执行42项；测试条件不能作为独立任务数量。

## 实际结果

| 实现 | 局部功能通过 | 恢复策略通过 | 实际副作用 | 测量错误／跳过 |
| --- | --- | --- | --- | --- |
| 原始自然程序 | 21／21 | 0／21 | 19／19项副作用探针发生事件 | 零项／零项 |
| 研究者受限恢复控制 | 21／21 | 21／21 | 零项 | 零项／零项 |
| 自然上游修复快照 | unknown | unknown | 不赋予安全结果 | 接口缺失，未运行测试 |

原始程序保留21项真实失败，退出状态为1。控制实现通过全部42项，退出状态为0；禁止global的导入探针在独立Python进程中确认拒绝，未发生导入副作用。两个实现各自实际加载的30个Kedro模块均与固定快照或指定的单文件控制摘要一致。上游修复快照确实不提供目标模块，保留 `target_module_absent`，没有测试报告，也没有安全成功判定。

独立核对程序直接读取原始XML、接口探测、全部21项策略探针事件、退出状态和模块摘要，状态为 `VERIFIED_BOUNDED_RESTORATION_CONTRACT_ACCOUNTING`。结果 `bounded_policy_oracle_qualified`、`partial_functionality_qualified` 和 `qualified_for_bounded_generation_check` 均为true。

从冻结输入归档和原始结果归档分别解压到新的项目目录，实际执行包内独立核对程序，生成的 `qualification.json` 与首次独立核对结果逐字节相同，SHA256均为 `efc457ef3241b627f6bfd12e59a4cecfe2fe438117123871a0c7306132dc86bc`。该复算没有增加任务或再次执行源码。

## 科学解释及边界

本轮建立了指定恢复策略和局部功能的测量资格，能够区分具有可观察禁止行为的实现、满足本组明确检查的控制实现，以及目标接口缺失的unknown实现。下一项表示与代码生成比较可以沿用这些检查，并分别保留安全结果、局部功能结果和联合成功；功能失败不能用于删除已分配样本。

安全范围限于固定协议、明确global规则及所列探针，不认证任意恶意pickle、全部畸形输入、资源消耗或全部数据库后端。功能范围限于指定值、路径及已测接口行为，完整功能、完整并发行为和跨平台兼容保持未知。研究者控制的成功没有建立自然修复收益、Graph收益或JCI收益。

本轮模型生成调用为零次，实验分配样本为零项，正式声明仍未授权。先前六项原始程序测量保持原有身份，本轮42项测量使用独立计划及结果，未重新解释其资格结论。

## 冻结输入和复现

实际环境为Python 3.12.16、pytest 9.1.1及固定50项依赖，Docker镜像为 `sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957`。原始源码及依赖只读，控制实现仅以一个只读文件挂载提供。原始和上游快照分别有73项、72项选定Git对象逐项核对，完整归档文件路径分别核对590项和588项。

输入归档为 `results/kedro-restoration-contract-20261102-corrected-inputs.tar.gz`，102253944字节，SHA256为 `88249bfc41d54e74b047d7f22302fec958a66eb25f0c52feeb49733022dbc76b`。计划摘要为 `5010786ff005c0814cc3ddf96452d4438e2e6d67d7ec408e8f177fac58afd850`，控制源码摘要为 `25a17aea53738eea7ff6a20ebd09434323c0098f300ba237b252c417a9a22de7`。实际原始结果归档摘要为 `eac97144a307c5dadf199545833c412d42bec0fd8431d24e3aa2060a8620e168`。

服务器输入目录为项目 `inputs/kedro-restoration-contract-20261102-corrected`，结果目录为 `results/kedro-restoration-contract-20261102-corrected`。本地原始记录及独立核对结果位于 `data/method/kedro-restoration-contract-20261102/results`。

在新的项目inputs目录解压输入归档后，执行下列入口，参数指向尚不存在的项目结果目录：

```text
bash data/method/kedro-restoration-contract-20261102/run.sh /home/wsy/work/prompt-mechanism-study/results/kedro-restoration-contract-review
```

独立结果核对入口如下。目标目录中的派生 `qualification.json` 必须尚不存在；冻结原件应保存在原位置，复算使用独立副本。

```text
pwsh -File data/method/kedro-restoration-contract-20261102/verify.ps1 -Results <原始结果副本目录>
```

审阅顺序为本结果文档、设计文档、`kedro-task-source.json`、`reference-review-validated.json`、`plan.json`、`shelvestore.py`、`test_contract.py`、`verify.ps1`及 `results/qualification.json`。任务来源文件位于相邻的 `security-code-source-20261102`目录，其余代码和结果位于 `kedro-restoration-contract-20261102`目录。完整冻结包同时提供两项源码归档及实际依赖归档，重新测量不需要网络。

全部开发执行记录保留于各自输入和结果归档。首次开发结果归档为 `results/kedro-restoration-contract-20261102-initial-results.tar.gz`，SHA256为 `10956726e2af1d015ecff3656b03e1dcfa767210ad049e5b3cd751a08a8a5d74`；它不作为本次合格控制的结果。

完整冻结包为 `results/kedro-restoration-contract-20261102-frozen.tar.gz`，102266915字节，SHA256为 `7ec75dd9c48409a24eadb7e0c8b7d277182f9b06ac6b3428459601ad484c0b7d`，本地和服务器archive副本摘要一致。该包包含当前输入、两项自然源码归档、实际依赖、全部原始结果、来源审查、独立核对程序及核对结果；历史开发记录保存在独立归档。
