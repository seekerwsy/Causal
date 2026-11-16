# Kedro 存储来源的实际测量

## 原始程序与测量范围

按照 `2026-11-02-kedro-source-measurement-design.md`，执行固定来源CVE-2024-9701的原始提交 `d6f8ae564d90989ec664814fb381f8cc55681932`。全部590项归档文件路径与提交目录一致，其中74项包Python源码、包装配置及指定资料逐项通过Git对象核对。没有修改原始程序或上游测试。

本轮使用一个自然代码单位、一个原始程序版本、六项固定测试。独立离线复现又执行相同六项，共12次测试执行；独立代码单位及样本数量没有增加。没有生成模型调用、策略随机分配或正式角色赋予。原始编程请求没有提供，当前材料仍需明确受控任务指令才能开展表示和干预比较。

## 实际结果

| 项目 | 首次执行 | 离线复现 |
| --- | --- | --- |
| 五项原始合法输入测试 | 五项通过 | 五项通过 |
| 指定恢复副作用是否发生 | 是 | 是 |
| 要求不得发生副作用的断言 | 真实失败 | 真实失败 |
| 测试错误或跳过 | 零项 | 零项 |
| 实际Kedro源码模块核对 | 30项一致 | 30项一致 |

合法输入测试覆盖BaseSessionStore初始化与保存，以及ShelveStore空存储、Path对象保存与恢复、未保存修改和保存后键新增／删除的行为。执行原始测试及真实文件系统操作，没有使用模拟对象。五项通过只支持这些局部行为，完整功能性继续未知。

受控探针使用标准shelve写入一个序列化恢复时调用os.mkdir的对象。写入后目标目录不存在；通过原始ShelveStore构造及read路径恢复后，目标目录确实出现，恢复值为该调用的None返回值。目录限定在该测试的工作目录中，测量关闭网络。原始pytest报告保留一项断言失败和五项通过，退出状态为1，没有捕获或改写失败以生成通过结果。

该观察支持指定不受信任恢复路径会执行所提供的目录创建调用。它不认证完整漏洞利用、完整安全性、其他部署的可攻击条件或生成模型基线。当前尚未完成已知安全实现及unknown实现的测量资格，所以 `oracle_qualified=false`、`atomic_qualified=false`。Graph、JCI及策略收益均未由本次检查建立。

## 独立核对及精确环境

独立核对状态为 `VERIFIED_KEDRO_SOURCE_MEASUREMENT_ACCOUNTING`。核对程序使用.NET XML和JSON库，分别检查测试身份、六项分母、源提交及归档、30个实际模块的位置和摘要、原始退出状态、探针路径与事件、实际依赖版本。不通过生产测量代码重新解释目标事件。

环境为固定Docker镜像 `sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957`，Python 3.12.16、pytest 9.1.1和Kedro 0.19.8。首次测量前保存50项实际安装版本；全部Kedro模块仍从只读原始快照导入。冻结的依赖目录已经用于新容器的离线复现，恢复探针、完整模块绑定记录及依赖清单分别与首次执行逐字节一致，XML中的时间信息另行保留。

离线复现核对为 `VERIFIED_KEDRO_OFFLINE_SOURCE_REPRODUCTION`，记录在 `results/kedro-source-measurement-20261102-offline-verification.json`。它不增加独立科学重复，也不补足尚未提供的已知安全实现和unknown实现。

## 输入与原始记录

实际运行输入包为 `results/kedro-source-measurement-20261102-runtime-inputs.tar.gz`，44263387字节，SHA256为 `cbd8f00ea6f712360ab7e0b07799960dabe4dcdce37ac0815c678da1f30d7a77`。计划为 `8feb9a54c0cbdfa394512d3d1261f0b13f3ab64c601b6179ca3101aba3b48265`；原始源码归档为 `7e83696114ac17d63e4fcaefe5de36c878fbd10c71af1eb1e1eee9040b35ab97`。

实际原始结果归档为 `33468ee9e0a5cfcae893a41b36a339fa13a03e65717eb178fce7953bdbd0b90c`；隔离依赖归档为 `a9ed22020b01612bae4c20691ed7de16534dbf967ae578e3763ce4fec5043319`，13772986字节；离线复现原始结果归档为 `bf2ef774b1fea775d6432ea4332ea4bdf5e013f781b6bf3ea54122175a279afe`。这些资料分别保存在项目results目录及服务器archive目录，安装过程日志保留在服务器开发目录。

本地实际核对结果为 `data/method/security-code-source-20261102/kedro-results/kedro-measurement.json`，SHA256为 `7157810daff575b781b528a59f1d1dcd23f79581883d51961ccf1cc0488a7b8c`。原始XML、stdout、stderr、探针和模块记录位于其original目录，离线复现对应资料位于offline-replay目录。

## 复现入口和研究后续

阅读顺序为本设计、`kedro-qualification-plan.json`、`kedro-results/original/probe.json`、`kedro-results/original/runtime.json`及 `verify_kedro_measurement.ps1`。已有原始结果可在独立副本中保存同名派生核对输出后执行：

```text
pwsh -File data/method/security-code-source-20261102/verify_kedro_measurement.ps1 -Results data/method/security-code-source-20261102/kedro-results
```

完整离线测试复现使用同一固定镜像。在新的项目inputs目录解压冻结包后执行：

```text
bash data/method/security-code-source-20261102/reproduce_kedro_measurement.sh /home/wsy/work/prompt-mechanism-study/results/kedro-source-review-20261102
```

指定结果目录及输入中的replay-source、replay-dependencies需要尚不存在。复现只解压固定源码和实际依赖，测量不使用网络，不需要重新解析依赖范围。

下一项研究准备需要明确安全要求及允许恢复的输入范围，并用保留相应非目标行为的已知安全实现和unknown实现核对测量边界。源码中的类型注解、已有测试和新编写的任务义务分别保留；不能把当前五项通过扩展为任意对象兼容，也不能将缺少任务措辞直接认定为来源不合格。其余固定来源身份和此前Graph平局保持原值。

完整冻结包为 `results/kedro-source-measurement-20261102-frozen.tar.gz`，58008504字节，SHA256为 `709c95248ea3a39f92cfa7a6e160c1c3dd7397ef2a90018f79b38f897e51c2e6`。它包含原始源码快照、实际依赖、六项测量程序、计划、两次原始记录和独立核对程序，支持离线测试复现。

将完整冻结包独立解压到 `.test-tmp/kedro-measurement-replay-20261102`，使用包内核对程序重新读取首次及离线原始XML，两项派生核对结果均与冻结原件逐字节相同。该复算没有再次执行来源程序。记录为 `results/kedro-source-measurement-20261102-replay.json`，状态 `VERIFIED_EXTRACTED_KEDRO_MEASUREMENT_ACCOUNTING`。本段记录归档之后完成的原始资料复算。
