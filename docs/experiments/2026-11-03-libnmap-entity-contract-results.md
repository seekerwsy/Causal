# libnmap公开解析入口的局部执行结果

## 实际观察

原始程序和作者参考均已在Python 3.12.16、Expat 2.9.0及同一隔离Docker环境完成51项检查，共102项。固定设计为2026-11-03-libnmap-entity-contract-design.md，全部输入与两份实现均在程序首次运行之前固定。没有模型调用，没有读取上游修复代码。

| 控制 | 实体声明拒绝 | 局部功能 |
| --- | ---: | ---: |
| 固定原始源码 | 0/12 | 39/39 |
| 作者参考 | 12/12 | 39/39 |

原始程序通过三个公开入口接受全部四种规模受限的实体声明输入。被引用普通实体确实进入返回NmapService的owner字段，值为entity-value；未引用普通、参数及外部实体声明均仍返回普通对象。参考在相同输入上抛出NmapParserException，其原始异常文字记录EntitiesForbidden。没有访问声明中的文件，也没有执行放大载荷。

两份程序保留全部已检查对象字段、根节点分派、端口顺序、文件输入、incomplete补全、普通外部DOCTYPE、预定义转义、注释和CDATA文本；四种预定错误输入在三个入口均抛出指定异常。结果支持该局部测量区分两个控制，并保留39项覆盖内的功能。完整功能、资源消耗改善、真实漏洞利用和表示收益保持未建立。

## 执行及核对

输入包results/libnmap-entity-contract-20261103-inputs.tar.gz大小439232字节，摘要b210ac99d403da642b3641d554fd4a9363427bb18e71e673acb3a55c392d2ae6，本地与服务器inputs相同。输入包括固定原始归档、快照、来源审查、设计、probe.py、作者reference_parser.py、run.py及固定defusedxml wheel。参考的源码变化只涉及解析依赖导入和公开路径fromstring调用，私有辅助函数的原始Element处理保留。

服务器输入为/home/wsy/work/prompt-mechanism-study/inputs/libnmap-entity-contract-20261103-runtime。真实命令从该目录使用既有科学Python执行：

```text
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/libnmap-entity-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/libnmap-entity-contract-20261103-control
```

控制逐项保存完整Docker命令、源码与依赖摘要、stdout、stderr及实际对象或异常。镜像固定为sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，网络关闭，非特权用户，源文件只读；临时文件位于容器/work，主机TEMP、TMP和TMPDIR均指向输入目录runtime-tmp。两个进程返回码均为零。

完整原始结果已取回data/method/libnmap-entity-contract-20261103/control-results。独立verify.py没有导入probe或参考实现，重新检查102项入口和输入身份、规定异常、返回字段、全部功能对应及汇总计数。它不采用probe保存的expected字段作为判断依据。状态INDEPENDENTLY_VERIFIED_REAL_LIBNMAP_PUBLIC_ENTRY_CONTROLS，结果摘要43eca45701c0660e3a5c6be322101010843d3735884465ab6a04e4f828b9b185，核对结果摘要e6aab9fd1a1882284786fb738e3aadef481cd9516742b1089147d5be52a4ef50。核对入口为：

```text
.venv/Scripts/python.exe data/method/libnmap-entity-contract-20261103/verify.py data/method/libnmap-entity-contract-20261103/control-results
```

核对输出路径必须尚不存在；独立重放时使用重新解压且不含verification.json的结果目录。无需重新生成程序即可复核实际原始记录。

完整冻结包为results/libnmap-entity-contract-20261103-frozen.tar.gz，501210字节，摘要9973fad48f933f760dac1158c31075dd1f3d17d6106b6e538aebafc8232e054f，本地与服务器archive相同。包内包含原始输入、完整102项观察、核对程序和对应来源材料。已在.test-tmp/libnmap-entity-contract-20261103-replay重新解压，排除原核对输出后，使用包内verify.py复核实际记录；verification.json逐字节复现e6aab9fd1a1882284786fb738e3aadef481cd9516742b1089147d5be52a4ef50，没有再次执行来源。重放命令为：

```text
New-Item -ItemType Directory -Path .test-tmp/libnmap-entity-contract-20261103-replay
tar --exclude='*/verification.json' -xzf results/libnmap-entity-contract-20261103-frozen.tar.gz -C .test-tmp/libnmap-entity-contract-20261103-replay
.venv/Scripts/python.exe .test-tmp/libnmap-entity-contract-20261103-replay/data/method/libnmap-entity-contract-20261103/verify.py .test-tmp/libnmap-entity-contract-20261103-replay/data/method/libnmap-entity-contract-20261103/control-results
```

## 研究边界

第五项来源现在具有这一限定政策的真实控制测量。它仍没有自然编程请求，也尚未形成固定代码生成任务、独立表示比较或Graph处理前属性准确性证据。源码版本声明与CVE版本范围的对应缺口继续保留；实体拒绝政策由研究者提出，不能写成已经还原CVE利用。

当前Goal的JCI完整稳健性实验和aiohttp表示开发检查分别运行。本结果不增加JCI样本，不充当Graph独立收益，也不进入正式协议。后续表示制作仅取得原始来源、共同任务与共同API资料，不能读取作者参考、测量答案和控制结果。
