# pypdf的LZW写入前限额实际测量

## 三个真实控制

按2026-11-03-pypdf-lzw-contract-design.md固定的八项输入、五条实际路径和编码保持检查，原始程序、写入前参考、解码后参考各完成48项，共144项。程序、设计、输入构造规则及两个作者控制均在执行前固定；没有模型调用，没有读取上游修复。

| 控制 | 写入前安全要求 | 局部功能 |
| --- | ---: | ---: |
| 固定原始源码 | 0/15 | 33/33 |
| 写入前检查参考 | 15/15 | 33/33 |
| 解码后检查参考 | 0/15 | 33/33 |

原始程序在三个超限输入上分别积累16388、65536、16416字节并正常返回。解码后参考同样先积累全部字节，再抛出LimitReachedError，因此仍违反写入前限额。写入前参考抛出相同异常，但各次实际写入后的位置均不超过16384。单独观察异常类别无法区分这两个控制；真实写入记录提供了区别。

五条路径为直接LzwCodec、Decoder包装、LZWDecode过滤器，以及长名称和缩写过滤器的真实EncodedStreamObject。限额内的25项解码功能和八项编码保持均通过，包含等于限额时正常返回、非过滤器元数据复制和成功解码缓存。没有替换缓冲区、解码器或外部程序。

八份原始编码输入全部通过独立pdfminer.six 20250506解码，其字节与事前定义的原始输入逐项相同。实际写入覆盖原始源码237、241、250三处位置，记录9、10、11、12位码宽。这些位置及输入不是新增自然任务单位。

## 输入、环境和核对

实际输入results/pypdf-lzw-contract-20261103-runtime-inputs.tar.gz大小13720623字节，摘要976e7436c556750698ed28b5f1be071639d0c3aabbcea6736eda25037e3f5bc5，本地与服务器输入相同。源包、PDFMiner wheel、快照、设计、probe.py及三个控制在运行前固定。两个作者控制只改变原始LZW方法的限额行为；文件顶部模块说明保留为注释，编码算法保持原值。

服务器输入为/home/wsy/work/prompt-mechanism-study/inputs/pypdf-lzw-contract-20261103-runtime。实际命令在该目录执行：

```text
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/pypdf-lzw-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/pypdf-lzw-contract-20261103-control
```

使用固定Python 3.12.16镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，网络关闭，原始代码、候选控制及wheel只读，非特权用户，CPU限制1、内存限制2GB。容器临时文件位于/work；主机TEMP、TMP、TMPDIR指向项目输入的runtime-tmp。输入构造和三个控制进程均返回零；实际命令、源码和依赖摘要、stdout及stderr随完整记录保存。

结果目录已取回data/method/pypdf-lzw-contract-20261103/control-results。独立verify.py不导入probe或任何控制，使用相同独立PDFMiner重新核对输入字节，逐项检查三个控制的144项记录，包括异常、字节摘要、写入连续性、观察到的码宽、元数据、缓存和编码保持，并核对原始源文件与驱动身份。状态INDEPENDENTLY_VERIFIED_REAL_LZW_PREWRITE_CONTROLS，实际结果摘要a380c6f7d88ee220eae2031057e39c966b258cc2a01fead32cdcbcfd91db65c8，核对输出摘要b6628a24885c8261cf3c02c211a0c01448156adbdacad9386e01548cc5b1929d，核对器摘要664edc4fe223f5ad91b4fe32dea6625f05c996bfcf84e3a11fd83432a2e3058e。

独立核对需要将固定PDFMiner wheel加入PYTHONPATH，并使用不含原核对输出的新解压目录：

```text
$env:PYTHONPATH = (Resolve-Path .test-tmp/pypdf-lzw-dependencies-20261103/pdfminer_six-20250506-py3-none-any.whl).Path
.venv/Scripts/python.exe data/method/pypdf-lzw-contract-20261103/verify.py data/method/pypdf-lzw-contract-20261103/control-results
```

完整冻结包results/pypdf-lzw-contract-20261103-frozen.tar.gz大小15845841字节，摘要7d266a9e787a8026ac78164f6f9a3696baba371290754016fe4f6b6788fc647f，本地与服务器archive相同。包内保留完整运行输入、八份编码材料、144项实际观察、设计和核对实现。在.test-tmp/pypdf-lzw-contract-20261103-replay重新解压并恢复包内输入，排除原核对输出后使用包内verify.py和wheel复核，输出逐字节复现b6628a24885c8261cf3c02c211a0c01448156adbdacad9386e01548cc5b1929d，没有再次执行被测程序。

## 资格与研究边界

该有限测量取得正反控制区分资格，并实际区分解码后拒绝与写入前限制。它只对已固定BytesIO输出形式和现有路径提供证据；未认证任意生成代码的测量准确性。字典、临时字节、缓冲区实际容量、组合流及完整进程峰值内存均没有获得限额保证，没有执行拒绝服务利用或完整PDF功能评价。

来源可以支持继续准备自然原始代码上的研究者新增任务。具体基准提示、独立表示输入与完整比较仍需在模型结果之前固定。144项检查是一个来源的控制测量，不是144个自然任务，也不是Graph、JCI或策略价值收益。后续表示制作只能取得共同原始来源、政策及允许API资料，不能取得控制实现、编码测量答案或实际结果。
