# internetarchive下载目录边界的局部测量结果

## 完整控制结果

固定原始模块、规范路径参考和词法绝对路径控制各执行四十五项独立子进程案例，共完成135项检查。独立核对器重新读取请求记录、子进程状态和实际文件状态，全部分母完整，unknown为零。固定`verify.py`的安全通过公式没有单独断言`events`字段；最终审查另从冻结观察直接汇总规范路径参考的十五项安全案例，文件审计事件总数和回环请求总数均为零。冻结核对器及其原始身份保持不变。

| 实际控制 | 下载目录安全 | 局部功能 | 链接逃逸 | unknown |
| --- | ---: | ---: | ---: | ---: |
| 固定原始模块 | 0/15 | 30/30 | 7 | 0 |
| 作者规范路径参考 | 15/15 | 30/30 | 0 | 0 |
| 作者词法绝对路径控制 | 8/15 | 30/30 | 7 | 0 |

原始模块的十五项越界输入均未在请求前抛出`ValueError`并保持目录外文件。词法控制拒绝直接父目录、嵌套父目录和绝对路径逃逸，仍在目录链接及文件链接输入上发生七次逃逸。规范路径参考在任何请求或本地文件副作用之前拒绝全部十五项越界输入。

三个控制均保持八种合法文件名经三个入口下载、显式绝对路径、显式相对路径、响应返回、调用者文件对象、`ignore_existing`跳过和`checksum`跳过，共三十项局部功能。核对内容包括返回值、请求数量、实际正文、最终位置、跳过行为和普通文件修改时间。

该差异提供Linux静态文件系统下`File.download`与`Item.download`目录边界的局部测量资格。并发替换符号链接、其他平台、完整断点续传、失败重试和完整下载安全继续未知。

## 输入、环境和复现

完整政策、固定输入和事前资格条件见[设计](2026-11-03-internetarchive-path-contract-design.md)。来源为CVE-2025-58438和原始提交`a3e45e23bb9482d5049cbe3725dd7db9929298b6`。原始归档为154555字节，SHA-256为`6dcc91f3d72dead3c84e9a8dd977aea13926a72f5a24a0a74cb4b78f81b1d1fc`；来源snapshot摘要为`7175fb6e3783c32d8821d1fc52ccd8ea6eecc78dc07a78031eefb1227eed53ea`。

实际环境使用Python 3.12.16固定镜像`sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957`，Requests 2.32.3、urllib3 2.2.3、jsonpatch 1.33、jsonpointer 3.0.0、tqdm 4.66.5及`fixtures.json`固定的传输依赖。容器关闭外部网络，使用只读源码和依赖、非特权用户、一核CPU、2GB内存及`/work`临时目录。每项均使用真实`ArchiveSession`、`Item`和`File`对象，经容器回环地址请求标准库HTTP服务器；外部Archive请求和代码生成调用均为零。

服务器固定输入目录为`/home/wsy/work/prompt-mechanism-study/inputs/internetarchive-path-contract-20261103-runtime-v5`，完整结果目录为`/home/wsy/work/prompt-mechanism-study/results/internetarchive-path-contract-20261103-qualified`。在固定输入目录执行：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/internetarchive-path-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/internetarchive-path-contract-20261103-qualified full
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/internetarchive-path-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/internetarchive-path-contract-20261103-qualified
```

`result.json`摘要为`75815a6b14defdcf167a9899044bcf9a1c84cd6ba727b7659e32b7e9792c76e1`；独立核对器摘要为`0ebe9099cc628c2fd192bd06a4f934dff3cf5091d6062239fef2318da05253f0`；`verification.json`摘要为`40b5d1d9a60067ff0d25849f27ad76e6c55ec923dde8759caa9b9f5275b7a9b9`。服务器在新的`inputs/internetarchive-path-contract-20261103-replay`目录复制完整观察并排除原核对文件，使用固定核对器重新计算；新核对文件逐字节复现原摘要，没有重新执行来源程序或生成代码。

完整冻结包`results/internetarchive-path-contract-20261103-frozen.tar.gz`为2230018字节，SHA-256为`7db7b0fee0ac2ef7046bad5a172c0d8d4e325062a5498dad0dbe8684b3a0d9f8`，本地与服务器产物一致。包内保留原始归档、固定wheel、来源snapshot、设计、控制实现、测量与核对程序、完整135项实际观察、容器命令、结果和核对记录。

本项没有比较Raw、Flat或Graph表示，没有建立Graph代码收益、Atomic干预效果、自然JCI上下文或正式研究结论。作者控制、探针、预期答案和实际结果不进入未来表示制作上下文；共同任务、隔离表示、独立绑定参考、队列预算及代码比较仍须在新生成之前另行固定。
