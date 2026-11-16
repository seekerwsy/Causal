# Starlette真实上传写入的局部测量结果

## 控制结果

固定十六种真实文件输入、三个完整模块控制均已执行。每个控制十项需要工作线程的安全检查、十六项联合局部保留义务检查，共78项；独立核对全部通过。三个控制的安全unknown均为零。

| 实际控制 | 安全检查 | 局部保留义务 |
| --- | ---: | ---: |
| 固定原始模块 | 5/10 | 16/16 |
| 作者写入前选择线程参考 | 10/10 | 16/16 |
| 作者始终在线程池写入控制 | 10/10 | 7/16 |

原始模块的五次首次转存分别发生于单次越界、分块越界、seek后越界、size未知和超过阈值位置的空写入；实际完整底层write及rollover都在事件循环线程。已经转存和普通文件的五次写入在工作线程。写入前参考对全部十次需要工作线程的写入均正确分配，保留全部十六项局部行为。始终在线程池写入虽然满足安全端点，但违反九种输入的纯内存写入保留义务。

这些观察取得当前标准文件形式的局部Oracle资格，说明转存前状态与本次写入效果需要分别判断。它们没有产生Graph比较或新模型代码。完整功能、拒绝服务防护和吞吐收益仍未知；自然任务独立单位仍只有一个。

## 输入、环境与复现

政策、来源和输入见[固定设计](2026-11-03-starlette-upload-contract-design.md)。原始程序提交540ff5f076468eb69f827e76cb020e21fb39b3ca，原始归档2583316字节，SHA256为f55e956b05540eba270e22c560bbb898b87e30f8d00cb1d2c3e774dd8dc4ec62。三个控制只改变UploadFile.write，实际来源模块摘要逐项写入原始记录。

实际环境为Python 3.12.16、AnyIO 4.10.0、typing_extensions 4.14.1、idna 3.10、sniffio 1.3.1，使用已有固定镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957。文件和依赖只读挂载，非特权用户、关闭网络、CPU一核、内存2GB，真实临时文件位于/work。

输入包results/starlette-upload-contract-20261103-observed-inputs.tar.gz为2859272字节，SHA256为561ae7818d8114eb7a492d14877c9789916fd6ef28ac0ee7ba1c8f9da46e08d0。服务器工作目录为/home/wsy/work/prompt-mechanism-study/inputs/starlette-upload-contract-20261103-observed，结果为/home/wsy/work/prompt-mechanism-study/results/starlette-upload-contract-20261103-observed-control。

在解压后的工作目录使用现有科学Python执行：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/starlette-upload-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/starlette-upload-contract-20261103-observed-control
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/starlette-upload-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/starlette-upload-contract-20261103-observed-control
```

复现时使用新工作目录和新结果目录；已有结果不覆盖。核对器独立读取全部实际事件，检查底层write与rollover的真实顺序、线程身份、写入前后状态、字节内容、size、位置和完整分配，不共享生产判定函数。

结果摘要2b90dcb87d3d78ec970b69d82142c53dd1d2ac9737095529708a2bf2de275e08；独立核对器摘要13c9750b67eefdbcac2ac19ca1faf5e1316fc53cbb240a3de1fc7ab9686ca175；核对结果摘要59fc3e377fc0b66afe619e0299acf80e5ba5e5c5c7c0bec3bd5324fc33318ff5。完整原始观察、控制输入和核对程序随冻结包保存，不重新解释此前观察。

完整冻结包results/starlette-upload-contract-20261103-frozen.tar.gz为5749511字节，摘要69efc021c596b85a80e74e19d36ed847f7f42de32208d15fa34ecc56bee776f6，本地与服务器archive一致。服务器在新的inputs/starlette-upload-contract-20261103-replay目录解压包内输入，使用包内核对器读取原始结果，核对输出逐字节复现59fc3e377fc0b66afe619e0299acf80e5ba5e5c5c7c0bec3bd5324fc33318ff5，没有重新执行程序或生成代码。

## 后续使用资格

来源已有相关安全要求，Atomic ADD资格保持不成立。该局部测量允许准备固定政策下的表示组件任务；完整公共提示、表示制作、独立参考及新生成的样本数和判断规则仍须事前固定。三个作者控制不进入Graph收益分母，不作为新增自然任务或JCI合格上下文。
