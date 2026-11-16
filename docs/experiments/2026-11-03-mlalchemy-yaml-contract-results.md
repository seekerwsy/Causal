# MLAlchemy数据构造的局部测量结果

| 控制 | 限定安全检查 | 局部功能检查 | 未知 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 0/12 | 26/26 | 0 |
| 安全数据构造参考 | 12/12 | 26/26 | 0 |
| 拒绝全部YAML控制 | 12/12 | 16/26 | 0 |

全部114项检查完成，独立核对与固定包复现通过。十二项原始输入均实际创建了测试文件，即使后续查询处理以异常终止，文件副作用仍然计为安全失败。输入覆盖两个文件构造函数、三个输入位置及两种标签形式。安全数据构造参考拒绝这些标签且没有创建文件。拒绝全部YAML控制破坏十项正常YAML输入，JSON及字典入口的十六项功能保持。

正常功能包含真实SQLAlchemy查询对象及SQLite查询结果，覆盖八项普通查询的三个入口，以及日期和共享引用两项YAML输入。独立核对器未导入MLAlchemy或生产测量函数，使用标准库SQLite与固定SQL重算结果，核对实际标记文件、原始输入、子进程终止状态和普通查询对象。三个控制的全部异常、失败与分母均保留。

固定设计为docs/experiments/2026-11-03-mlalchemy-yaml-contract-design.md。测量入口data/method/mlalchemy-yaml-contract-20261103/run.py接收新的输出目录及representative或full；run.sh先执行代表性运行与独立核对，通过后执行完整矩阵。独立核对入口verify.py接收已有结果目录与新的核对JSON路径。输入包摘要36b350c00420012f1d6c61f5b8600ddc6b60326c25e075516759a19d6e8b0834，在首次来源执行前固定。

实际环境为Python 3.9 Bookworm镜像sha256:894dd9cb78e93e3c9ef81902619dcda7aeb78ef721ef92abcea9297eea7b293b、SQLAlchemy 1.3.24、future 1.0.0和PyYAML 3.13官方纯Python实现。依赖全部满足原始requirements.txt的版本范围。PyYAML源码摘要3ef3092145e9b70e3ddd2c7ad59bdd0252a94dfe3949721633e41344de00a6bf，实际构建wheel摘要f104cfbbe38cdc05e3376657f97f78eb491f591292b46fd2aa1c1c9032ff65fb。原始源码及依赖没有修改，--without-libyaml为依赖自身提供的构建选项。

实际完整结果位于服务器results/mlalchemy-yaml-contract-20261103，结果摘要6de8d7eec6aebb3f6d89eaf1ecb575d86c481a9b2fb9c905779bdda085e15906，独立核对摘要e337517e3da4eb5321df0e34ed2f1d0a188bdb592e7f095716f951bfc4e7ae2e。完整固定包results/mlalchemy-yaml-contract-20261103-frozen.tar.gz为9614948字节，摘要9ededa2a55ca111566ffe67f7e8fe3ba985ec4def4d3906b71c6617b2a076f73，本地与服务器archive一致。服务器在inputs/mlalchemy-yaml-contract-20261103-replay独立解压，重新执行包内核对器，核对JSON逐字节复现。

该结果取得固定环境下数据构造和局部查询端点的测量资格。原始宽范围依赖在其他版本中的行为、完整资源保证和完整应用安全仍然未知。程序测试记录和探针来自同一个固定来源，不增加自然任务数量。模型生成次数为零，Graph表示准确性、代码收益和自然JCI上下文尚未建立。
