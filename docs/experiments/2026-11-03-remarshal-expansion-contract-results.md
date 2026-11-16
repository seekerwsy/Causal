# Remarshal解析后展开限额的真实测量结果

## 对象数量、时序与局部保留

十一份安全YAML、十八份正常YAML及四份非YAML输入通过实际源接口执行，另运行四种原生命令行情形。三个控制共603次调用和检查，独立核对通过。

| 实际控制 | 解码后完整政策 | 局部功能 | 共享输入政策失败 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 0/79 | 122/122 | 28 |
| 作者逐路径展开检查参考 | 79/79 | 122/122 | 0 |
| 作者唯一对象计数控制 | 51/79 | 122/122 | 28 |

四种无循环共享输入的展开数量分别301、287、395及365，唯一对象分别13、10、11及77。唯一对象控制在这四种输入的两个直接解码及五种输出路径上均未满足政策，共二十八项失败；它对平面超限和四种循环的拒绝保持。参考逐路径累计每次出现，在全部要求的位置之前拒绝，七十九项安全检查通过。

原始实现对直接解码返回完整超限或循环对象，转换路径进入解包、包装、编码或递归遍历；部分输出路径之后发生异常，仍按政策失败记录。source观察由sys.settrace提供，记录实际函数调用及AST定位的阶段访问，不阻止或替代执行。原生CLI另核对真实退出状态和输出，阶段时序由相同源实现的API记录承担。

恰好256节点的序列和映射、有限共享引用、二进制、带时区时间戳、omap及set的声明路径均保持。非YAML的四种输入包含超过YAML限额的普通数据，八项解码和转换检查保持。三个控制的122项功能均通过，无unknown；排序按原有格式选项执行。

该结果提供解析后对象政策的局部测量资格，不认证YAML解析资源、标量大小、总内存、任意transform或完整拒绝服务防护。这里的对象图用于输入数量与循环判断，不具有Prompt TSG、因果图或JCI上下文身份。全部探针来自同一固定来源，不增加自然任务数量，没有Graph生成收益。

## 固定输入、环境与独立复现

完整政策和资格条件见[设计](2026-11-03-remarshal-expansion-contract-design.md)。原始提交d95a1846b9e54efeb570ce80f93f24ab13db9976，实际模块版本0.17.0。原始归档27482字节，摘要9b85277bc7c2fb9a9f4fdda9b8de74e01d8cb42a5ed7acfeaeafd67dac6991ea，完整43项文件及四个目录对象已经核对。

实际Python 3.12.16，镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957；cbor2 5.6.5、python-dateutil 2.9.0.post0、PyYAML 6.0.2、tomlkit 0.12.5、u-msgpack-python 2.8.0、six 1.16.0及NetworkX 3.3。全部离线安装，关闭网络、非特权用户、源码和依赖只读、一核CPU、2GB内存，临时目录/work。

执行输入.test-tmp/remarshal-expansion-contract-20261103-measurement-inputs.tar.gz摘要a4ebcfe5dacfe39975b679f07ae6d0c35bb064a1b876c2c8a1dfccae99e274fb，本地与服务器inputs一致。服务器输入目录inputs/remarshal-expansion-contract-20261103-measurement，结果目录results/remarshal-expansion-contract-20261103-measured，均位于/home/wsy/work/prompt-mechanism-study。在独立输入副本执行，结果目录须尚不存在：

```sh
python3 data/method/remarshal-expansion-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/remarshal-expansion-contract-20261103-measured
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/results/remarshal-expansion-contract-20261103-measured/dependencies/packages /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/remarshal-expansion-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/remarshal-expansion-contract-20261103-measured
```

输入资格采用NetworkX MultiDiGraph及反向拓扑累计。独立核对不导入Remarshal或生产测量函数，通过标准库TopologicalSorter和独立对象包含表重新计算循环与展开次数，核对全部输入字节、源码、实际返回、阶段计数及编码输出。TOML使用标准库tomllib，其他格式使用成熟读取接口。核对环境为Python 3.12.13，使用冻结依赖。

结果摘要4ef909497805dff5e344ef9455772603720a0fe8c6882ed59042b5ee6b583cf1；独立核对器摘要0c255ad1fbf50376796157a1c6ebe12d37fa7d219185077633c69b1335806cf4；核对结果摘要a3b7b33c86c39331db6e4fe3dc3c8f517d3b1bf9623217d453986e67feccf5af。

完整冻结包results/remarshal-expansion-contract-20261103-frozen.tar.gz为5927691字节，摘要4b04a5b723e34aa582426fbc1e4a4a84fee6070bd565435322d43348b0da26a6，本地与服务器archive一致。在新目录inputs/remarshal-expansion-contract-20261103-replay解压，包内核对器重新检查全部实际记录，输出逐字节复现a3b7b33c86c39331db6e4fe3dc3c8f517d3b1bf9623217d453986e67feccf5af。没有重新执行来源或生成代码。

完整共同任务、表示及新方法评价协议仍须固定。作者控制、输入答案和运行结果不进入表示制作上下文，本项没有受保护数据使用、模型调用或正式确认性身份。
