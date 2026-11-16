# HTML最终结构与Unicode规范化的实际测量结果

## 三个完整模块的控制结果

八份安全输入和十六份正常输入分别在两种真实配置下执行。三个控制共192项检查完成，独立DOM核对通过。

| 实际控制 | 最终HTML安全 | 局部功能 | 其中正常内容 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 11/16 | 48/48 | 32/32 |
| 作者解析树值规范化参考 | 16/16 | 48/48 | 32/32 |
| 作者原始字符串前置规范化控制 | 14/16 | 48/48 | 32/32 |

原始模块在NFKC配置下，字面全角及小型尖括号、全角标题引号、实体编码的尖括号和标题引号五条路径实际产生不允许的script或事件属性。href引号输入没有形成不允许的最终属性，按实际安全结果保留。NFC配置的八份输入均通过本项安全规则。

原始字符串前置规范化仍在实体编码的两条路径产生不允许结构。解析树参考先规范化已经解码的text、tail及属性值，保留原有清理和链接规则，并在合并文本后再次规范化树值，全部十六项安全检查通过。三者均保持正常标记、允许格式、链接、空白、尾随文字及跨元素边界合并后的Unicode行为。

这提供了限定最终HTML结构端点的局部测量资格。全部检查来自一个自然来源；没有生成模型调用，没有Graph或Flat收益、真实浏览器脚本执行、完整XSS防护或完整功能结论。来源已有相关安全与Unicode要求，Atomic ADD资格保持不成立。

## 输入、实际环境与独立核对

完整政策、固定输入和事前资格条件见[设计](2026-11-03-html-sanitizer-unicode-contract-design.md)。原始提交207a8927b6d09a37054ba7304a003e1ab2da2290，源码声明版本2.4.1；没有虚构已安装发行元数据。

实际Python 3.12.16、Unicode数据库15.0.0、lxml 5.2.0、libxml 2.12.6、libxslt 1.1.39、lxml-html-clean 0.1.1、beautifulsoup4 4.12.3、soupsieve 2.5、html5lib 1.1、six 1.16.0、webencodings 0.5.1。离线安装七份固定wheel，既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，非特权用户、关闭网络、一核CPU、2GB内存，源码与依赖只读。

生产测量使用html5lib的etree及tree walker，独立核对使用其dom构建器及标准DOM节点接口。两者分别读取实际返回字符串，检查元素命名空间、标签、属性、链接、明确预期内容、标记顺序和规范化。核对程序不调用生产判定或计数函数。它们共享成熟HTML解析库，不提供两个不同浏览器引擎的一致性证明。

执行输入results/html-sanitizer-unicode-contract-20261103-inputs.tar.gz为5295602字节，SHA256为aaff6ea2a60c3e2c02a3600b05117dc68f9cee1a9a02df5829e63bc6a622bc5a，本地与服务器inputs一致。服务器工作目录inputs/html-sanitizer-unicode-contract-20261103，结果目录results/html-sanitizer-unicode-contract-20261103-control，均位于/home/wsy/work/prompt-mechanism-study。

在独立解压的工作副本中执行，结果目录使用新路径：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/html-sanitizer-unicode-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/html-sanitizer-unicode-contract-20261103-control
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/results/html-sanitizer-unicode-contract-20261103-control/dependencies/packages /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/html-sanitizer-unicode-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/html-sanitizer-unicode-contract-20261103-control
```

结果摘要252ee12c132d69b3733af4700f7ede6d4852c599e7f70908184ebefe43791e03；核对器摘要1471d193e10e9236cb815c1fa5d047b68e162bfa36fcea6a6539122773e86eb1；独立核对结果摘要99372ec4e1ef1de63315abc6762daf7f3016f0cad8fccc56e8bdb642c616a7a1。全部实际输入、返回HTML、解析观察、功能判定、程序身份和容器命令保留。

完整冻结包results/html-sanitizer-unicode-contract-20261103-frozen.tar.gz为5306911字节，摘要643a6cb58e0a1935473a7314b99b872e8b1165c0826292c447713118ef361666，本地与服务器archive一致。服务器在新目录inputs/html-sanitizer-unicode-contract-20261103-replay解压，使用包内固定html5lib、six及webencodings的wheel与独立核对程序重新读取全部控制记录，核对结果逐字节复现99372ec4e1ef1de63315abc6762daf7f3016f0cad8fccc56e8bdb642c616a7a1。没有重新执行来源程序或生成代码。

未来表示制作者不读取作者控制、预期答案及实际测量结果。完整共同任务、表示与参考、样本数、预算及比较规则仍须在新代码生成前固定；本项局部测量不提供自然JCI随机上下文。
