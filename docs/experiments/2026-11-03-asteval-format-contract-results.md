# Asteval真实格式化属性边界测量结果

## 实际控制结果

固定六项安全输入、十六项正常功能输入在两个实际解释器控制上全部执行，共44项检查，独立核对通过，安全unknown均为零。

| 实际控制 | 安全检查 | 正常局部功能 |
| --- | ---: | ---: |
| 固定原始Interpreter | 2/6 | 16/16 |
| 作者格式说明边界参考 | 6/6 | 16/16 |

原始AST路径拒绝直接访问__globals__和__code__。同一原始解释器的动态格式说明路径实际返回了受保护字典内的研究测试标记及代码对象的参数数量。另两项输入通过用户异常处理中的obj取得同一受保护字典或代码对象，实际对象身份核对为真。

作者参考保持原始值、说明表达式和!s/!r/!a转换求值，使用内置format处理最终说明；六项输入均被已有属性或格式边界拒绝，没有暴露上述对象，十六项正常功能全部保持。前十五项功能取得独立CPython语言参照，另有正常try/except结果。

这些结果提供动态说明、受约束属性和异常对象之间的局部测量资格。未生成模型代码，没有Graph效果或新的JCI上下文；完整解释器安全、NumPy行为、任意代码执行及完整CVE利用仍未建立。该来源已有安全要求，其Atomic ADD资格保持不成立。

## 输入、构建和复现

政策、有限输入、真实函数和判断条件见[固定设计](2026-11-03-asteval-format-contract-design.md)。原始提交b57e8c07fe5e8cdde6e2f569e4b5a2e5e413890d，原始归档47034字节，摘要9e341784b53fa061468260a3f9f0ad889323b77a43d534a500999c2d5272df69。

实际Python 3.12.16使用已有固定容器镜像，关闭网络、非特权用户、一核CPU和2GB内存。原生构建工具离线安装至独立依赖目录，再由原项目setuptools配置生成版本文件与wheel。构建标识0+git.b57e8c07明确表示固定提交的本地包，未声称上游发布版本。生成wheel摘要697fcd2170140a82bd2c974aa0f510baf08101d6d2f99da100eb2a09863eaf72；生成版本文件摘要ff08b1addd5111e9dcd4eb9623780a526c43155d2443dac3b571b0a06490d295。实际执行前全部原始asteval包内Python文件均与固定Git快照逐项SHA256相同。

执行输入包results/asteval-format-contract-20261103-installed-inputs.tar.gz为1427643字节，摘要2d5a14f5ab94500e7732af9bf2e99b8ba420f5c9ca3e38ecb01285ec40d32df2。服务器输入目录/home/wsy/work/prompt-mechanism-study/inputs/asteval-format-contract-20261103-installed，结果目录/home/wsy/work/prompt-mechanism-study/results/asteval-format-contract-20261103-installed-control。

在独立解压的工作目录中运行：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/asteval-format-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/asteval-format-contract-20261103-installed-control
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/asteval-format-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/asteval-format-contract-20261103-installed-control
```

复现使用新的输入副本和结果目录，已有记录不覆盖。独立核对器不调用生产计数函数，重新检查完整输入身份、测试标记与代码属性的实际字符串观察、对象身份记录、错误类别及十六项明确语言结果。

结果摘要6e50508d336cd6fed089f55ed146de2d17efaa67711cb581a1a8cf0c1c27de96；核对器摘要269acc528b640be76e3b1f04510bf4ca4be7d4599307b8543c32974ae756a077；独立核对结果摘要bfafce5817d1cd55b11c02a7474ab03629fef4b268909fd19e913bdc80c94eea。原始构建和观察记录随冻结资料保留。

完整冻结包results/asteval-format-contract-20261103-frozen.tar.gz为2989065字节，摘要600fcc184355c6f3098958261ad271212b21f01500f31c31cef3f60c1069368c，本地与服务器archive一致。服务器在新的inputs/asteval-format-contract-20261103-replay目录解压冻结输入，使用包内核对器读取全部实际记录，输出逐字节复现bfafce5817d1cd55b11c02a7474ab03629fef4b268909fd19e913bdc80c94eea，没有重新生成或执行候选。
