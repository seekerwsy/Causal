# Markdown包含替换位置的真实测量结果

## 三个完整模块的控制结果

十二份安全输入和二十份正常输入经底层get_file_content和真实插件事件执行。三个模块共192次实际处理、264项检查完成，独立核对通过，两个入口结果一致。

| 实际控制 | 完整位置安全 | 局部功能 | 其中正常输入 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 2/24 | 64/64 | 40/40 |
| 作者完整位置参考 | 24/24 | 64/64 | 40/40 |
| 作者仅保护页面原文控制 | 14/24 | 64/64 | 40/40 |

原始模块仅在没有真实包含指令的普通标记输入上通过，页面文字与已经恢复的内容都可能获得错误替换。仅保护页面原文的控制保持五种页面标记及嵌套页面中的字面位置，仍在五种先恢复内容上发生后续替换，共十项失败；其中recursive=false保留的内部指令没有执行，但同一内容中的相似标记仍被错误替换。

完整参考避开页面字面标记，并在一次统一替换中恢复所有登记位置，二十四项安全检查通过。普通包含、多个文件、相对路径、过滤、换行、缩进、嵌套开关、Markdown链接、注释、标题、排除和自定义指令的四十项检查在三者中全部保持。安全输入的二十四项局部功能另行核对前后普通标记及实际文件读取；它们通过不表示完整替换政策已经满足。

Python audit hook记录处理期间的真实open事件，打开文件及顺序符合事前期望，未发生写入打开。输入文件在实际容器中只读，独立核对也检查全部文件字节。该证据提供限定Markdown返回内容完整性的局部测量资格，没有最终HTML、浏览器利用、全部插件功能或Graph收益。全部输入来自一个自然来源，不扩大独立任务数量。

## 输入、环境和独立复现

完整政策、固定期望和资格条件见[设计](2026-11-03-mkdocs-include-contract-design.md)。原始提交1ae8fca510cb5b18f164aaefb855a07f522ec8ff，实际读取原始项目元数据版本7.1.7。来源已有占位符碰撞问题，Atomic ADD资格不因本项测量改变。

实际Python 3.12.16、MkDocs 1.6.0、wcmatch 10.0、bracex 2.5.post1；其余固定依赖为click 8.1.8、colorama 0.4.6、ghp-import 2.1.0、Jinja2 3.1.6、MarkupSafe 2.1.5、Markdown 3.7、mergedeep 1.3.4、mkdocs-get-deps 0.2.0、packaging 24.2、pathspec 0.12.1、PyYAML 6.0.2、pyyaml-env-tag 0.1、watchdog 6.0.0、platformdirs 4.3.8、python-dateutil 2.9.0.post0及six 1.16.0。十九份wheel的完整名称与摘要保留于dependencies.json。

使用既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，全部依赖离线安装，非特权用户、关闭网络、源码及依赖与输入只读、一核CPU、2GB内存，临时目录/work。实际插件路径使用MkDocsConfig、Page、File、Files和插件配置加载；没有替换文件读取或包含回调。

执行输入results/mkdocs-include-contract-20261103-inputs.tar.gz为5613529字节，摘要d1c55668400c3817681b7d0647c9e1dca7d65715ada1df33fea1334c1c97b8da，本地与服务器inputs一致。服务器输入目录inputs/mkdocs-include-contract-20261103，结果目录results/mkdocs-include-contract-20261103-control，均位于/home/wsy/work/prompt-mechanism-study。

在独立工作副本中执行，使用新结果目录：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/mkdocs-include-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/mkdocs-include-contract-20261103-control
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/mkdocs-include-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/mkdocs-include-contract-20261103-control
```

独立核对程序不导入被测插件或生产测量，直接核对全部输入文件、完整预期字符串、实际返回内容和文件打开记录，重算全部264项检查及入口分母。它不重新实现Markdown或包含指令解析器。

结果摘要0732da30aa26f4dab746f073b30af7a752cd0f815f85f5921cb1bd707286f1b6；核对器摘要166b0b1c9263c5f3270e2f04e3ef9459d146ea263406739bcf169413e98e0f24；独立核对结果摘要5c8c084dc27d1757e8609b1836da3b27e5bec6dc94e72b48ee2d1978a16c223d。原始输入、真实返回、open事件、环境及程序身份保留。

完整冻结包results/mkdocs-include-contract-20261103-frozen.tar.gz为5627227字节，摘要942403ef9e465437a97d91589a8c295e83d3568334dcaff5bf9eb8d46f2a056c，本地与服务器archive一致。服务器在新目录inputs/mkdocs-include-contract-20261103-replay解压，用包内独立核对器重查全部输入文件及实际记录，核对输出逐字节复现5c8c084dc27d1757e8609b1836da3b27e5bec6dc94e72b48ee2d1978a16c223d，没有重新执行来源或生成代码。

未来完整生成任务、独立表示及参考、全部样本、预算和比较规则仍须在新代码生成前固定。作者控制、期望字符串和测量结果不进入表示制作上下文；本项不提供自然JCI随机上下文或新增Graph代码收益。
