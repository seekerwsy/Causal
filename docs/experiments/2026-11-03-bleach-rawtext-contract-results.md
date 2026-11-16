# Bleach原始文本组合的局部测量结果

| 控制 | 限定安全检查 | 局部功能检查 | 未知 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 0/24 | 16/16 | 0 |
| 条件转义参考 | 24/24 | 16/16 | 0 |
| 全局转义控制 | 24/24 | 12/16 | 0 |

全部120项检查已经执行并通过独立核对。安全输入覆盖style、xmp和iframe，两种边界文本、两种strip配置及bleach.clean和Cleaner.clean两个公开入口。每项实际清理输出分别使用html5lib 1.1在启用及禁用脚本的模式重新解析。条件转义参考保留外围段落，禁用脚本解析下保留允许元素，两种模式均满足限定结构政策。全局转义控制改变单独style与xmp的普通输出，两个入口合计四项功能失败。

该结果取得固定HTML片段政策的局部运行测量资格。HTML脚本没有执行，完整浏览器安全和完整Bleach功能仍然未知。模型生成次数为零，Graph代码收益尚未评价。原始程序及两个研究者控制分别保留证据身份。

固定设计为docs/experiments/2026-11-03-bleach-rawtext-contract-design.md，输入为data/method/bleach-rawtext-contract-20261103/fixtures.json。完整输入包摘要c599c790eced99511513c285f37f0c0d8e1a77681e368b9647c3b628b028502f，在代表性和完整运行之前固定。使用Python 3.9 Bookworm镜像sha256:894dd9cb78e93e3c9ef81902619dcda7aeb78ef721ef92abcea9297eea7b293b，依赖版本及wheel摘要见输入文件。源码只读、网络关闭，单核CPU和2GB内存。完整结果位于服务器results/bleach-rawtext-contract-20261103。

run.py接收新的输出目录与representative或full参数。run.sh记录实际代表性、完整运行和独立核对命令。verify.py只读取固定输入、清理输出和来源摘要，重新解析HTML并重算安全与功能分母，不导入Bleach或生产测量函数。实际结果摘要1bceda4b0a002ee19ec760aee6d879c8fbb6c1dce76ccba1b5d10e0c27a4716b，独立核对摘要68ef3bfea97af1b85b7cbf48781dcf9ab5f8cd87e8a2d85a6590c8b309a9dd5c。

完整冻结包results/bleach-rawtext-contract-20261103-frozen.tar.gz为4220449字节，摘要4083f8ccc2508e004b2674773e2964cf4a9ad24f26b16fff78f214aa0f0cd6ac，本地与服务器archive一致。服务器在inputs/bleach-rawtext-contract-20261103-replay独立解压，用包内核对器和固定依赖重新解析全部实际输出，核对JSON逐字节复现。
