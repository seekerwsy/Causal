# Brotli绑定输出与限定资源资格结果

## 判定

固定原始提交`b01b63a467315186a76eae62d84bbd350ca5ccb4`完成真实C扩展编译、162项隔离运行和独立核对。来源测量资格判定为`false`。三个角色各有两项单字节流式运行在固定10秒CPU限制下以返回码`-9`终止；这些记录保留在每角色54项的固定分母中。

公开问题描述针对Scrapy。本次结果只覆盖固定Brotli Python/C绑定的65536字节累计返回政策和限定资源观察。结果没有复现Scrapy漏洞，没有建立完整进程内存保证、完整原生分配保证、Graph收益、自然JCI上下文资格或正式研究结论。

## 编译与输入身份

- 原始源码归档SHA-256：`d8dd99bdaea4f23d9324ed11bab38ffcaa141e0df61cfad5accd8e8686405386`
- 原始`python/_brotli.c` SHA-256：`156dfcb86a2db2ccb5b88e4d26899532cc85b7bcf76375aac69ea7fe43f3e944`
- 测量绑定SHA-256：`f5f566c4bc11fe33b43bad45753cb74be3140f6e67398c33dd99243cfcd567ba`
- 固定协议SHA-256：`8936062b5862da352cdaf6bacfa5acdf8f518163c196147ba37c67c4b015fb49`
- 固定输入包SHA-256：`8f75461c52efdf5b75a078e08e7c934b8adf87a766352fa10fab1fb2f88c849d`
- 环境：Linux x86_64、Ubuntu 22.04、内核`6.8.0-106-generic`、Python 3.12.13、GCC 11.4.0、setuptools 80.10.2
- 编译命令：`/home/wsy/miniconda3/envs/purp/bin/python setup.py build_ext --inplace`
- 原始扩展SHA-256：`ebabed72f1ece6b34ca4d2908a7a1fa252adeab2e6e27958b8e4677a3b5b3bcf`
- 测量扩展SHA-256：`e083964fcf6497702f4f736e930de9c3054b6e0f0b21e19b1d5bfec8afa2e5b1`

每项运行使用512 MiB地址空间限制、10秒CPU限制和20秒外部时限。固定夹具SHA-256为`a4dc1882dc0f5e0634e0790ea100dfa4e1d34cbfa93dbcc31fb0d0d31cacfc37`。

## 控制结果

| 角色 | 安全通过/分母 | 功能通过/分母 | 执行失败 | 判定 |
|---|---:|---:|---:|---|
| `original` | 14/15 | 38/39 | 2 | 已执行控制不受65536字节政策限制；固定分母未完整运行 |
| `reference` | 14/15 | 38/39 | 2 | 已执行超限控制满足事前输出政策；固定分母未完整运行 |
| `late` | 14/15 | 38/39 | 2 | 已执行超限控制在构造载荷后拒绝；固定分母未完整运行 |

六项失败来自三个角色中的同两类单字节流式坐标：一类属于功能分母，一类属于安全分母。所有失败均保留预定角色、检查族和坐标；没有替换输入或减少分母。其余156项运行中，每个角色的三十八项有效解码、六项错误语义检查和八项编码核对均按照预定规则判定。

## 聚合资源观察

下表只聚合成功返回或按政策抛出错误的有效解码运行。`native`字段来自固定Brotli分配器观察；进程最大常驻集来自`ru_maxrss`。

| 角色 | 已执行有效解码 | 最大返回字节 | 最大绑定块容量 | 最大会话绑定预算 | 最大已构造载荷 | 最大原生峰值字节 | 最大常驻集KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| `original` | 38 | 262144 | 360448 | 360448 | 262144 | 290875 | 18432 |
| `reference` | 38 | 65536 | 65536 | 65536 | 65536 | 290875 | 18432 |
| `late` | 38 | 65536 | 360448 | 360448 | 262144 | 290875 | 19456 |

`reference`在已执行运行中将Python返回、绑定块容量、累计绑定预算和已构造载荷限制到65536字节。三个角色的最大原生峰值均为290875字节，说明该Python绑定政策没有约束全部原生分配。`late`仍建立262144字节载荷，保留了事前限制与事后拒绝之间的预定区分。

## 独立核对与冻结产物

独立核对器重新计算八份原始载荷和压缩夹具摘要，核对162个预定坐标、逐项文件摘要、角色分母、错误语义、准确输出、资源不等式及全部边界声明。核对状态为`INDEPENDENTLY_VERIFIED_REAL_BROTLI_BOUND_OUTPUT_MEASUREMENT`，来源测量资格为`false`，新增模型调用为零。

- 服务器输入：`/home/wsy/work/prompt-mechanism-study/inputs/brotli-output-contract-20261103-py312-r3`
- 服务器结果：`/home/wsy/work/prompt-mechanism-study/results/brotli-output-contract-20261103-py312-r3`
- 服务器冻结包：`/home/wsy/work/prompt-mechanism-study/archive/brotli-output-contract-20261103-py312-r3-frozen.tar.gz`
- 本地冻结包：`results/brotli-output-contract-20261103-py312-r3-frozen.tar.gz`
- 冻结包SHA-256：`20bbc870a5d1950b1f094ef4efabfa934c5024b24c9c2aca0120170bb7ec566a`
- `result.json` SHA-256：`09514baa62fc0c3ea6a6a51e02d40aba51789a5f17e2bad5930f24e9a607b954`
- `verification.json` SHA-256：`cce8294cc8e553c2c2ac72cde07ccb75c9ac0f0ad0bac1d8e2aebc1bf17c16eb`

本地冻结包已经重新计算SHA-256，与服务器冻结包逐字节一致。
