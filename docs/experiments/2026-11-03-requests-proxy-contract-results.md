# Requests代理凭据接收位置的真实测量结果

## 代理与应用服务的独立记录

三个完整模块执行153次真实客户请求，形成234项检查；此前三项标准库HTTP、CONNECT及错误CA检查全部通过。实际代理和应用服务分别记录收到的头部，独立核对通过。

| 实际控制 | 应用端凭据安全 | 局部功能 | 代理请求 | 应用请求 |
| --- | ---: | ---: | ---: | ---: |
| 固定原始模块 | 9/27 | 51/51 | 81 | 84 |
| 作者HTTPS头部参考 | 27/27 | 51/51 | 81 | 84 |
| 作者重定向后直接连接控制 | 27/27 | 15/51 | 45 | 84 |

原始模块在十八种组合中把代理认证头部发送到HTTPS应用服务。普通scheme配置的九种组合发送第一个代理的凭据；host配置的九种组合实际使用第一个代理，但把普通后备配置中第二个代理的凭据发送到应用服务。all配置九种没有出现该接收。实际代理仍获得自己正确的认证，代理路由和完整响应全部正常。

参考保留实际代理配置及HTTP和CONNECT认证，在HTTPS目标中不把代理URL认证放入应用请求头部。全部二十七项安全及五十一项功能通过。直接连接控制没有应用端代理凭据，仍在三十六项重定向配置上缺少应有的后续代理请求；它保持实际应用响应，功能只通过十五项。该差异使测量能够识别绕过代理取得安全结果的行为。

目标Authorization、307的POST和二进制正文、重定向Cookie、直接HTTP及HTTPS请求、合法证书和错误CA拒绝在原始及参考中全部保持。三个入口分别为requests.request、Session.request和Session.send。错误CA产生预定SSLError，没有应用请求；它是声明的正常拒绝检查，没有被计为自动安全成功。

HTTPS代理使用标准CONNECT字节转发，代理没有终止隧道内TLS。应用服务通过真实SSL连接取得请求并记录TLSv1.3，实际接收证据来自应用端。只检查PreparedRequest或适配器参数不能提供本项接收证据。

本项取得限定显式HTTP代理配置的局部测量资格。环境代理、NO_PROXY、SOCKS、HTTPS代理、自定义适配器、手工认证头部及完整Requests功能仍未建立。二百三十四项检查来自一个固定来源，不增加自然任务数量，没有模型生成、Graph收益或自然JCI上下文。

## 固定身份、环境及复现

政策、输入及门槛见[设计](2026-11-03-requests-proxy-contract-design.md)。原始提交302225334678490ec66b3614a9dddb8a02c5f4fe，实际模块版本2.30.0，完整100项文件、十五个目录对象与独立来源审查已经核对。源码已有代理认证边界，本项不改变相应Atomic ADD资格判断。

实际Python 3.12.16，标准库TLS使用OpenSSL 3.0.22 25 Aug 2026；urllib3 1.26.18、charset-normalizer 3.3.2、idna 3.10、certifi 2024.8.30、cryptography 42.0.8、cffi 1.17.1及pycparser 2.22。镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，依赖离线安装、外部网络关闭、非特权用户、只读源码及依赖、一核CPU、2GB内存，临时目录/work。五个真实HTTP或HTTPS服务均在同一容器回环地址。

CA、应用证书、私钥及错误CA为事前生成的实际测试材料，三个控制共同使用。应用证书的127.0.0.1 SAN、CA签名及私钥匹配经独立核对，测试私钥权限为0600。没有读取外部凭据。

执行输入.test-tmp/requests-proxy-contract-20261103-inputs.tar.gz摘要1e10cff58a8873fa3d1145b789724bbbca486a84173aefda95e88a7728b116d2，本地与服务器inputs一致。服务器输入目录inputs/requests-proxy-contract-20261103，结果目录results/requests-proxy-contract-20261103，均位于/home/wsy/work/prompt-mechanism-study。在独立输入副本执行，结果目录须尚不存在：

```sh
python3 data/method/requests-proxy-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/requests-proxy-contract-20261103
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/results/requests-proxy-contract-20261103/dependencies/packages /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/requests-proxy-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/requests-proxy-contract-20261103
```

独立核对不导入Requests或生产测量函数，使用email.message.Message和SimpleCookie读取头部与Cookie，独立核对固定请求、代理目标、各自认证、应用请求、方法、正文、重定向、响应及TLS拒绝，再重算全部分母。证书由成熟cryptography解析及验证。实际核对环境为Python 3.12.13，使用冻结依赖。

结果摘要e6683a3a30165e50e61edb4e99c3aa5a9da63cef0a652e224a216ad5477fe37d；独立核对器摘要0a64faf61eb634d63e0f21b8daad9c5bb6bf9a1a47ade3e81c21e1931990671e；核对结果摘要c6921053584b87ec3e5b1fad3bda859d3e19dd813bef70a49ceb4786d57bc4b5。

完整冻结包results/requests-proxy-contract-20261103-frozen.tar.gz为13908861字节，摘要7f0c5099d8d6965356e3526a5b85c29b28cc6f6ba4661b1f66a389af84eca704，本地与服务器archive一致。服务器在新目录inputs/requests-proxy-contract-20261103-replay解压，包内核对器重查全部实际记录，输出逐字节复现c6921053584b87ec3e5b1fad3bda859d3e19dd813bef70a49ceb4786d57bc4b5。未重新运行来源、服务或模型。

完整共同任务、独立表示和新方法评价仍须固定，作者控制、接收记录及答案不进入表示制作上下文。本项没有受保护数据使用或正式确认性身份。
