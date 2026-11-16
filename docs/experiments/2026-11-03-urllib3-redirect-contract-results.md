# urllib3默认跨源头部删除的实际接收测量

## 实际控制结果

完整原始包与两个作者控制共完成303次客户调用，形成462项检查。三个控制分别记录197次应用请求和六次真实CONNECT代理请求；标准库HTTP转发、CONNECT及错误CA三项传输检查全部通过。独立核对不导入urllib3或生产测量函数。

| 控制 | 默认跨源凭据安全 | 局部功能 | 最终接收普通代理凭据 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 0/54 | 100/100 | 54 |
| 作者默认集合参考 | 54/54 | 100/100 | 0 |
| 作者无条件删除控制 | 54/54 | 88/100 | 0 |

原始模块在三种跨源路线、三种头部形式、三种默认Retry入口及两个调用入口的全部54项配置中，将初始普通Proxy-Authorization继续发送到最终应用服务。初始接收者得到调用者明确提供的凭据，重定向后由真实HTTP或HTTPS应用服务记录接收位置。

参考只增加默认删除集合中的Proxy-Authorization，保留已有Authorization和Cookie默认删除。显式空、自定义删除集合、同源头部、非敏感字段、303方法与正文、禁止跟随、管理器默认头部、后续独立请求及独立代理认证全部通过。无条件删除控制在显式空和仅Authorization集合的十二项配置中破坏调用者保留Proxy-Authorization的明确要求，功能为88/100。

真实ProxyManager通过proxy_headers配置代理专用认证，代理收到正确CONNECT认证，TLS应用端不收到该专用头部。它与调用者放入普通请求的同名头部分别测量。普通显式请求头部没有被增加普遍不变的要求；管理器默认头部的复制与后续独立请求分别检查。

unknown及后端错误均为零。该结果建立限定默认跨源政策的局部测量资格。各项检查属于同一个来源，不能增加自然任务数量；没有生成模型调用、Graph代码收益或自然JCI随机上下文。

## 身份、环境与复现

完整政策及输入见[设计](2026-11-03-urllib3-redirect-contract-design.md)。来源CVE-2024-37891，固定原始提交29cfd02f66376c61bd20f1725477925106321f68，实际包版本1.26.18。只替换完整src/urllib3/util/retry.py，其他源文件保持原样。来源已有跨源敏感头部要求，相应Atomic ADD资格判断保持。

Python 3.12.16镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，OpenSSL 3.0.22 25 Aug 2026；cryptography 42.0.8、cffi 1.17.1、pycparser 2.22离线安装。外部网络关闭、源码及依赖只读、非特权、一核CPU、2GB内存，临时目录/work。真实证书的签名、SAN及密钥匹配由cryptography独立核对，没有读取外部凭据。

实际接收逻辑位于src/measurement/urllib_redirects.py，复用未修改的proxy_credentials.py传输与证书准备脚本。执行输入.test-tmp/urllib3-redirect-input-20261103.tar.gz摘要2ede3ff885bfe9227a196bcfdb72f596157eb5127cf6fba856f1b5b6bc0f5812。服务器在/home/wsy/work/prompt-mechanism-study/inputs/urllib3-redirect-contract-20261103解压执行，结果在同一项目results/urllib3-redirect-contract-20261103。新的输出目录须尚不存在：

```sh
python3 data/method/urllib3-redirect-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/urllib3-redirect-contract-20261103
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/results/urllib3-redirect-contract-20261103/dependencies/packages /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/urllib3-redirect-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/urllib3-redirect-contract-20261103
```

独立核对按固定矩阵重新构造100项输入，使用email.message.Message读取实际头部，独立检查路径、方法、正文、响应、Retry历史、代理认证和全部分母。303历史记录的是转换后的GET方法，初始实际请求仍为POST。源码身份、依赖、证书及实际输出摘要一并核对。核对环境为科学Python 3.12.13。

result.json摘要a4b854d1ae433b49bf9129e0430f1e5f0a424b5466980a13aa4ce966e31ff7ed；独立核对器摘要d9fe80726098e1f1b69cd9370b8735c0ef85004d0d2a8d86c495194dc69390c9；verification.json摘要6e99e1f70fb31c8e45c9cd2e3b3d1b83d56b061f969c6f0f2e46fb4f17a9cbdd。完整冻结包results/urllib3-redirect-contract-20261103-frozen.tar.gz为14708634字节，摘要1c5456f7449a0e0369efea76bd82bfcfee7be0e11c174e2dcc1a632603a382a7，本地与服务器archive一致。

服务器在新目录inputs/urllib3-redirect-contract-20261103-replay解压，用包内独立核对器重新计算全部实际记录，核对JSON逐字节复现。没有重新执行来源、服务或模型。完整表示任务、独立表示参考和整轮预算规则仍须完成；作者控制及测试答案不进入表示制作上下文。
