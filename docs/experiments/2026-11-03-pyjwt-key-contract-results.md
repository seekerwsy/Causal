# PyJWT真实序列化材料与HMAC边界测量结果

## 完整控制结果

二十一份真实密钥或证书材料在三种HMAC算法、两种传入形式和三个入口执行安全检查。三个完整模块共1266项检查完成，独立材料解析、签名验证及结果核对通过。

| 实际控制 | 密钥边界安全 | 局部功能 |
| --- | ---: | ---: |
| 固定原始模块 | 162/378 | 44/44 |
| 作者完整序列化识别参考 | 378/378 | 44/44 |
| 作者只识别公钥及证书控制 | 234/378 | 44/44 |

原始模块拒绝七份PEM公钥、一个证书及OpenSSH RSA公钥，共162项；实际接受P-256、P-384、P-521和Ed25519四份OpenSSH公钥，共72项，并接受五份PEM私钥及三份OpenSSH私钥，共144项。接受不仅发生于准备函数，实际签名、独立伪造令牌的验证和Payload返回也有记录。

公钥及证书控制拒绝全部十三份对应材料，但继续接受八份私钥，共144项。完整参考拒绝全部二十一份材料，三个HMAC算法和两个传入形式均通过本项政策。三者保持二十四项普通HMAC、十一项非对称签名及九项声明和API功能，包含普通秘密中的相似格式文字、空密钥、错误签名拒绝和明确关闭签名验证。

该结果提供当前固定格式与环境内的局部测量资格。它不建立任意格式、加密私钥、其他后端或全部API的安全和完整功能，也不意味着仅允许非对称算法的应用受到同样影响。二十一份材料及1266项检查来自一个自然来源，不扩大任务数量，没有生成模型调用或Graph收益。来源已有密钥边界要求，Atomic ADD资格保持不成立。

## 实际材料、环境与独立核对

完整政策、格式清单和事前资格条件见[设计](2026-11-03-pyjwt-key-contract-design.md)。原始提交24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc，实际源码版本2.3.0。新增作者识别逻辑使用cryptography的成熟加载器，保留原有拒绝规则；不编写PEM、SSH或JWT解析器。

实际Python 3.12.16、cryptography 42.0.8、OpenSSL 3.2.2 4 Jun 2024、cffi 1.17.1、pycparser 2.22、jwcrypto 1.5.6、typing_extensions 4.12.2。使用既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，固定wheel离线安装，非特权用户、关闭网络、源码和依赖只读、一核CPU、2GB内存，临时目录/work。

材料准备程序不导入被测jwt，实际生成六类测试密钥、匹配的错误公钥、证书和全部序列化形式。jwcrypto使用明确oct密钥类型，独立生成63份实际HMAC令牌。固定实际材料文件materials/fixtures.json的摘要为8e296fa4fedffb274763fc052f59e8c3995304b3f70d855b6f7510508ebaeabc；其中私钥全部为公开研究测试材料，不承载服务凭据。

独立核对程序不导入被测jwt或生产探针，重新解析二十一份材料并比较公钥身份、验证证书自签名和全部输入令牌。它逐条核对1134项实际拒绝或接受记录，并验证实际输出令牌签名、Payload、132项功能判断、输入及源码摘要和完整分母。成熟密码学依赖共享，PyJWT的密钥分类、签名及解码实现不作为独立核对逻辑。

执行输入results/pyjwt-key-contract-20261103-inputs.tar.gz为4638079字节，摘要a030c01ec945df2e0fdf8d41f25b17e16fbfd16589e48d1bbac6c441b38b4e4e，本地与服务器inputs一致。服务器输入目录inputs/pyjwt-key-contract-20261103，结果目录results/pyjwt-key-contract-20261103-control，均位于/home/wsy/work/prompt-mechanism-study。

在独立工作副本中执行，使用新结果目录：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/pyjwt-key-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/pyjwt-key-contract-20261103-control
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/results/pyjwt-key-contract-20261103-control/dependencies/packages /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/pyjwt-key-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/pyjwt-key-contract-20261103-control
```

重新执行材料准备会得到新的随机测试密钥，不能覆盖当前实际输入。冻结包保留全部实际材料、原始结果、依赖及独立核对程序，读取冻结记录可重复核对同一组输入。

结果摘要ac5a5c0d091e3953314645a9e24fe0c9289cfd18e26f1b19e0e4f582f8633c30；核对器摘要e6c352c684d7761548c163e321a8884e962059a09037426de2f64b068bfc70a2；独立核对结果摘要63ec3022e43a454b461b9ededc41ce56be018663ac010fa5f1bb596e02a0425b。

完整冻结包results/pyjwt-key-contract-20261103-frozen.tar.gz为9199193字节，摘要f4fae3ab2e533268315aca6159bf8febdbd46a65db366656b80f283c131d52be，本地与服务器archive一致。服务器在新目录inputs/pyjwt-key-contract-20261103-replay解压完整实际材料、依赖及结果，用包内独立核对器重查全部记录，核对输出逐字节复现63ec3022e43a454b461b9ededc41ce56be018663ac010fa5f1bb596e02a0425b。没有重新生成密钥、执行来源程序或调用生成模型。

后续共同代码生成任务、独立表示及参考、全部样本、预算和比较规则仍须固定。材料、作者控制、签名令牌和实际测量结果不进入表示制作上下文；本项测量不提供自然JCI随机上下文。
