# OctoPrint显式会话查询的真实测量结果

## 身份查找与局部功能

九种安全输入和十三种正常输入通过真实FilebasedUserManager及适用的基类入口执行。三个控制共九十九次查询、144项检查，独立核对通过。

| 实际控制 | 会话身份安全 | 局部功能 | 其中正常返回 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 6/15 | 33/33 | 18/18 |
| 作者显式会话参考 | 15/15 | 33/33 | 18/18 |
| 作者拒绝全部显式会话控制 | 15/15 | 28/33 | 13/18 |

原始基类在六项无效会话查询中返回None；文件账户管理器的九项相应输入均继续返回持久账户，包括空字符串、退出及索引移除后的会话、账户不匹配和API密钥分支。参考保留基类会话查询结果，明确提供session时不再进入持久账户分支，十五项身份检查全部通过。

拒绝全部显式会话的控制满足拒绝要求，仍破坏五项有效会话查询，包括同账户第二个会话和退出另一会话后的保留。原始与参考的十八项正常返回均保持；三控制全部查询均未改变持久账户、会话映射或用户文件。非活跃账户的普通查询返回对象并保留is_active=false，没有将它解释为认证通过。

实际使用完整原始Settings、组管理器、文件账户管理器、User和SessionUser，真实持久YAML及原始login_user、logout_user和会话移除方法。设置文件事前提供固定测试salt和全局API密钥，账户、密码和会话分别由原始方法创建。没有替换源对象、查找方法或存储。

本项取得显式会话查询政策的局部测量资格，没有完整Cookie恢复或撤销、密码修改后认证、remember Cookie、设备行为或完整OctoPrint功能证据。来源已有审查中的这些未知结论保持。九十九次查询属于同一固定来源，不能扩大独立任务数量；当前没有模型生成、Graph收益或自然JCI随机上下文。

## 原始身份、环境与复现

完整政策和事前门槛见[设计](2026-11-03-octoprint-session-contract-design.md)。原始提交b83b57406eebca60432fbdcb54f8e7791b377e5b，实际使用已核对完整原生归档，摘要b877e805cf5f55db6bb28394788b60ad85a9a3974cd485eaa0806472a7b24c56。未安装归档的版本接口实际返回0+unknown、revision=None；来源身份由完整Git对象与文件摘要确定，没有手写版本或宣称已安装发布版本。

实际Python 3.10.22，镜像sha256:6fd6ebbd05fc4cf5dc3a789c47e42f4d787cb9c90fe5d29835875a934680271d。核心依赖Flask 2.1.3、Werkzeug 2.0.3、Flask-Login 0.5.0、Flask-Babel 2.0.0、wrapt 1.13.3及PyYAML 5.4.1符合来源声明范围。其余为Babel 2.10.3、Jinja2 3.0.3、MarkupSafe 2.1.5、blinker 1.6.3、certifi 2024.8.30、charset-normalizer 3.3.2、click 8.1.8、frozendict 2.3.8、idna 3.10、itsdangerous 2.1.2、netaddr 0.8.0、netifaces 0.11.0、pytz 2022.7.1、requests 2.31.0、urllib3 1.26.20及webassets 2.0。

PyYAML及netifaces由官方未修改源码离线构建，真实wheel、安装包、命令和输出均保存；PyYAML实际启用LibYAML。构建使用Cython 0.29.37、setuptools 57.5.0及wheel 0.37.1，构建临时目录允许加载原生扩展。源测量非特权、关闭网络、只读源码与依赖、一核CPU、2GB内存，临时目录/work。

服务器当前输入为inputs/octoprint-session-contract-20261103-execution，结果为results/octoprint-session-contract-20261103-lookup-controls，均位于/home/wsy/work/prompt-mechanism-study。在独立输入副本执行，结果目录须尚不存在：

```sh
python3 data/method/octoprint-session-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/octoprint-session-contract-20261103-lookup-controls
python3 data/method/octoprint-session-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/octoprint-session-contract-20261103-lookup-controls
```

独立核对程序不导入OctoPrint或生产测量函数。它解析保存的实际YAML，独立核对密码摘要、账户、组、API密钥、会话UUID与每个操作后的索引，再从实际返回和状态记录重算全部安全及功能检查。既有核对环境Python 3.10.12、PyYAML 5.4.1；未重新执行来源或创建会话。

结果摘要4b162f619d3ddbf10041b73a9f0be5cd12389384a2919670fea1e246a40b7f5b；独立核对器摘要793bba199e0506dee5d73498d72d191ac78419c70eba7d023f80b14761c62954；核对结果摘要3bf79301ebbbea83162916d57192339e7dcd43d7ac8b018096a6320b2eb150ae。

完整冻结包results/octoprint-session-contract-20261103-frozen.tar.gz为36703639字节，摘要0f1a12c4086f02733df41e8fdb3517cdacc8e4832a9c794c91bf4f9ebfba287b，本地与服务器archive一致。在新目录inputs/octoprint-session-contract-20261103-replay解压，包内核对器重查全部实际记录，逐字节复现3bf79301ebbbea83162916d57192339e7dcd43d7ac8b018096a6320b2eb150ae。完整共同任务、表示和新生成协议仍须固定，作者控制和测量答案不提供给表示制作者。
