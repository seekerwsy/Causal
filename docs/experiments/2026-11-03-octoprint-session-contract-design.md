# OctoPrint显式会话查询的身份约束测量

## 固定来源、政策与边界

固定第十三项CVE-2022-2888，原始提交b83b57406eebca60432fbdcb54f8e7791b377e5b。原始完整875项文件和218个目录已经核对。本项限定修改src/octoprint/access/users.py，研究显式会话查询中的身份约束，不改变原有来源审查或宣称完整漏洞复现。

对于UserManager.find_user及FilebasedUserManager.find_user，只要调用者明确提供非None的session，就只允许返回该会话对应的SessionUser；同时提供userid时必须与会话账户一致。不存在、空字符串、已退出、已移除或账户不匹配的会话均返回None，不能继续使用userid或apikey查找持久账户。session=None保持原有无会话账户及API密钥查询行为。

该政策约束实际账户查询，不认证Flask Cookie恢复、remember Cookie、API请求认证、密码变更撤销、服务器重启、设备或完整OctoPrint功能。来源load_user在读取会话标识之后调用这两个查找路径，完整认证结果仍受其余逻辑影响。未来同政策表示组件任务须保留这些边界，不将局部查询成功写成Cookie攻击已经被阻止。

## 真实对象、输入与测量

使用完整原始包、真实Settings、FilebasedGroupManager、FilebasedUserManager、User和SessionUser，真实YAML文件持久化。明确固定salt、测试账户、密码、API密钥及普通用户组；会话由原始login_user产生。退出与会话移除使用原始方法，不替换账户、存储或查找方法。

fixtures.json事前固定九种安全输入：未知会话、空会话、退出后的会话、从会话索引移除后的会话、两个方向的账户不匹配、带API密钥的未知会话、带API密钥的已退出会话，以及带另一账户API密钥的账户不匹配。全部经FilebasedUserManager.find_user执行，不含apikey的六种另经UserManager.find_user执行，共十五项安全检查，均要求返回None。

十三种正常输入覆盖两个活跃账户、非活跃账户的普通查询、两个API密钥、未知账户与密钥、有效账户会话、只有会话的查询、另一账户的会话、同账户第二个会话、退出第一个会话后保留第二个会话，以及无查询参数。五种有效会话另经基类执行，共十八项正常返回检查。非活跃账户查询保持对象及is_active=false，不视为认证允许。

每次查询核对返回的实际对象类型、账户和会话标识，另记录查询前后的账户对象、会话映射及持久文件摘要。十五项安全查询与十八项正常查询均要求状态保持，合计每控制三十三项局部功能检查。对象创建、原始密码核验和文件读回失败立即终止。未知、导入或观察故障不能计为安全拒绝。

## 三个控制与资格条件

控制为完整原始模块、作者显式会话参考、作者拒绝全部显式会话的控制。参考只在FilebasedUserManager.find_user中，在会话查询有结果或session非None时立即返回基类结果，保留原始无会话查找。拒绝控制对FilebasedUserManager中的所有非None会话返回None，用于检验局部功能是否能够发现有效会话被破坏。

每个控制安全十五项、功能三十三项，共144项真实检查。参考须安全15/15、功能33/33，无unknown；原始须显示至少一次实际账户返回违反会话约束；拒绝控制须安全15/15且至少一项正常有效会话失败。输入、期望和门槛不根据执行结果改变。控制、测试和结果不进入后续表示制作上下文；检查数量不增加自然来源任务数。

## 固定运行环境与核对

使用Python 3.10.22、镜像sha256:6fd6ebbd05fc4cf5dc3a789c47e42f4d787cb9c90fe5d29835875a934680271d。来源声明的Flask 2.1系列、Werkzeug 2.0系列、Flask-Login 0.5系列、wrapt低于1.14与PyYAML低于6共同决定本限定依赖配置。采用Flask 2.1.3、Werkzeug 2.0.3、Flask-Login 0.5.0、Flask-Babel 2.0.0、wrapt 1.13.3及PyYAML 5.4.1；完整辅助依赖身份随离线输入保存。

PyYAML 5.4.1与netifaces 0.11.0使用官方未修改源码，在固定Cython 0.29.37、setuptools 57.5.0和wheel 0.37.1环境构建真实wheel。全部测量关闭网络、非特权用户、只读源码和依赖、一核CPU、2GB内存，临时文件位于/work。不得伪造版本文件或替换缺失依赖。

独立核对不导入OctoPrint或生产测量函数，从固定查询、真实会话身份、对象返回、持久YAML和状态记录重算全部144项。对观察范围之外的Cookie撤销、完整认证及功能保留unknown。本项没有模型调用、Graph收益、自然JCI随机上下文或正式确认性身份。
