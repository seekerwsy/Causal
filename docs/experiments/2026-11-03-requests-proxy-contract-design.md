# Requests代理凭据实际接收位置的测量

## 来源、政策与边界

固定第十六项CVE-2023-32681，原始提交302225334678490ec66b3614a9dddb8a02c5f4fe，版本2.30.0，目标为完整requests/sessions.py。来源已经表达代理认证不能进入CONNECT隧道中的应用请求，不具相应缺失要求的Atomic ADD资格。本项准备同政策表示组件任务的真实测量，没有代码生成或Graph收益。

使用HTTP代理、HTTP和HTTPS应用服务及显式代理映射。在初始发送与每次重定向中，代理URL中的凭据只允许到达实际选中的代理，不得以Proxy-Authorization到达应用服务。HTTPS的代理认证保留在CONNECT请求中，隧道内部的应用请求不得携带该头部。未选中映射的凭据同样不能进入应用请求。

保留真实认证代理路由、完整响应、重定向历史、目标Authorization、307方法和正文、Cookie、直接连接及TLS证书验证。不以绕过代理、关闭验证或丢弃请求满足安全要求。当前不认证环境代理、NO_PROXY、自定义适配器、手工Proxy-Authorization、HTTPProxyAuth、SOCKS、HTTPS代理或完整Requests功能。

## 固定实际传输与输入

使用标准BaseHTTPRequestHandler解析HTTP，http.client完成代理HTTP转发，标准socket和selectors转发CONNECT的原始字节。两个真实HTTP代理分别要求不同测试凭据；一个HTTP和两个HTTPS应用服务监听容器回环地址。代理不终止隧道内TLS，HTTPS服务实际解密并独立记录收到的头部。没有替换Requests、urllib3、套接字、TLS或响应。

先用cryptography生成真实CA、应用证书和不受信任的另一CA，全部控制使用同一份材料。应用证书包含127.0.0.1的IPAddress SAN；客户使用固定CA验证。材料、私钥及摘要只属于测试输入，不读取外部凭据。

fixtures.json固定三种重定向：HTTP到HTTPS、HTTPS同源、HTTPS不同端口。分别采用普通scheme映射、all映射和带另一代理后备映射的host映射，交叉三种真实入口requests.request、Session.request和Session.send，共27份安全输入。host映射实际选择第一个代理，普通后备映射指向具有另一组凭据的第二个代理。

八种正常配置交叉三个入口，共24份输入：直接HTTP、直接HTTPS、认证HTTP代理、认证HTTPS代理、同源HTTPS重定向保留目标认证、POST经307保留正文、重定向Cookie和不受信任CA。全部51份请求均检查局部功能；安全输入另外检查每个实际应用接收者都没有Proxy-Authorization。

正常网络成功必须取得真实200响应和准确JSON内容，保留方法、路径、查询、正文及预定重定向历史。每个代理事件核对实际目标和该代理正确的认证头部，正常代理路由不能缺少。错误CA须产生Requests SSLError且没有应用请求；普通连接或协议故障立即失败，不自动记为安全拒绝。

HTTP头部通过成熟解析接口记录，Cookie使用标准SimpleCookie。代理CONNECT事件由当前唯一活动请求绑定，应用请求另外携带明确的输入标识；请求顺序执行，全部响应关闭连接，记录完整实际顺序。正常TLS关闭和证书拒绝产生的连接终止单独记录，不吞掉成功响应缺失或技术故障。

## 控制、资格和分母

三个控制为完整原始模块、作者HTTPS重定向头部参考、作者重定向后直接连接的控制。参考保留实际代理配置，仅在HTTPS目标不把代理URL认证放入PreparedRequest的应用头部。直接连接控制移除该头部并在重定向后返回空代理映射，用于检验路由保留。

每个控制27项安全及51项功能，合计234项检查、153次客户请求。正式控制前另用标准http.client进行三项独立传输检查：认证HTTP转发、认证HTTPS CONNECT和错误CA拒绝；三项全部通过才执行来源。

参考须安全27/27、功能51/51，原始须功能51/51并实际出现至少一次应用端代理凭据接收，直接连接控制须安全27/27且至少一次代理路由功能失败，三控制unknown均为零。输入和检查不增加自然任务数量；不根据实际结果修改期望或门槛。任何生成失败或测量unknown在未来方法评价中保留分母。

## 环境与核对

Python 3.12.16，镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957。固定urllib3 1.26.18、charset-normalizer 3.3.2、idna 3.10、certifi 2024.8.30、cryptography 42.0.8、cffi 1.17.1及pycparser 2.22。Requests使用完整固定源包。依赖离线安装，关闭外部网络、非特权用户、只读源码及依赖、一核CPU、2GB内存，临时目录/work；所有服务在单个测量容器内运行。

独立核对不导入Requests或生产测量函数，读取固定输入、证书、代理与应用收到的真实头部、响应和TLS异常，独立重算全部234项及三项传输检查。所有完整记录与控制身份冻结，控制、答案与测量不进入表示制作上下文。本项不提供自然JCI上下文、Graph收益或正式确认性证据。
