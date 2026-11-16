# Flask-CORS真实请求路径的政策测量结果

## 完整控制结果

三个完整模块分别通过立即初始化、延迟init_app和Blueprint注册执行全部固定请求，共342次真实WSGI请求、414项检查。独立核对完成，三个入口的各项结果一致。

| 实际控制 | 禁止Origin安全 | 局部功能 | 其中普通功能 |
| --- | ---: | ---: | ---: |
| 固定原始模块 | 0/24 | 90/114 | 66/66 |
| 作者直接request.path参考 | 24/24 | 114/114 | 66/66 |
| 作者仅保留unquote控制 | 12/24 | 102/114 | 66/66 |

原始模块在四种目标路径的GET和OPTIONS中均对禁止Origin返回了Access-Control-Allow-Origin。合法Origin对应的二十四次目标请求也没有全部得到所需CORS头部。原始请求路径、RAW_URI、WSGI PATH_INFO及查询文本实际记录表明，问题发生在资源匹配所使用的对象状态。

仅保留unquote的控制通过字面加号和一次编码加号的十二项安全检查，两次编码的加号和空格路径仍错误放行十二次；二十四次合法目标请求中，仍有十二次缺少所需响应。直接request.path参考完成全部安全和功能要求。三控制均保持六十六次普通请求，包括优先顺序、不同资源配置形式、装饰器、既有头部保护、预检、HEAD、UTF-8和404。

这提供限定Flask/Werkzeug WSGI环境中资源政策的局部测量资格。实际Origin放行头部是测量端点，没有浏览器执行、生产网络及代理部署或完整CORS安全结论。全部请求来自一个自然来源，不增加独立任务数量；没有生成模型调用，没有Graph或Flat收益。来源已有相关政策要求，Atomic ADD资格保持不成立。

## 输入、环境和复现

完整政策、固定输入和事前资格条件见[设计](2026-11-03-flask-cors-path-contract-design.md)。原始提交e970988bea563e05e8b8f53fa7bcc134b5bf5c5f；实际导入源码version.py声明5.0.0，保留其与项目元数据及公开描述的区别。

实际Python 3.12.16、Flask 3.0.3、Werkzeug 3.0.6、Jinja2 3.1.6、MarkupSafe 2.1.5、itsdangerous 2.2.0、click 8.1.8、blinker 1.9.0。使用既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，固定wheel离线安装，非特权用户、关闭网络、只读源码和依赖、一核CPU、2GB内存，临时目录/work。

立即初始化、延迟初始化和Blueprint的路由使用相同正常视图；装饰器使用单独的视图函数，普通路由保留真实自动OPTIONS行为。请求由Flask test_client.open和Werkzeug EnvironBuilder产生，没有手动覆盖PATH_INFO、替换依赖或模拟被测CORS函数。

执行输入results/flask-cors-path-contract-20261103-request-inputs.tar.gz为731253字节，摘要e83050046345f56c2c6e3197afef29f17edfeebfc02ecc33d2c38624c9bec24b，本地与服务器inputs一致。服务器输入目录inputs/flask-cors-path-contract-20261103-request，结果目录results/flask-cors-path-contract-20261103-request-control，均位于/home/wsy/work/prompt-mechanism-study。

在独立解压的工作副本中执行，使用新的结果目录：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/flask-cors-path-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/flask-cors-path-contract-20261103-request-control
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/flask-cors-path-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/flask-cors-path-contract-20261103-request-control
```

独立核对程序不导入生产探针或Flask-CORS，使用标准URL及WSGI头部工具核对原始目标、一次解码路径、查询、Origin和预检头部，并从完整实际响应重新计算安全及功能结果。它检查全部342条请求记录、输入及源码摘要、三个入口、unknown和完整分母。

结果摘要29ae904972a7d20fde6fd0b939246cea4e40aff16bcb0c26906ecf38403bbab1；核对器摘要51b96a99586d4eba1dbe5b377c3ebb20cdbddc79a424e4a80681b69fda0688d6；独立核对结果摘要7c5a2c15d9ba8944587aa102a31d6de8a04fe03052281c99fb189185d23ba61e。输入、程序、全部原始响应、容器命令和技术记录保留。

完整冻结包results/flask-cors-path-contract-20261103-frozen.tar.gz为1506170字节，摘要c1efb4489c4eb3e7d60aa43dce6a0c6c51f15e18d93c571b8807ce5a67e2acf9，本地与服务器archive一致。服务器在新目录inputs/flask-cors-path-contract-20261103-replay解压，使用包内核对器重新读取全部实际记录，核对输出逐字节复现7c5a2c15d9ba8944587aa102a31d6de8a04fe03052281c99fb189185d23ba61e，没有重新执行来源程序或生成代码。

后续仍须固定共同代码生成任务、独立表示及参考、全部样本、预算和比较规则。作者控制、期望头部和实际测量结果不进入表示制作上下文；本项控制不提供新的JCI随机上下文。
