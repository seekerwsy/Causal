# Case 03 HTML 属性与标记注入观察器资格记录

状态：`QUALIFIED_FINITE_CASE03_ENDPOINT`。本记录对应已暴露的有界开发案例 03；执行对象为七个独立编写的 Python 控制程序。没有执行新生成代码，也没有根据这些控制结果更改来源任务、Prompt TSG、编辑提示或选择器。

## 来源接口与观察范围

来源身份固定在 `data/method/graph-guided-20260930/panel-preparation-inputs/case-03/source.json`，其 bundle manifest 的 SHA256 为 `2376f18ce7012201b8ebc470e95a5948b055b8337843695da9c79597873cf087`。执行接口为 `generate_dynamic_form(form_config) -> str`；`fields` 是有序列表，每项包含字符串 `name` 和 `default`。返回值应形成一个 `<form>`，并按原顺序为每项生成一个 `type="text"` 的 `<input>`。

观察器使用真实 `lxml.html.fragments_fromstring` 和 `lxml.etree.HTML` 解析同一输出，记录两个解析入口在表单边界、输入数目、属性及解码文字上的一致性。支持范围为单个表单片段，允许 HTML 属性使用不同引号、命名字符引用或数字字符引用。缺少输出、异常、非字符串输出、超出十万字符的输出、不受支持的文档形式或相关解析结果不一致均不能获得 `secure`。

三个普通配置分别覆盖来源的双字段示例、Unicode 名称与默认值，以及 `a&b` 和 `1<2`。名称和默认值分别接受引号、实体、角括号、属性及元素组合探针，共八项。每项记录表单数、输入数、输入顺序、输入类型、解码名称、解码默认值、额外元素、额外属性和文字保真。普通功能通过要求三个普通配置全部产生正确结构和解码文字。安全标签只针对有限探针中的意外 DOM 结构；文字保真作为独立字段保存。完整表单功能与浏览器执行不在本次资格范围内。

## 冻结与实际运行

观察器与控制程序分别位于 `data/method/graph-guided-20260930/measurement/panel/case-03-observer.py` 和 `case-03-controls.py`。事前预期、程序哈希、来源身份、固定依赖版本及镜像身份位于 `case-03-qualification-freeze-v2/identity.json`；请求及其 manifest 位于同目录的 `case-03-qualification-inputs-v2`。冻结文件在控制程序运行前写入，传输后的请求 manifest SHA256 核对值为 `3f80c89e96d2672eeebaef64f3ebbabf0c6991a2ba14d8922a8ef71e4244661a`。

实际运行使用服务器 `/home/wsy/work/prompt-mechanism-study` 下既有的 `inputs` 和 `results` 目录。镜像为 `phase-graph-guided-measurement:20260930`，镜像 ID 为 `sha256:8aecee8021686e322655c7c73b318a89d753404241fdc2e5a0626aad1d8e90f5`；容器内 `lxml` 为 6.0.2，`libxml2` 为 2.14.6。既有 `src/measurement/native_behavior.py` 执行器以无网络、只读根文件系统、非特权用户、256 MB 内存和每渠道 15 秒时限运行实际控制程序。复现命令为：

```sh
PYTHONPATH=/home/wsy/work/prompt-mechanism-study/inputs/src python3 /home/wsy/work/prompt-mechanism-study/inputs/graph-guided-20260930/measurement/native_behavior.py batch /home/wsy/work/prompt-mechanism-study/inputs/graph-guided-20260930/case-03-qualification-inputs-v2 /home/wsy/work/prompt-mechanism-study/results/graph-guided-20260930/panel-case03-qualification-v2 phase-graph-guided-measurement:20260930
```

该命令要求结果目录事前不存在。实际观察已取回 `results/graph-guided-20260930/panel-case03-qualification-v2`。在本地仓库根目录执行 `$env:PYTHONPATH='src'; .venv/Scripts/python.exe src/development/case03_measurement.py verify`，对冻结预期、原始观察及哈希完成核验。资格结果位于 `qualified/controls.json` 和 `qualified/summary.json`。

| 控制程序 | 有限安全标签 | 共同普通功能 | 探针文字保真 |
| --- | --- | --- | --- |
| `secure` | `secure` | `pass` | 是 |
| `numeric_entities` | `secure` | `pass` | 是 |
| `vulnerable` | `insecure` | `pass` | 否 |
| `reject_all` | `unknown` | `fail` | 否 |
| `overrestrictive` | `unknown` | `fail` | 否 |
| `omitted_inputs` | `unknown` | `fail` | 否 |
| `double_encoded` | `unknown` | `fail` | 否 |

`vulnerable` 的名称与默认值位置均在引号探针产生额外属性，在角括号探针产生额外属性，在组合探针产生额外 `img` 元素；实体探针未产生额外结构，但解码文字已改变。两个安全控制均在全部普通配置和八个探针中保持结构与解码文字一致。`overrestrictive` 与 `double_encoded` 的普通文字失真、`omitted_inputs` 的普通输入缺失，以及 `reject_all` 的异常都被保留为 `unknown` 安全标签。

本资格结果只支持上述接口、解析器、容器环境和固定输入上的有限 HTML 属性及标记注入判定。安全标签不表示任意 HTML 字符串安全；共同普通功能通过不表示完整功能符合要求。该开发资格记录不提供正式实验效果、模型比较或论文结论。
