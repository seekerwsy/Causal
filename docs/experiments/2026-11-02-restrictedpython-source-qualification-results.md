# RestrictedPython 成对来源测量结果

## 实际资料与执行

按照[固定设计](2026-11-02-restrictedpython-source-qualification-design.md)，已取得24项固定身份中第一项 `CVE-2025-22153` 的原始父提交及修复提交完整快照。两个版本各103个文件，206项Git对象逐项核对，未修改上游源码或测试。源码和测试保留原始ZPL-2.1许可证及版权材料。

实际运行一个自然任务、两个原始程序版本，每个版本22项预定测试，合计44次测试执行。没有生成模型调用、实验分配或新增独立样本。测试配置及输入在执行前固定，计划SHA256为 `357d518793ecb0ebf92de13a6b25aaaeebb9e381d96c8f03648f90dcf1ba8207`。

## 分别测得的策略与功能范围

| 范围 | 原始版本 | 修复版本 |
| --- | --- | --- |
| 指定TryStar语法拒绝测试 | 一项断言失败 | 一项通过 |
| 非目标功能及错误处理 | 21／21通过 | 21／21通过 |
| 测试错误或跳过 | 零项 | 零项 |
| 编译诊断返回代码对象 | 是 | 否 |
| 编译诊断错误 | 空列表 | 明确拒绝TryStar |

原始版本真实返回代码对象，错误列表为空。修复版本返回明确的TryStar拒绝错误且不提供代码对象。上游测试在原始版本的实际断言失败已保留，没有通过捕获异常制造通过结果。两个版本的标准错误输出均为空。

21项非目标检查包括八项原始编译函数测试、八项原始算术操作测试及五项普通异常处理程序的真实事件检查。两个上游功能测试文件在原始及修复提交中的Git对象完全相同；五项适配检查执行原始测试中的程序字符串，用实际列表记录事件，没有使用模拟对象。19项检查合法输入执行，两项检查非目标语法错误处理。完整功能性继续为false。

该功能范围没有覆盖全部公开编译选项、显式关闭策略的policy=None路径或ExceptionGroup等全部内置对象的可用性。未来具体干预的非目标范围仍需按任务指令固定；当前21项通过不能替代那些尚未检查的合同。

独立核对结果为 `VERIFIED_SOURCE_QUALIFICATION_ACCOUNTING`。指定语法拒绝Oracle与声明的局部功能范围均取得资格，`qualified_for_bounded_policy_measurement=true`。该结论只支持指定语法策略测量；实际漏洞利用、完整安全、全部功能及Atomic资格均未建立。两个原始版本的差异不证明生成模型的基线程序不安全，也不构成Graph或JCI收益。

## 实际绑定与隔离环境

两个容器分别导入对应源码，独立核对全部九个RestrictedPython模块的实际路径及内容摘要，没有导入另一版本的程序。共同测试来自修复快照，功能测试对象相同。已选测试没有mocker依赖，依赖插件自动加载关闭。

环境为现有Docker 27.5.1、Python 3.12.16及pytest 9.1.1。镜像摘要为 `sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957`。容器关闭网络，根目录只读，源码、测试及依赖只读挂载；普通用户使用明确工作目录和项目结果目录。没有执行TryStar诊断产生的代码。

资料准备人员接触了原始公开API、上游测试以及修复版本的测试答案和变更路径；这些材料不应进入未来表示制作上下文。后续仍需固定共同的原始源码上下文、任务指令、单项干预与独立参考，才能开展Graph和平面方法比较。缺少任务指令及干预方案的部分属于协议准备工作，当前不据此替换固定来源。

## 原始记录、核对及复现

输入包为 `results/restrictedpython-source-qualification-20261102-inputs.tar.gz`，大小925272字节，SHA256为 `30e57b9bbb8499a76307ae533f8f352d00ebfc3de0456042e5eb5a7f4372e477`。服务器输入位于 `/home/wsy/work/prompt-mechanism-study/inputs/restrictedpython-source-qualification-20261102`；原始结果位于同项目 `results/restrictedpython-source-qualification-20261102`。在该独立输入目录执行 `bash data/method/security-code-source-20261102/run.sh` 可得到两个原始版本的相同测试集合；运行目录需要尚不存在，避免覆盖已冻结输出。

原始服务器结果归档为 `archive/restrictedpython-source-qualification-20261102-results.tar.gz`，本地副本位于 `results`，大小2663字节，SHA256为 `170c6d549614d667fb5bff4a0ee6a079e471fac2f4986be60820f1c3d38c3356`。源码快照分别为 `9ea756a5cb9c433ff01f74c9cf6c2f9121156c2792cd4279cca4e02dd50ef517` 及 `ca9ffcb3fee902b45f46f791907497683ddafd9658791f3e32b46786b9ef0195`。

原始XML、模块绑定、退出状态和输出已取回 `data/method/security-code-source-20261102/qualification-results`。当前独立核对程序 `verify_qualification.ps1` 使用.NET XML库与原始编译诊断核对测试身份、分母和来源版本，SHA256为 `e9c9d49b9a3abd584d6300490fdcd6eb6a2ccd4f4eb41e17ebdbd9ecf2f3b7e5`。在保留已有qualification.json的独立副本中执行：

```text
pwsh -File data/method/security-code-source-20261102/verify_qualification.ps1 -Results COPIED_RAW_RESULTS_DIRECTORY
```

核对不重新运行测试，也不调用模型。当前资格结果SHA256为 `6b02654063cb5183eb63b75648e584b157589f2aef039d61f6f22c72273c98a1`。所有冻结来源身份、原始失败、旧实验及正在运行的JCI预算设计保持原值。

完整冻结包为 `results/restrictedpython-source-qualification-20261102-frozen.tar.gz`，大小930689字节，SHA256为 `9fd2e2c5c9cf69065caf7f4a6403c2d071e6fa2b6fa2963b78049360d849a476`。它包含两个完整原始快照、固定测试配置、原始输出及当前独立核对程序。在 `.test-tmp/restrictedpython-qualification-replay-20261102`独立解压，保存原资格输出后，用包内程序重新读取原始XML及模块绑定，得到的资格结果与原件逐字节相同。该复算没有再次运行测试或调用模型。本段记录归档之后完成的独立复算。
