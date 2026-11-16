# Werkzeug真实分段表单的数量政策测量结果

## 完整控制结果

十五份实际正文全部经独立python-multipart解析，三个完整模块控制、六个真实解析入口及功能保留检查共321项已执行，独立核对通过。

| 实际控制 | 数量安全检查 | 局部功能检查 |
| --- | ---: | ---: |
| 固定原始模块 | 0/42 | 65/65 |
| 作者字段与文件共同计数参考 | 42/42 | 65/65 |
| 作者仅统计字段控制 | 12/42 | 65/65 |

共同计数参考在第五项Field或File返回前拒绝，两个低层入口实际只返回前四项part事件。重复名称、空filename、空内容和字段/文件各自均不超过四项的五项混合输入仍被完整计数。仅统计字段的控制只拒绝两种五字段正文，其余文件及混合情况绕过，保留30项安全失败。

全部控制保持八种合法正文、单个600000字节文件、十五次不解析的原始正文读取，以及两种原有字节限制。Request.get_data(parse_form_data=False)返回准确原始字节，不被记为已经解析或完成数量政策。

这些实际差异取得限定数量端点的局部测量资格，未提供Graph、Flat或Raw新代码结果。没有总内存、CPU、全部读取立即终止、异常文件清理或拒绝服务防护证据。321项检查仍来自一个自然来源，不扩大任务样本数。

## 固定输入、环境与复现

完整政策、有限输入及资格条件见[设计](2026-11-03-werkzeug-parts-contract-design.md)。原始提交cf275f42acad1b5950c50ffe8ef58fe62cdce028；新增MAX_MULTIPART_PARTS=4是研究者规定的完整数量政策，三种未来表示需取得完全相同的政策。

实际Python 3.12.16、MarkupSafe 2.1.5、python-multipart 0.0.20，使用既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957。离线安装真实wheel，源码和依赖只读，非特权用户、关闭网络、一核CPU、2GB内存，临时文件位于/work。MultipartEncoder和独立MultipartParser分别承担正文生成和独立输入检查，没有编写分段协议解析器。

执行输入results/werkzeug-parts-contract-20261103-request-inputs.tar.gz为1002723字节，摘要50818d98e77aea4ddc03633f616a31ba61f652875b43ae75e951f6119216e17f。服务器输入目录/home/wsy/work/prompt-mechanism-study/inputs/werkzeug-parts-contract-20261103-request，实际结果目录/home/wsy/work/prompt-mechanism-study/results/werkzeug-parts-contract-20261103-request-control。

在独立解压的工作目录运行：

```sh
/home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/werkzeug-parts-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/werkzeug-parts-contract-20261103-request-control
PYTHONPATH="$PWD/.test-tmp/werkzeug-parts-dependencies-20261103/python_multipart-0.0.20-py3-none-any.whl" /home/wsy/work/prompt-mechanism-study/inputs/jci-framework/.venv/bin/python data/method/werkzeug-parts-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/werkzeug-parts-contract-20261103-request-control
```

复现使用新工作副本和结果目录，已有记录不覆盖。核对器重新解析全部正文，复算全部90项解析记录、十五项原始读取与两项字节限制，检查完整分母、实际part事件、字段与文件内容及控制身份，不调用生产判定函数。

结果摘要1341bf3cd043d5c6dbb290b46cfa9128947d5e7cb432918f186ffd8f161ec1a2；核对器摘要6b7b40a6329ea0dab491f4261548e01579e8de882e74156d25bfa613f643f30c；独立核对结果摘要f01e44f0f7700aae9e46c1858951675737db96dddf9a6530755f1cd027ae41e0。原始输入、观察、技术记录及核对程序一并保留。

完整冻结包results/werkzeug-parts-contract-20261103-frozen.tar.gz为2038675字节，摘要562a09957aa5dbd725fa2ec0f72098811c08bab9a504c5537e569076d956ba55，本地与服务器archive一致。服务器在新目录inputs/werkzeug-parts-contract-20261103-replay解压冻结输入，使用包内核对器读取全部实际记录，输出逐字节复现f01e44f0f7700aae9e46c1858951675737db96dddf9a6530755f1cd027ae41e0，没有重新执行来源程序或生成代码。

后续仍需固定完整代码生成任务、独立表示及参考、全部样本、预算与判断规则。本局部测量不赋予自然JCI上下文或正式Atomic效应资格。
