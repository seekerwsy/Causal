# Gradio真实路径关系的局部测量结果

## 资格判定

固定来源CVE-2024-47164、原始提交`c12f600a984bdc269ba3e6db30e3b62186170ab0`已取得Linux本地文件系统下的`is_in_or_equal`局部测量资格。资格限定为设计中固定的严格实际目标关系：候选和信任根均须解析到已有对象，候选实际对象须等于根或位于根内；无法确定关系时拒绝。该资格支持后续相同政策范围内的表示组件任务准备。

原始函数没有满足该政策。它在八项安全输入中通过4项，在十四项功能输入中通过13项。结果完整保留，不影响测量端点能够区分参考和不充分控制的资格判定。

## 三项真实控制

| 控制 | 安全 | 功能 | 文件系统保持 | unknown |
| --- | ---: | ---: | ---: | ---: |
| 固定原始`abspath`与`is_in_or_equal` | 4/8 | 13/14 | 22/22 | 0 |
| 严格解析参考 | 8/8 | 14/14 | 22/22 | 0 |
| 仅词法规范化控制 | 4/8 | 14/14 | 22/22 | 0 |

原始函数对根内指向根外文件的链接、根内指向根外目录的链接、缺失的根内名称和悬空链接返回True。这四项的实际关系均由严格解析及真实文件内容观察判定为False。原始函数还对真实位于根内的`segment..name/data.txt`返回False。仅词法控制保留相同四项安全失败，同时通过全部十四项功能输入。严格解析参考通过全部安全、功能及保持检查。

每个控制执行八项安全判断、十四项功能判断和二十二项无修改检查，三项控制合计132项。绝对和相对父目录输入、同名前缀相邻目录、内部和外部链接、缺失与悬空对象、字符串与`Path`输入、点号名称、空格、Unicode及链接根均使用实际Linux目录、文件和符号链接。三项文件树归档保存真实内容摘要和链接目标。

## 环境与独立核对

测量在既有镜像`sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957`中运行，使用Linux amd64、Python 3.12.16、关闭网络、只读容器根目录、非特权用户、一核CPU、1GB内存和64进程上限。三项控制分别使用独立`/work`文件系统。固定原始归档摘要为`9e99e213af5b7c96c9569afdd18fe9c4fbfb15e4bd284f524736de5e435e4890`，`gradio/utils.py`与snapshot中的原始blob摘要一致。

独立核对器在同一固定镜像中重新建立三份目录树，重新执行原始函数，独立计算严格解析和词法答案，并核对全部逐项观察、文件树归档、分母、汇总及输入摘要。状态为`INDEPENDENTLY_VERIFIED_REAL_GRADIO_PATH_CONTROLS`，132项一致，结果摘要为`5afdbbe0c5ccd98f182626016a42fb7c8e31814c06a3445b2b8da3a88a9b52f5`，独立核对文件摘要为`de5dcc76142116e735ae31bc214c13b074d16443fff318f528d8cd103bfc9bee`，最终核对器摘要为`a4781c8a39e0d45ea9c67e747a6aa6ec8cbdd266b616b1e90ffb2af74c7502b6`。

冻结输入包`results/gradio-path-contract-20261103-inputs.tar.gz`摘要为`7bc2fb78c3722def7e73f1874027d6875c24456cfe974cec59c5422fd764fd7e`。服务器输入位于`/home/wsy/work/prompt-mechanism-study/inputs/gradio-path-contract-20261103-runtime`，结果位于同项目`results/gradio-path-contract-20261103-measured`。服务器冻结包位于`archive/gradio-path-contract-20261103-frozen.tar.gz`；本地副本为`results/gradio-path-contract-20261103-frozen.tar.gz`，大小67044134字节，摘要`d4139e9713f1d88bdc4ce9b0c09a34fdd1c0bf6860e792cc12fde93641aa9045`，两端一致。

## 科学边界

本结果证明固定Linux路径政策具有真实文件测量资格，并记录固定原始helper的局部失败。它没有执行Gradio服务路由，没有建立认证、blocklist优先级、上传与缓存来源、HTTP文件响应、完整服务功能、并发文件系统安全或CVE利用。它没有代码生成、模型调用、表示比较、Graph收益、自然JCI上下文、Atomic ADD资格或正式确认性证据。Windows、大小写不敏感文件系统、挂载变化和并发链接更换继续未知。
