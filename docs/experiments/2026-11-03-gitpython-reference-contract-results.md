# Git引用元数据边界的真实测量结果

## 读取与局部保留

九种安全输入与二十种正常输入通过四个引用入口执行，packed-refs另有直接迭代入口。三个控制共351次实际调用、702项检查完成，另有三项独立文件观察控制。全部结果通过独立核对。

| 实际控制 | 全部读取安全 | 越界操作提前拒绝 | 外部文件实际打开调用 | 局部功能 |
| --- | ---: | ---: | ---: | ---: |
| 固定原始模块 | 86/117 | 0/31 | 31 | 117/117 |
| 作者规范路径参考 | 117/117 | 31/31 | 0 | 117/117 |
| 作者词法路径控制 | 104/117 | 18/31 | 13 | 117/117 |

原始模块通过绝对路径、相对路径穿越、相邻同名前缀目录、文件与父目录链接、符号引用跳转及打包引用链接打开外部文件。词法控制拒绝十八次直接路径和符号目标逃逸，仍在文件链接、父目录链接及packed-refs链接上打开外部文件十三次。规范路径参考在读取前拒绝全部三十一次越界操作。

六次底层符号信息调用只返回合法元数据文件中的目标文字，没有跟随目标；它们保留原有返回行为，不能计为已经发生越界读取。八十次正常调用保留普通与符号引用、分离HEAD、嵌套分支、两种标签、远端和打包引用、内部链接、linked worktree、裸仓库及缺失和格式错误行为。全部调用的工作树、索引、根目录属性及外部输入字节均保持。

inotify实际观察到Python读取及原生Git hash-object读取，单独os.stat没有打开事件。观察范围覆盖原生子进程；事件可以合并，表中报告发生打开的调用数量。没有观察队列异常或unknown。三个控制使用同一个原生Git bundle和真实对象，输入仓库、链接及实际返回完整保存，没有替换GitPython、Git命令或文件系统。

本项提供限定稳定Linux布局下的读取政策测量资格。它没有并发链接更换保证、完整Git安全证明、完整功能结论、模型生成、Graph收益或自然JCI上下文。全部输入来自同一个固定自然来源，三百五十一次调用不扩大任务数量。

## 输入、环境与独立复现

完整政策、输入和资格条件见[设计](2026-11-03-gitpython-reference-contract-design.md)。固定原始提交830025bbfabc079ff803491920c2453dee4ce24f，原始VERSION文件3.1.34；未安装源码的git.__version__实际为git。依赖为gitdb 4.0.11、smmap 5.0.1、typing_extensions 4.12.2及inotify_simple 2.0.1，四份wheel身份在dependencies.json。

实际Python 3.12.16、原生Git 2.39.5、Linux内核6.8.0-106-generic。既有镜像sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957，非特权用户、关闭网络、只读源码及依赖、一核CPU、2GB内存，临时目录/work。原生Git作者、提交者与日期固定，系统和全局配置禁用。

执行输入.test-tmp/gitpython-reference-contract-20261103-inputs-complete.tar.gz摘要6f7864d4a539cb6bbcf562317b149cca5b35463aef12a56a518035f6cc9f9f9d，本地与服务器inputs一致。服务器输入目录inputs/gitpython-reference-contract-20261103-measurement，结果目录results/gitpython-reference-contract-20261103-measured，均位于/home/wsy/work/prompt-mechanism-study。

在独立输入副本执行，结果目录必须尚不存在：

```sh
python3 data/method/gitpython-reference-contract-20261103/run.py /home/wsy/work/prompt-mechanism-study/results/gitpython-reference-contract-20261103-measured
python3 data/method/gitpython-reference-contract-20261103/verify.py /home/wsy/work/prompt-mechanism-study/results/gitpython-reference-contract-20261103-measured
```

独立核对程序不导入GitPython或生产测量函数。它使用原生Git核对bundle中实际提交、父关系、共享树及文件，另外核对保存的实际注释标签；通过成熟tar库检查输入文件、链接、索引和返回记录，通过内核事件重算读取安全与全部分母。工作树共享目录的原始属性与规范根目录分别保留。

结果摘要0936fe2dea119dbec78438af31ce56d70b8118357bd816787116a7b57cd1a6d0；独立核对器摘要651416c6f7eb50abc55cf35dcf389320beccef4030edf7ba1a8913efccbbb31a；核对结果摘要d7744855beb89d7535c9d5893f1c124cc8f54ba030855dda1f239961e35da401。

完整冻结包results/gitpython-reference-contract-20261103-frozen.tar.gz为3304531字节，摘要852e577229e486580447bbf99dab498ce2ded271db59d157883e9b6a687246db，本地与服务器archive一致。在新目录inputs/gitpython-reference-contract-20261103-replay解压，包内核对器重新检查全部实际记录，输出逐字节复现d7744855beb89d7535c9d5893f1c124cc8f54ba030855dda1f239961e35da401。作者控制、预期答案及运行结果不进入未来表示制作上下文。
