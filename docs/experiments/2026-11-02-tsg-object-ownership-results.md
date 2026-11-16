# 对象组成与实际操作参与者的机制验证结果

## 来源、参考及实际提取

本轮遵循[固定设计](2026-11-02-tsg-object-ownership-design.md)，使用已暴露的 `pydata__xarray-7229` 原始问题及三个原始代码文件。新来源参考由未接触旧表示、旧参考、评分或实现的独立上下文制作，包含35项逐字证据、17项有条件的明确组成关系和六项未知关系；行号及引文全部通过机械核对。具体示例与一般范围分别记录。

新Graph由另一个隔离上下文实际提取，包含33个来源节点，机械检查一次通过，最终文件与草稿摘要相同。没有编辑旧Graph或重评分旧比较。计划摘要为 `12efa8da9a632dc4ff204540b61195ba10757967936452e71066d8438bbe91d7`，新实际来源记录摘要为 `a6005b09661a8407f916c5eaf2cd21d4564a79715cb71f63a9dc7c7b3771eea6`。

## 已执行的原生行为

原生来源编译器登记明确的 `part_of` 关系；要求读出保留主体到实际参与者的路径。本次具体示例的主体仍为time坐标，路径到达调用的返回对象，返回对象通过 `produces` 连接实际where调用。time没有进入直接输入或输出列表，ds也没有代替ds.air成为where的直接实参。

具体示例要求的 `binding_complete` 为true，读出保留示例条件、完整谓词和范围依据。一般坐标要求继续为未完成，三个一般组成候选及输入time身份保持未确定。使用新实现重放旧50节点图，所得完整来源读出与其原件逐项相同，没有使用新规则改变旧结果。

一个新的独立语义核对上下文依据先前固定的来源参考，对操作实例、要求主体、组成路径和范围保留四项均判定supported，并核对实际四条组成关系。它明确限定这些关系为来源声明的对象成员关系，没有认证内部存储、内存别名或实际执行。具体目标读出没有独立带出attrs节点；属性谓词由要求含义保留，完整来源记录另有attrs节点和组成关系。目标读出不能当作全部源对象的完整清单。

这次修订建立了对象组成路径的实际消费能力。旧Graph和平面均4／4的语义结果保持原值；新提取与新消费者的单项机制检查不能提供相对平面的独立收益。本轮没有生成候选程序、运行库程序或获得安全及功能结果，Atomic资格和Graph收益仍为false。

## 独立核对与默认检查

`verify.py`不调用生产路径或绑定函数，依据原始端点构造组成矩阵，使用SciPy Floyd–Warshall独立核对全部可到达参与者、路径长度、原始主体和实际输入输出。核对结果为 `VERIFIED_OBJECT_PARTICIPATION_MECHANISM`，目标来源语义核对四项均supported；该状态不认证一般语义真值。来源参考和语义核对共享模型来源，没有人工真值保证。

新默认检查使用完整自然来源和实际提取记录的冻结副本。七项检查覆盖主体与实际参与者的区别、嵌套属性路径、引用不能替代组成、显式未完成声明、组成环和类型错误，以及具体实例不能完成一般范围。连同原有合同检查，本地16项通过。

服务器独立输入目录的完整默认检查为60项全部通过，无失败、错误或跳过，耗时90.41秒；原始输出保留四项既有进程创建弃用提示。XML记录经.NET XML库独立核对，摘要为 `25e57a1e6070073cb5b8ceb1467dbf0149e362fc48e1d2817108c3863def2807`。完整默认检查包括当前活动方法的端到端执行与独立结果核对，没有将单元检查计为新增科学重复。

## 环境、入口及结果位置

服务器使用Python 3.12.13、NumPy 2.5.1、SciPy 1.18.0、scikit-learn 1.9.0、NetworkX 3.7、R 4.1.2及现有pcalg 2.7.12。所有数值线程限制为一个，R和Python临时文件均在项目结果目录。没有修改正在运行的JCI预算曲线输入或服务器源码。

机制材料位于 `data/method/tsg-object-ownership-20261102`。在保存原生成输出的独立副本中，依次执行：

```text
python data/method/tsg-object-ownership-20261102/prepare.py
python data/method/tsg-object-ownership-20261102/run.py analyse
python data/method/tsg-object-ownership-20261102/verify.py
```

复算重用首次来源参考、实际提取与语义核对，不重新调用模型。默认检查输入包为 `results/tsg-object-ownership-reviewer-20261102-inputs.tar.gz`，SHA256为 `c764fddf18644006b8eb89c3967e182670942c637d542ce16d96696177931d8f`。服务器输入目录为 `/home/wsy/work/prompt-mechanism-study/inputs/tsg-object-ownership-reviewer-20261102`，检查结果目录为同项目 `results/tsg-object-ownership-reviewer-20261102`。命令为：

```text
python -m pytest -q -p no:cacheprovider --rscript=/usr/bin/Rscript --basetemp=/home/wsy/work/prompt-mechanism-study/results/tsg-object-ownership-reviewer-20261102/pytest-tmp --junitxml=/home/wsy/work/prompt-mechanism-study/results/tsg-object-ownership-reviewer-20261102/pytest.xml
```

设置PYTHONPATH为独立输入目录，TMPDIR、TMP和TEMP均为上述结果目录内的runtime-tmp；R_LIBS指向既有 `inputs/jci-framework/.codex-runtime/r-lib` 及 `.codex-runtime/r-deps/usr/lib/R/site-library`。本地已取回原始stdout、stderr和XML，核对文件位于机制材料的reviewer-tests目录。

机制冻结包为 `results/tsg-object-ownership-20261102-frozen.tar.gz`，大小342646字节，SHA256为 `8347225a7707654c99845074759010098f279568f7156447dca21f2b64e13904`。在 `.test-tmp/tsg-object-ownership-replay-20261102`独立解压，使用包内共用源码重新执行上述三个阶段，输入、计划、编译图、读出、结果与独立核对六份输出均与原件逐字节相同。首次来源参考、实际Graph及语义核对保持原值，没有再次调用模型。本段记录归档之后完成的机械复算。
