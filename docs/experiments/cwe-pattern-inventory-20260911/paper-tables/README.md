# 论文用 CWE 与任务形式表

状态：已生成、编译并检查。模式：`draft-to-latex-layout`。这是候选池的数据描述表，不是正式实验结果或已冻结的任务模式分类。

- [正文表 PDF（1 页）](main-preview.pdf)：20 个 CWE，6 个展示类别，覆盖 **1,333 / 1,992 = 66.9%** 的独立任务。
- [正文表与完整附录 PDF（7 页）](preview.pdf)：第 1 页为正文表，第 2–7 页为全部 117 个来源标签。
- [正文表 LaTeX](cwe-main.tex) 与 [完整附录 LaTeX](cwe-appendix.tex)：可分别插入论文的数据描述部分及附录。
- [正文表图片](main-preview.png)；[原始中文总表及可追溯任务依据](../cwe-task-patterns.xlsx)。

正文按候选池中任务数从多到少选择前 20 个标签，同数按 CWE 编号升序选择；展示时按领域分组，组内仍按任务数排序。这是版面选择规则，不是研究范围、任务角色或正式纳入资格的变更。

四列分别为 **Category / CWE (ID & description) / Illustrative task forms / Tasks**。采用黑白三线表、加粗分组、组间横线和右对齐数字；不添加尚不存在的 Avoided、Original 或改善比例。最后一行表示去重任务总数。

## 数据与含义

数量来自既有 `research-candidate-pool-v2/tasks.json`，由 [inventory.json](../inventory.json) 指向的文件哈希约束。表格生成时逐个 CWE 重新核对任务身份集合，而不是手工录入数量。

正文 20 行的标签成员数之和为 1,334，去重后为 1,333；完整 117 行的成员数之和为 1,993，去重后为 1,992。唯一的跨标签重复任务同时标记为 CWE-120 和 CWE-121。

117 个编号中有 116 个弱点条目和一个历史 Category 条目 CWE-730，保留来源标签，不重新标注。表中的类别是编辑分组，不是 MITRE 官方父子分类；CWE 描述经过缩写，完整名称见原始工作簿。

任务形式是对既有 214 条已检查来源示例的英文压缩描述，来自 [annotations.json](../annotations.json)，不表示 214 个不同模式。尚未对全部 1,992 个任务逐题完成模式归类，因此表中不给出模式总数或每模式样本量。来源 CWE 标签也不证明相应任务具有已验证漏洞或已满足干预条件。例如 CWE-807 的来源示例是读取 Git HEAD，CWE-338 的示例包括一般随机抽样；这里如实展示来源任务，而不根据 CWE 名称补写安全操作。

数据到表格的路径只有一条：既有 `inventory.json` 与其绑定的候选池 → [display.tsv](display.tsv) 中的缩写与英文任务描述 → [build.py](build.py) → 两个表格 `.tex` → 预览 PDF。[table-data.json](table-data.json) 记录选择规则、覆盖数、输入哈希和表格源文件哈希。模式依据仍保留原有任务身份；本次未调用模型、读取生成代码结果或改变活动协议。

## 模板与插入位置

沿用本地 `paper/fse2027/main.tex` 的 `acmart[acmsmall,screen,review,anonymous]` 模板，单栏宽度 395.8225 pt，正文区域高度 574 pt。表格为 9 pt、注释为 8 pt，未调整模板页边距、全局字号或浮动体规则。本地尚无本次附录的正式页数预算，因此这是与当前模板兼容的独立排版预览，不表示已经满足最终投稿篇幅要求。

| 表格 | 对应内容 | 建议位置 | 所需宏包 |
|---|---|---|---|
| `tab:cwe-task-forms-main` | 候选池的主要来源标签及任务形式 | 数据集描述段落之后 | `booktabs`、`multirow`、`tabularx`，现有主文已加载 |
| `tab:cwe-task-forms-appendix` | 全部来源标签清单 | 数据附录 | `booktabs`、`array`、`longtable`；当前预览已加载 |

正文文件本身包含 `table`；附录文件包含可跨页的 `longtable`，不能再包在 `table` 浮动体中。未直接改写现有论文的内容或添加主文宏包；仅生成本目录中的可插入文件。

## 编译与检查记录

环境：Windows，Python 3.12.13，TeX Live 2026，pdfTeX 3.141592653-2.6-1.40.29，acmart 2.16。生成程序只依赖 Python 标准库。使用目录为本文件所在的 `paper-tables`。

本机复现命令：

```powershell
& 'D:/MyCode/Causal/.tmp/tsg-single-clean-env/Scripts/python.exe' build.py
& 'D:/texlive/2026/bin/windows/pdflatex.exe' -interaction=nonstopmode -halt-on-error preview.tex
& 'D:/texlive/2026/bin/windows/pdflatex.exe' -interaction=nonstopmode -halt-on-error preview.tex
& 'D:/texlive/2026/bin/windows/pdflatex.exe' -interaction=nonstopmode -halt-on-error main-preview.tex
& 'D:/texlive/2026/bin/windows/pdflatex.exe' -interaction=nonstopmode -halt-on-error main-preview.tex
& 'D:/texlive/2026/bin/windows/pdftoppm.exe' -r 160 -png -singlefile main-preview.pdf main-preview
```

其他机器可将解释器路径替换为 Python 3.12+ 和本机 TeX Live 路径。

- 两轮布局调整后，最终正文为 1 页、正文加附录为 7 页；无 overfull box 或超页浮动体警告。
- 所有 7 页均已渲染检查，正文类别没有重叠，附录保留重复表头，行内容没有跨页截断。
- 独立读取生成表格和 PDF 提取文本，核对正文 20 个、附录 117 个 CWE 行身份及每行任务数；核对 1,333、1,992 和 66.9% 的显示值。
- 独立表格预览没有论文首页元数据，因此完整版产生 acmart 对关键词、CCS 和 ACM 引用格式的提示；这些不是表格布局错误。现有论文首页配置不受影响。
- 不涉及实验实现或正式科学输出，本次未重复运行与表格无关的实验测试。

本次没有待确认的排版操作。
