# TSG 构建调试查看器

打开 [`../results/tsg-debug/index.html`](../results/tsg-debug/index.html)，即可离线查看
2026-09-12 single-role-check 的 6 个已暴露开发案例。文件包含数据和界面，不需要服务器、
联网或模型密钥。它是表示阶段的只读检查工具，不改变抽取方法、参考标准或冻结结果。

## 建议的检查顺序

1. 顶部下拉框选择案例。案例编号沿用来源编号，可能重复；任务标识保留在页尾。
2. 在“流程图”查看业务节点。节点使用简短名称，连线直接显示关系；宽窗口从左到右，
   窄窗口从上到下排列。可显示生成层要求、聚焦单个操作、缩放图形。
   点击节点或连线才展开原文证据、概念定义、对象角色和保存的复核。
3. 在“检查记录”分别检查“原文应有的节点与关系”和“已生成内容是否有依据”。
   前者发现遗漏，后者发现额外的错误断言。取消“只看问题”可查看全部记录。
4. 缺失节点可以“定位原文”；已经存在的节点和关系可以“定位图中内容”。
   “要求的作用范围”保留期望状态、实际状态、依赖检查和原有可用性结论。
5. 在“逐句覆盖与影响范围”检查模型的覆盖声明及复核意见。
   下方按事实清单、关系绑定、固定范围判断展示原始回复，失败或截断的回复单独保留。
6. 可导出当前视图的 SVG，或在“原始记录”保存含证据和诊断的案例 JSON。

可先查看 PDF 案例：固定检查为 25/25，但额外的上传目的地关系仍标为待核对。
再查看“原子要求与 10 字符限制”：两个要求节点确实存在，但关系绑定失败，
页面明确标为中间节点清单。两种状态不能混为完整抽取成功。

## 如何理解标记

- “有依据／无依据／待核对”来自已保存的开发复核；没有复核的内容显示“未复核”。
- 橙色虚线表示需关注的关系。普通连线和机械编译成功都不自动证明语义正确。
- 固定检查比例不是准确率；缺失、因端点缺失而受阻、未评估、没有可用图分别保留。
- 未表达某项提示要求，不等于生成的软件缺少该保护。
- TSG 边表示原文语义关系，不是因果边。该批复核不是独立资格认证。
- 图中短名称只是显示标签，不修正错误的概念或绑定；确切概念和原文在点击后的详情中。
- 失败回复中的节点草稿和说明不会被补进实际图。工具不提供修改冻结结果的入口。

## 重建页面

单一入口仍为 `representation visualize`。从仓库根目录执行：

```powershell
$batch = 'data/method/open-tsg-scope-development-v1/single-role-check'
.tmp/candidate-builder-review-env/Scripts/python.exe -X utf8 -m prompt_mechanism_study representation visualize "$batch/inputs/tasks.json" "$batch/server-results/extraction" results/tsg-debug/index.html --review "$batch/analysis"
```

可换成已安装项目的 Python 3.12 环境。其他抽取包的通用用法：

```text
prompt-mechanism-study representation visualize TASKS EXTRACTION_BUNDLE OUTPUT.html
```

`--review` 接受现有开发分析包，其 `summary.json` 绑定抽取包及参考输入包，
并含 `case-results.json`、`assertion-review.json`、`source-review.json`。
加载时核对图、完整表示输入、回复及参考输入的身份；不匹配即拒绝导出，不重新评分。
没有复核包也能查看图、证据和原始回复。图目录或 contract 内没有概念表时，
用 `--catalog CATALOG.json` 提供该图的原始概念表。输出应放在冻结包之外。

已有实验的 `--results` 和 `--additional-extraction` 参数保留。
新增实现仍在 `src/prompt_mechanism_study/tsg_visualization.py` 和
`src/prompt_mechanism_study/fixtures/tsg-viewer.html`，没有第二条抽取链路。
流程图使用 [Dagre](https://github.com/dagrejs/dagre/wiki) 1.1.5 自动布局；其官方浏览器
发行文件及 MIT 许可保存在 `fixtures/dagre.min.js`，导出时内嵌到 HTML，无需运行时联网。
布局只改变坐标、线形和显示文字，不改变原始节点、边或复核记录。

## 开发时的验证记录

以下是工具开发时的历史检查。界面专用测试已在最小测试集清理中删除；当前运行方式见
[测试说明](../tests/README.md)，无需重跑这里的历史命令。

环境为 Windows、Python 3.12.13；只读取既有开发产物，没有真实模型调用。
自动检查覆盖源图与复核身份、未复核状态、失败阶段、中间图保留、HTML 数据转义，
并复用现有输入绑定及实验记录导出检查：

```powershell
.tmp/candidate-builder-review-env/Scripts/python.exe -X utf8 -m pytest tests/test_tsg_visualization.py tests/test_task_input.py tests/test_development_itt.py -q -p no:cacheprovider --basetemp=.tmp/tsg-debug-pytest-02
```

临时测试目录需为新的空路径。上述 41 项检查通过。浏览器通过本地 HTTP 预览验证同一
HTML，检查图中定位、原文高亮、失败案例、390 像素窄屏及 SVG 实际下载；PDF 导出的
SVG 保留 8 个业务节点和 11 条关系。内置浏览器禁止直接访问 `file:` URL，未在其内
验证文件协议打开。该限制不涉及常规浏览器双击打开自包含 HTML 的用法。
原有科学结果及其完整验收结论均保持不变。
