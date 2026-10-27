# 隔离语义准备要求

每个准备实例只处理任务消息指定的一份公开来源文件。读取仓库 AGENTS.md、本文件和指定来源；不得读取其他任务、其他准备流程、功能蓝图、控制程序、参考绑定、生成代码、测量结果或选择器结果。使用当前继承的 Codex 模型和推理设置。本次实例只允许一次准备，输出上限为 12000 token。

公开来源中的 `source_versions` 是完整原文，`policies` 给出三个固定政策。任务是来源表示、目标绑定和 Atomic 编辑。所有来源要求、输入允许范围、接口和行为均须保持；每项编辑只翻转该政策的状态。完成全部材料后一次性提交，后续语义检查不触发重写。

TSG 流程为每套来源建立显式图，包含完整命题、输入对象、操作、条件和范围，以及有来源依据的关系。节点以逐字引用和出现编号指向来源；边表达提示语义。记录用于定位政策目标及检查非目标要求的图查询。

Raw 流程直接阅读完整原文，以自由文本分析确定绑定。Rich-Flat 流程建立包含命题、对象、条件、范围、来源和关系的平面记录，再确定绑定。三个流程均根据公开政策独立编写真实编辑。

输出使用指定路径的 UTF-8 JSON 文件，由文件编辑工具写入。字段如下：

```json
{
  "task_id": "指定任务身份",
  "flow": "指定流程",
  "representation": {
    "nodes": [{"id": "n1", "type": "object", "version": 1, "quote": "原文逐字引用", "occurrence": 0}],
    "edges": [{"source": "n1", "relation": "语义关系", "target": "n2"}],
    "binding_queries": ["实际使用的图查询及其节点结果"]
  },
  "candidates": [
    {
      "policy": "local",
      "status": "prepared",
      "versions": [
        {
          "version": 1,
          "binding": {
            "object_quote": "唯一目标输入定义",
            "operation_quote": "目标操作原文",
            "qualification_quote": "完整目标限定命题"
          },
          "edits": [{"quote": "需要替换的原文", "occurrence": 0, "replacement": "替换全文"}],
          "states_before": [0, 0, 0],
          "states_after": [1, 0, 0],
          "preservation_reason": "非目标内容保持依据"
        }
      ]
    }
  ]
}
```

`states_before` 和 `states_after` 始终按 local、example、reference 排列，由完整来源和实际编辑读取。local 为完整限定命题与目标操作共处同一段落或列表项；example 为目标输入具有完整的可选非穷尽示例；reference 为完整限定命题直接使用目标参数标识符。

每个候选必须包含全部公开表达版本；每套表达提供针对原始来源的精确替换列表。`occurrence` 从零开始计数。各替换在原始文本上的位置不得重叠，执行时由最后位置向前应用。移动操作可使用删除和插入两处替换。源文本中同一引用有多次出现时，明确选择正确编号。引用和替换不附加公共执行后缀，也不更改函数接口。

`candidates` 必须具有 local、example、reference 三个位置。无法确定合法编辑时，该位置的 `status` 为 `unprepared`，写明具体语义原因并提供空 `versions`；不得猜测缺失事实。Raw 的 representation 使用 `analysis` 字符串；Rich-Flat 使用 `facts` 数组及来源和关系字段。TSG 使用上面的显式图字段。

最终回复只说明输出路径和完成状态。不要运行 Qwen、修改代码、寻找外部资料或启动其他准备实例。
