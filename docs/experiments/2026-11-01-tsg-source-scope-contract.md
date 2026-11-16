# Prompt TSG 的来源范围与提取约束

规范实现为 `src/tsg/prompt_tsg.py`，来源概念目录由 `src/tsg/prompt_contract.py:open_concept_catalog` 提供。提取、规范编译、范围选择与语义审核分别保留实际输出。该约束说明用于后续方法准备；不替换已经冻结的表示指令、主要指标或结果。

## 来源、要求与表达式

每个事实保存逐字来源、出现位置、独立 local_id、semantic_id 和一致的节点类型。同一完整要求的重复位置可以共享 semantic_id，但分别保存 local_id 和证据。操作、对象、条件、要求、事实和例子必须保留各自身份；全文目的不能为某一事实自动赋予规范作用。

`structures` 的所有父项及成员必须是要求类型：task_requirement、safety_requirement、constraint、presentation_control。操作节点和对象节点不能直接作为 AND／OR／NOT 的表达式成员；要求成员通过各自关系绑定操作和对象。AND／OR 至少两个不同成员，NOT 恰好一个成员，atom／opaque 没有成员。表达式没有有向环，同一成员只有一个所属父项，父项条件必须由成员保留。AND 容器不自动成为单项可编辑政策。独立事实或例子使用 opaque 时，不据此认证规范要求。

已经存在的完整目标要求需要由原文支持。ADD 所要增加的要求没有出现在原文时，仅定义目标概念，不制造目标事实节点。当前范围查询不以目标要求是否存在选择操作或对象；语义未知保持 unresolved。

## 范围的具体表示

`scopes` 保存整体任务或逐个对象的量化范围，只允许 task 和 each。每项恰好一个 task／task_operation 边界；task 使用 task.root，target_class=null；each 提供非空 target_class。同一要求不能同时使用保留范围和直接 constrains。targets、objects 是 selector 的查询类别，不是 `scopes` 的合法 kind。

调用 `build_prompt_tsg` 时，整体任务边界通过空的 boundaries 数组传入，由构建函数映射为规范图中的 task.root；操作边界使用一个实际 local_id。task.root 由程序创建，不是可放入 facts 或直接作为局部关系端点的 local_id。规范图记录与构建函数输入的边界坐标需要分别使用其实际格式。

针对某个操作及其对象的要求使用直接 constrains 关系；针对对象自身且没有操作限定的属性，使用 task.root 配合 objects 查询。不能为了通过查询，给原文没有指定的操作增加要求归属。

操作范围内的对象可以是来源明确给出的输入或输出：对象 used_by 操作，或操作 produces 对象。查询与验证均只接受同一操作实际连接的 data_object，不把其他操作的对象借入范围。objects 查询使用整体任务边界。输入与输出的来源关系分别保留，不将产生关系改写为输入关系。

`owned_relations` 的所有者必须是原子要求，端点必须是两个不同的 task_operation，目前只保存政策所属的 precedes。AND 容器不能拥有该关系。独立事实顺序保留在普通 relations；它与完整政策所属顺序各有含义。

## 条件与政策查询

selector 明确提供 operation_semantic_id、subject_semantic_ids、condition_semantic_ids、policy_condition_semantic_ids、scope_kind、target_class 和 requirement_kind。所有标识列表按规定排序，操作及各端点必须有唯一来源匹配。对象范围使用 root；整体和 each 范围保留量化含义；政策匹配还核对完整要求的对象、条件、范围、表达式类别及所属关系。

conditions 表示执行条件，context_for 表示非门控来源背景，两者不能互换。包含来源背景的查询需要显式 execution_condition_semantic_ids，列出全部执行条件；condition_semantic_ids 另外包含被查询的背景条件。policy_condition_semantic_ids 保存政策自身的条件，不能把它用于选择来源任务。来源范围查询成功与完整政策匹配成功分别记录；存在背景条件时仍须满足政策匹配的完整规则，不能依据范围存在推断政策存在。

直接传给原生查询的 policy_relations 为三项数组组成的列表，依次为源操作的 semantic_id、关系类型、目标操作的 semantic_id。来源局部 owned_relations 使用明确字段 source、edge_type、target。两种格式具有各自的接口含义，不把字典字段名作为语义端点。

实际编辑保留非目标要求、功能目的、事实、例子、接口、顺序、引用及原有未知。规范编译和唯一范围只检验结构资格，不认证编辑后政策缺失、语义正确、软件安全或功能性。后续方法的机械检查与修订次数应在输出前固定，并给予平面方法相同检查机会；不能使用语义评审反馈修改首次比较结果。

## 实际输出对象边界检查

`check_output_scope.py` 读取已经冻结的42项研究中全部18张实际规范图形和首次 selector，保留冻结结果 SHA256。输出对象规则使临时文件任务的 temp.create／temp.file 范围可以直接从原有 produces 关系选出；该文件没有被伪装成创建操作的输入。其余17张图的查询结果保持原值。未解决的对象属性限定与背景条件位置继续保持原状态，没有修改原始提取或审核。

检查结果为 `VERIFIED_SOURCE_SCOPE_MECHANISM_ONLY`，位于 `data/method/tsg-role-dependencies-20261101/output-scope-check.json`；SHA256 为 `b8303679dd05608dd44bf97a4d56b9ef5337bd9fedef40e2bec161571d494c15`。该检查对应的实现 SHA256 为 `0af01335b312720b67bde3fea299384e004ce8ec45e0319fd914e1f6f92b07c8`。来源范围及条件相关的七项既有测试通过。本检查没有重新计分表示收益，没有新模型调用，也没有改变冻结的15/42与32/42绑定结果。

```text
python data/method/tsg-role-dependencies-20261101/check_output_scope.py
python -m pytest tests/test_open_prompt_tsg.py -k "scope or condition or atomic_source" -q -p no:cacheprovider
```

检查输出使用排他创建；复现时使用完整项目副本并将已有检查结果移至副本的归档目录。冻结的安全绑定研究源码和原始结果保存在 `results/tsg-security-binding-complete-20261101-frozen.zip`，SHA256 为 `cdce1b5ff8dc17c508916ea8246b17476b8c2272e473ce178c78bcd85e525244`。旧比较复现应使用其归档源码，不在新范围规则下重新解释原结果。
