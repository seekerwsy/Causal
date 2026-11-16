# aiohttp政策依赖表示检查的执行记录

## 共同来源与方法准备

依据固定设计2026-11-03-aiohttp-policy-dependency-design.md，使用一个已暴露自然来源上的研究者任务。共同输入包含完整任务、完整Atomic政策、五份完整Python原文件及许可证，78409字符。133项实际调用位置共同提供给Raw、Flat、Graph的独立准备上下文。

共同来源经过独立上下文审查，另由Python AST独立核对全部133项调用及六份文件身份，状态VERIFIED_SHARED_AIOHTTP_SOURCE_CONTEXT，摘要91e7a82e1bba153105503c732dcbaaae0f2353a7428aa2822fef4b27fff1767c。该判断仅支持任务理解和来源准备，不能证明候选行为或测量资格。

三种方法均在各自隔离上下文中完成，一次机械检查通过，最终记录与草稿逐字节相同。没有语义反馈或结果反馈后的方法记录修订。Raw可正常分析对象、调用、条件、修改位置与保留义务；Flat允许全部关系及交叉引用；Graph由现有规范根与记录依赖形成附加材料。全部生成提示始终保留同一完整原文和完整逐字政策。

## 显示与真实上下文资格

原生Graph读出存在重复展开的源码证据和连续来源单位枚举；实际输入65788 tokens，不能满足49152上下文。序列化处理把已在共同原文中的长证据替换为精确字符区间及定位摘录，并把连续来源单位完整表示为包含端点的区间。该变换共同适用于三种材料，不选择或删除事实、关系、来源单位或政策。

原始完整读出归档为results/aiohttp-native-display-20261103.tar.gz，摘要5b993beff9f0f217e13585026076872d9125fafcc43ad94ea19210767a21bb48。独立verify_preparation.py使用不同解码实现，逐项恢复三个实际材料并与原始完整读出严格比较，同时核对记录未改、共同原文及十二项位置。状态VERIFIED_LOSSLESS_AIOHTTP_PREPARATION，摘要41e0cd8404e203c8af3bd4e205d51e5c3f38ce4e2c644f02ef6ea01d70fe16bb。机械显示资格不表示Graph语义准确或具有收益。

使用真实模型tokenizer的最终检查如下，均加上共同8192输出上限后满足49152，没有截断任何来源或政策：

| 配置 | 实际输入tokens |
| --- | ---: |
| Raw | 21705 |
| Flat | 22743 |
| Graph | 31418 |

实际输入生成记录摘要6cedb14fedfa9e0c451ef53c81cf1c03afe4c3582fcc74787be4bd676c32361d。实际成本不同，不能声明等实际tokens。模型沿用原有Qwen2.5-Coder-32B-Instruct本地服务及共同静态YaRN；服务上下文由实际API确认49152。没有重新加载或修改权重，不与此前未使用YaRN的实验作表示效果归因比较。

## 独立语义评价

两个独立自动上下文评价实际最终材料，输入摘要均为e5dd1a02e397879c3ef18363be60124710747150619cf3f4a784fc95bdca8626。六项为对象身份、具体调用绑定、生命周期条件、错误分支范围、正常链复用及非目标保持。两个评审对Raw、Flat、Graph分别均为6/6 complete，无分歧。

这项准备评价为平局，没有建立Graph的绑定优势；六项判断及两个评审不能扩大一个自然任务的样本数。最终显示的评价为review-a-final-display.json与review-b-final-display.json。早期显示审查保留原有身份，不与最终审查合并为更多独立评审。评审全部为自动上下文，表示格式可辨识，误差可能相关，没有人工金标准。

## 控制重放及实际请求

新共享测量入口为src/measurement/middleware_lifetime.py，复用此前固定resource_profile.py。原始与作者参考程序在新入口各执行八项真实HTTP请求：原始保留四个错误路由对象，参考全部释放；两者均通过正常链复用、响应、中间件顺序及归属检查。实际原始记录中的三项正常复用及三轮四对象存活状态已核对。状态VERIFIED_REAL_AIOHTTP_CONTROL_REPLAY。它是两个作者控制，不是模型生成或独立科学任务。

输入包results/aiohttp-representation-20261103-runtime-inputs.tar.gz为2880743字节，摘要354b6e54528631f703f9863cc126961c891880b87f2b7471f39b2e77f6d3cb46，本地与服务器一致。完整生成计划generation-plan.json摘要7e6c818803a7f8a2e05680c6c10929210aefdec39491cbb02b7a8cfb1ecb1736，包含三个提示、固定种子、顺序、参数和测量及核对实现摘要。

十二项请求全部完成，十二份代码均通过语法解析并接受相同实际HTTP测量及独立结果核对。实际输入位于项目inputs/aiohttp-representation-20261103-runtime，结果为results/aiohttp-representation-20261103-generation，过程记录为results/aiohttp-representation-20261103-driver.stdout.txt及stderr。单个生成工作进程，temperature=0.7、top_p=1、最多8192输出tokens；没有修复、替换候选或追加种子。

## 完整代码结果

| 配置 | 完整政策成功 | 全部局部功能成功 | 联合成功 | 政策unknown |
| --- | ---: | ---: | ---: | ---: |
| Raw | 4/4 | 4/4 | 4/4 | 0/4 |
| Flat | 3/4 | 2/4 | 2/4 | 1/4 |
| Graph | 1/4 | 1/4 | 0/4 | 2/4 |

Raw全部释放四个错误路由对象，同时保留响应、中间件顺序、归属及正常链复用。Graph相对Raw的政策点差为负75个百分点，联合成功点差为负100个百分点；这些是一个来源的四个固定种子观察，没有总体统计推断。Graph相对Flat也没有代码收益。准备材料的六项语义评价均完整，未能保证实际实现遵守对应义务。

request-00为Flat，导入阶段因缺少AccessLogger而失败，没有完整观察，保留政策unknown。Graph的request-02使用未导入SystemRoute，request-11使用未导入MatchInfoError，实际HTTP请求发生NameError，最终错误路由观察数量为零；两份均保留政策unknown及功能失败，不记作安全。request-11还包含cache_info().cache_get调用，这一额外静态代码事实没有经过候选修复后的独立执行。

Graph的request-04保留四个错误路由对象，三轮GC后的存活状态均为真，局部功能检查通过。其代码将缓存改为字典，在命中分支才尝试从handler读取match_info；该实现没有取得实际要求的释放结果。Graph的request-05全部释放错误路由对象，但移除了正常构建函数的lru_cache装饰，正常链复用失败。Flat的request-06也出现释放成功、正常缓存复用失败的组合。两份的响应、顺序及归属检查通过，但均不计为全部功能或联合成功。

所有生成的finish_reason均为stop，输出4279至4527 tokens，未达到8192上限；十二份均可解析。这些事实不支持把失败归因于输出截断。Graph实际输入更长，但当前比较没有单独识别长度的因果作用，也没有证明更长输入造成上述具体失败。

结果摘要c97a32dabfa806906f6d19216bc2167431cbdd0c63f017a99a5f26c2f34b07cd，独立核对状态VERIFIED_ASSIGNED_AIOHTTP_LIFETIME，全部12项保留在分母。核对结果摘要c8adf0c6d98898212b0e7f1f806f881877f20cb72dade53a5dc70b4cb0af9da0，核对器摘要4431cbb42d02a773c579db6a3a5736314bf1e4f0870aba29b2effbaed30d560d。核对逐项重建原始请求、响应代码提取、源码及依赖身份、实际HTTP记录、释放与功能判定及各组计数。

事后诊断入口diagnose.py及diagnostic.json保存实际候选AST、导入、相关方法、运行异常和逐项结果，诊断摘要d4d72df2f386c1b9cf775076b23ed1e37c178cb577502a295f08fcee3576c502。没有新增生成或实验重复，也没有修改原始观察。

完整冻结包results/aiohttp-representation-20261103-frozen.tar.gz大小3870844字节，摘要43ee5be2f3b65f1d756ff79ac31d07184e5f277c4357622f5894062df05e253b，本地与服务器archive相同。它包含初始运行输入、完整原始显示归档、表示准备、两份语义评价、控制重放、十二项实际生成和测量及核对实现。原始显示归档保留verify_preparation.py所需的无损显示父材料。

已在.test-tmp/aiohttp-representation-20261103-full-replay独立解压完整包，排除generation-results/verification.json，再解压包内初始运行输入，使用其原样src提供.runtime/prompt_mechanism_study导入。包内verify_generation.py重新核对全部12项原始结果，输出逐字节复现c8adf0c6d98898212b0e7f1f806f881877f20cb72dade53a5dc70b4cb0af9da0。没有重新生成或执行候选，未依赖当前工作区发生变化的源码。

本检查没有建立Graph收益，Raw在该暴露任务上已达到观察到的成功上限。后续方法调整需要使用Goal允许的修订并固定新评价，不能继续追加本任务种子寻找正结果。单来源开发检查不提供总体Graph、自然任务JCI或策略价值证据；完整功能及内存耗尽防护继续未知。
