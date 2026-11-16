# aiohttp原始来源的真实HTTP结果

## 独立来源审查

第四项固定来源CVE-2024-52303的11份原始程序和公开文档经过独立上下文审查。操作可解释性、安全边界和可保留行为均supported；context_sufficiency为unknown，原因包括缺少完整自然编程请求，以及尚未固定的任务义务、运行和测量条件。这些条件与来源语义分别记录，旧unknown判断保持原值。

来源上下文摘要为 `4144af4d2eec492655f64c987ed814aca47e60b03dd0e7e84f30b675b2aaf989`，独立评审摘要为 `c4d95d2ec1198caf877f8e15286ac6a1dac0e4c950012619a41292e1130cd120`。逐字证据和四项判断通过verify_aiohttp_context.py核对，核对摘要为 `333ebd24bc212fcd3e50e29b47aa3e58afdb1c5f7dc8e060c3c224e8ec78f518`。基准完整要求表达、Atomic、Oracle和代码生成资格均保持未知或未取得。

上游[公开公告](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-27mf-ghqm-j3j8)将中间件和匹配错误造成的缓存积累联系起来；本轮只以实际原始候选运行判断局部行为，没有读取修复实现。

## 实际执行与完整请求

按[执行前设计](2026-11-02-aiohttp-runtime-profile-design.md)，使用已核对原始提交158bf304bdd8047eec192540fa5bf7fe3862bffd，实际导入版本3.10.11rc0。Python为3.12.16，aiohttp扩展关闭，依赖使用现有环境只读取得的九个实际包、130项文件。没有改动共享模型环境，没有将已安装aiohttp的代码放入依赖归档；实际导入源码与依赖逐模块核对摘要。

容器没有外部网络，原始服务端和客户端通过回环接口完成八项真实HTTP请求；没有替代路由器、异常、中间件、缓存或网络。八项响应、成功正文、HEAD空正文和八次中间件调用均符合预定检查。

| 顺序 | 方法与路径 | 实际状态 | 请求后缓存条目 | 请求后hits |
| ---: | --- | ---: | ---: | ---: |
| 1 | GET /ok | 200 | 1 | 0 |
| 2 | GET /ok | 200 | 1 | 1 |
| 3 | GET /missing | 404 | 2 | 1 |
| 4 | GET /missing | 404 | 3 | 1 |
| 5 | POST /ok | 405 | 4 | 1 |
| 6 | POST /ok | 405 | 5 | 1 |
| 7 | HEAD /ok | 200 | 5 | 2 |
| 8 | GET /ok | 200 | 5 | 3 |

初始缓存为空，最后currsize=5、hits=3、misses=5、maxsize=null。四次错误请求各增加一个缓存条目，重复正常请求复用已有条目。原始HTTP功能在这一局部配置可用，错误请求的条目积累已有实际观测；本轮没有测量内存耗尽、对象释放或拒绝服务阈值。

## 独立核对与冻结身份

独立核对verify_profile.py读取原始响应、缓存前后值、中间件事件、全部导入模块及130项真实依赖文件，状态为 `VERIFIED_ORIGINAL_AIOHTTP_HTTP_PROFILE`。原始结果摘要 `379b24ea35fc08cb74097116f7f919435939bf71bb66939c58c3ba0880299646`；核对摘要 `584a4eaec4f4cf52c044bb4fbd52c414b13e549b12c7b9a5e5a49ba0c8f8118f`。

执行前输入归档为 `results/aiohttp-runtime-profile-20261102-inputs.tar.gz`，1984795字节，摘要 `b83cfeff6ea40bfd8de763e72d3dcfb18856944b39d205253cd6049f458fd915`。依赖归档摘要为 `aff4f8926ff8fd1c0ec5cbe4daf75b83ec07b896bb7059ba253c2eeab93ee2a6`，完整原始源码归档摘要为 `ff07fff48e8c8a8a34bac18eb289091d8d1e148a5a2b6342c854a98d6c152e19`。

本地输入与结果位于data/method/aiohttp-middleware-contract-20261102，来源评审位于data/method/security-code-source-20261102/aiohttp-source-review.json。服务器实际输入为项目inputs/aiohttp-middleware-contract-20261102/profile-inputs，结果为results/aiohttp-middleware-contract-20261102-profile。run_profile.sh保存真实运行条件及顺序。

完整冻结包为 `results/aiohttp-runtime-profile-20261102-frozen.tar.gz`，2079789字节，摘要 `ab2fbc7b66abf14c1a2d2c193e6193e87505097de16d968294daf3d9e4338bc3`，本地与服务器归档一致。在 `.test-tmp/aiohttp-runtime-profile-20261102-replay`独立解压，使用包内来源、评审、实际响应及依赖归档重放两项独立核对；来源核对与HTTP核对分别逐字节复现 `333ebd24bc212fcd3e50e29b47aa3e58afdb1c5f7dc8e060c3c224e8ec78f518`和 `584a4eaec4f4cf52c044bb4fbd52c414b13e549b12c7b9a5e5a49ba0c8f8118f`。该核对重放没有新增HTTP请求、模型调用或独立任务样本。

## 方法含义与未完成条件

本轮提供了可运行的局部HTTP条件，能够区分正常路由复用和错误请求积累。未来资源安全Oracle需要另行固定对象保留、缓存归属、请求完成窗口及独立正反控制，不能直接把缓存接口存在与否当作通用安全答案。运行时状态应由这些具体观测与独立来源语义共同判断。

来源任务仍需明确作者任务和单项要求、非目标HTTP范围、中间件类型及应用层级。现有检查只包含一个新式中间件、一个应用和所列请求；老式与混合中间件、父子应用、Expect和路径规范化均未获得测量资格。所有未知保持原身份。生成调用为零，未建立Graph、JCI、完整HTTP功能、完整安全、正式确认或总体组件收益。
