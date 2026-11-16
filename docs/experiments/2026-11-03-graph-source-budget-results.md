# 二十项固定来源的完整模块长度结果

## 实际计数与可用预算

二十项固定来源的二十五份候选模块已使用真实Qwen tokenizer检查。输入逐文件匹配已核对的上下文、snapshot、原始提交及SHA256，完整正文保留，没有生成代码调用。

二十五份模块在预留16384个输出tokens后均未超过49152的实际服务上限。模块含消息边界的输入长度为807至19723，政策、API及表示尚未加入，剩余空间为13045至31961。它们只通过模块本身的必要条件，没有取得完整任务或Graph提示资格。

| 较长的候选完整模块 | 输入tokens | 扣除16384后剩余tokens |
| --- | ---: | ---: |
| OctoPrint server/__init__.py | 19723 | 13045 |
| OctoPrint server/util/flask.py | 12502 | 20266 |
| Gradio routes.py | 10729 | 22039 |
| Gradio utils.py | 10712 | 22056 |
| OctoPrint access/users.py | 9579 | 23189 |
| Asteval asteval.py | 8326 | 24442 |

16384是本项检查前确定的共同候选预留。OctoPrint server/__init__.py含消息边界的原文已经达到19723，因此本项没有认证完整代码回传额度足够。其最终编辑范围和额度需要依据完整政策及原文模块确定；不能依靠文件较短判断另一处修改可以满足完整政策。其他文件也仍须容纳完整任务、API、准备材料及其输出。

后续预算规则在新代码生成前固定，同一任务的三种表示获得相同输出额度、工具和准备机会，逐一核对完整实际输入。该结果不支持截断共同原文，也不支持根据预算表直接剔除来源、扩大样本或声称Graph收益。

## 环境与实际输入身份

服务器实际/v1/models报告Qwen2.5-Coder-32B-Instruct、max_model_len=49152，原始响应随结果保留。tokenizer使用Python 3.12.13、transformers 4.57.6及tokenizers 0.22.2，环境为/home/wsy/miniconda3/envs/purp。模型目录为/home/ubuntu/RAID5/data/model_zoo/CodeLLMs/Qwen2.5-Coder-32B-Instruct。

tokenizer_config.json摘要959e7f1d9a1b7641a6d6ce05ca97b75c7894fcb66cbe5a040406458fb1128ee4，tokenizer.json摘要c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539。只读取本地tokenizer，不加载模型推理或修改服务配置。实际计数进程退出状态为零，stderr为空。

输入准备入口data/method/graph-jci-goal-20261103/prepare_source_budget.py，计数复用既有data/method/aiohttp-representation-20261103/check_prompt_context.py。前者核对固定第五至第二十四项身份、全部完整模块、上下文与snapshot摘要，后者应用真实chat template。

执行输入results/graph-source-budget-20261103-inputs.tar.gz为180009字节，摘要f487fa97748aad857979d5cf228d4271bc84abf770cd0479fd0fed9ec0b4474d，本地与服务器inputs一致。实际tokenizer输入摘要d05c21bfdf839e4d5459e3d1e3e6e82e53a5061e31a56b1915156f77256581e9，结果摘要d1ad74cdff6822e75bfc51d3fbb1323574f344e64f411e3cdad99ca765a79a1a。

实际工作目录为/home/wsy/work/prompt-mechanism-study/inputs/graph-source-budget-20261103，结果为项目results/graph-source-budget-20261103-tokenizer.json，原始stdout、stderr、环境和模型列表保留于同名前缀文件。本地副本位于.test-tmp/graph-source-budget-20261103。

在新工作副本中执行，输出文件使用新路径：

```sh
.venv/Scripts/python.exe data/method/graph-jci-goal-20261103/prepare_source_budget.py .test-tmp/graph-source-budget-20261103/tokenizer-inputs.json
/home/wsy/miniconda3/envs/purp/bin/python data/method/aiohttp-representation-20261103/check_prompt_context.py /home/ubuntu/RAID5/data/model_zoo/CodeLLMs/Qwen2.5-Coder-32B-Instruct .test-tmp/graph-source-budget-20261103/tokenizer-inputs.json .test-tmp/graph-source-budget-20261103/tokenizer-result.json
```

首项准备命令使用现有Windows环境；服务器执行相同程序时采用已有科学Python路径。两项命令分别承担源输入核对及真实计数，不能将计数结果解释为代码执行、安全率或新的科学评价轮次。

完整冻结包results/graph-source-budget-20261103-frozen.tar.gz为1467792字节，摘要d2fd1d2e2044591facb5591c4b4c865c616de3f178b133c4659674cb43b243b2，本地与服务器archive一致。包内保留完整计数输入、二十项原始上下文及snapshot、候选清单、准备与计数程序、真实结果及环境记录；tokenizer文件使用上文所列既有模型路径和摘要。
