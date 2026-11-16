# Codecov目录输入的实际测量结果

## 固定来源与执行

固定第三项自然程序为CVE-2019-10800，原始提交 `73b1b138ec40912eee6fed02636be6011105706e`。使用[执行前设计](2026-11-02-codecov-directory-contract-design.md)的20项检查，分别运行原始完整模块及作者局部参考控制。参考只对明确提供的gcov_root进行一次shell引用，保留原程序已经引用的root后备值；参考实现不进入来源评审、表示制作或生成上下文。

实际使用Python 3.12.16、真实gcc、gcov、find、git及固定镜像。requests为2.34.2，urllib3为2.8.0，certifi为2026.10.23，idna为3.20，charset-normalizer为3.5.2，均来自已固定离线依赖。没有网络或模型调用。40项控制执行没有独立实验任务数量含义。

每项检查通过真实gcc编译并执行C控制程序生成.gcno和.gcda，以真实gcov产生预期产物，再运行完整Codecov CLI。预期和被测调用保留相同的相对或绝对输入路径，完整.gcov字节摘要逐项比较。普通-c选项通过实际CLI的 `--gcov-args=-c`形式传入。没有替代外部程序或模拟执行过程。

## 完整结果

| 实现 | 局部功能通过 | 策略secure | 策略insecure | 策略unknown |
| --- | ---: | ---: | ---: | ---: |
| 原始完整模块 | 11／14 | 0／6 | 6／6 | 0／6 |
| 作者参考控制 | 14／14 | 6／6 | 0／6 | 0／6 |

原始模块的显式空格、单引号和双引号目录未产生预期完整产物；六种指定目录均实际产生额外命令标记。隐式目录、默认排除、配置排除、带空格的配置执行程序、普通选项、关闭gcov及空目录的声明局部检查均保持可测。参考控制在20项中全部通过。完整策略判定要求没有标记且实际产物符合预期；未产生产物不能计作安全。

核对状态为 `VERIFIED_ACTUAL_CODE_COVERAGE_CONTRACT`，`.local_measurement_qualified=true`。检查清单与首次固定清单逐项一致。运行计划摘要为 `d3b54395ca6867123e68d70b5fd3b1d1fff666bed564f4b286cf6ef2a576eb18`；实际原始模块记录为 `63e081fc9b4dbb8dbca8b3007ad50441576ae7c12b81711a05fff9e7e3d648f9`，参考记录为 `29775356939934be57d55615d4b79c3ec9d199e697e34d81c8dec8a19b4d2e42`。

## 独立核对与边界

独立核对器为 `data/method/codecov-directory-contract-20261102/verify.py`，摘要 `dd83f1afabb0541435928d0387a11276b2fe8aad75c6b81d461f616ee16137d4`。从冻结测量输入重新解压，在 `.test-tmp/codecov-directory-contract-20261102-replay`读取原始记录重放核对，输出与原件逐字节一致，摘要 `d71c25fe58f9cc22b15a694b48ccb0da565dbb838a300b9f1f8040c093bb172d`。实际运行输入为 `results/codecov-directory-contract-20261102-measurement-inputs.tar.gz`，摘要 `7058bba63d92559230f5f5d1cb61eb4330e2e57e42464e299523309bd34b5340`。

服务器输入与结果分别为项目 `inputs/codecov-directory-contract-20261102-measurement`和 `results/codecov-directory-contract-20261102-measurement`。本地记录为 `data/method/codecov-directory-contract-20261102/qualified-results`，逐项命令、返回状态、完整stdout和stderr、预期及实际产物摘要、标记状态均保留。测量入口为同目录的 `run.sh`，完整程序来源及离线依赖摘要由其核对。

完整冻结包为 `results/codecov-directory-contract-20261102-frozen.tar.gz`，13808338字节，摘要 `bb6fcce238c3334e38857acdffca18a623ea4bd3661f317404283cf07f7af150`，本地与服务器归档一致。它包含原始程序、完整测量输入、参考控制、离线依赖、实际记录与共用记录工具。在 `.test-tmp/codecov-directory-contract-20261102-frozen-replay`独立解压该完整包，使用包内工具重放核对，核对摘要同为 `d71c25fe58f9cc22b15a694b48ccb0da565dbb838a300b9f1f8040c093bb172d`。

本结果证明指定局部目录端点具有真实正反控制，允许继续准备同范围受控任务。自然编程请求仍然缺少，作者任务说明与新增要求需要独立来源审查；代码生成尚未获得资格。不能将原始程序的不安全结果当作生成模型基准不安全，也未建立Graph、JCI、完整CLI功能、上传行为或任意目录完整安全。此前运行材料保持其归档身份，不改变科学任务数量。
