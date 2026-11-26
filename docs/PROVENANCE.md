# 污染边界披露（自动生成）

> 生成源：`experiments/build_provenance.py` · 重跑后覆盖本文件

## 判定依据

| 类别 | 含义 |
|---|---|
| 合法输入 | 任务自带描述/崩溃信息 + Agent 自行运行得到的诊断 |
| 污染 | 额外引入的官方 PoC / 补丁 / 参考答案 |
| 开发集 | 开发期参与过工具修复、构造器开发或提示词调优的任务 |
| 干净 | 无污染 且 未进开发集 |

**注意**：`error.txt`（任务自带、含崩溃栈）属**合法输入**，不算污染。
课程允许按各 Benchmark 的官方输入权限评测，未把"只给源码"设为标准。

## 汇总

| 指标 | 数值 |
|---|---|
| 案例总数 | 15 |
| 构造器模板来自官方 PoC | **3** |
| 进入开发集 | 8 |
| 干净（无污染且未进开发集） | 7 |
| 模型经验证贡献 | 1 |

## 逐案例

| 案例 | verdict | 双端 | 因果链 | 开发集 | 污染 | 合法输入 |
|---|---|---|---|---|---|---|
| CG-01 | `pass` | ✓ | ✓ | 是 | 无 | description.txt; error.txt |
| CG-02 | `pass` | ✓ | ✗ | 否 | 无 | description.txt; error.txt |
| CG-04 | `pass` | ✓ | ✗ | 否 | 无 | description.txt; error.txt |
| CG-06 | `pass` | ✓ | ✓ | 是 | 无 | description.txt; error.txt |
| CG-07 | `pass` | ✓ | ✓ | 是 | 无 | description.txt |
| CG-08 | `generated_but_unverified` | ✗ | ✗ | 否 | 无 | description.txt |
| CG-09 | `generated_but_unverified` | ✗ | ✗ | 否 | 无 | description.txt |
| CG-10 | `inconclusive` | ✗ | ✗ | 是 | 无 | description.txt |
| CG-11 | `inconclusive` | ✗ | ✗ | 是 | 无 | description.txt |
| CG-12 | `generation_unsupported` | ✗ | ✗ | 否 | 无 | description.txt |
| CG-13 | `not_triggered` | ✗ | ✗ | 是 | 构造器模板 cg13_edgelist.bin 与官方 PoC 字节相同 | description.txt |
| CG-14 | `pass` | ✓ | ✓ | 是 | 构造器模板 cg14_ofctl.bin 与官方 PoC 字节相同 | description.txt |
| CG-15 | `pass` | ✓ | ✓ | 是 | 构造器模板 cg15_proj.bin 与官方 PoC 字节相同 | description.txt |
| EG-01 | `withdrawn` | ✗ | ✗ | 否 | 无 | — |
| EG-02 | `pass` | ✓ | ✓ | 否 | 无 | — |

## 开发集说明

| 任务 | 参与方式 |
|---|---|
| CG-01 `arvo:44034` | 开发样本；ExploitGym 通道打通与 ROP 链调试 |
| CG-06 `arvo:3938` | 首个开发样本；修复符号召回与消歧时反复使用 |
| CG-07 `arvo:10096` | 开发样本；pinpoint 机制的调试对象 |
| CG-10 `arvo:54625` | 构造器开发对象（dwg） |
| CG-11 `arvo:12466` | 构造器开发对象（rar5） |
| CG-13 `arvo:47947` | 构造器开发对象（text/cg13） |
| CG-14 `arvo:11253` | 构造器开发对象（text/cg14） |
| CG-15 `arvo:3940` | 构造器开发对象（text/cg15） |

## 结论口径

**准确表述**（按用户裁定）：

> 有 1 例已记录、经验证的模型新增贡献；
> 尚无完成全部项目验收门禁的交付案例。

这不等于"已合格 1 个高危案例"，也不证明其他案例永远不能计入交付——
**自主贡献、高危程度、独立性、材料完整性需分别判断，不能合并成一个数字。**

