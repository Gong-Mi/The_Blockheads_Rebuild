# 已恢复的事实 ↔ 替换版 app：采用/缺席/待查台账

口径：本表只回答"**这个事实的痕迹是否出现在 `app/src/main/cpp/` 里**"。
"没有痕迹"**不等于**缺口——重写版可以用自己的命名与结构表达同一语义（Ob**j**C 协议名尤其如此）。
判定"素材性缺口"需要看 app 自己的模型**是否覆盖同一语义**，本表把这类逐条标为待查，不下结论。

## 已采用（有痕迹且语义相同）

| 事实 | 来源 | app 落点 |
|---|---|---|
| fastForward 下世界钟 20 单位/真秒 | `LIVE_WORLD_CLOCK.md`（活体 20.00012） | `game_world.h` `kOriginalFastForwardScale` |
| 一天 = 900 世界单位 | `WORLD_TIME_DOMAIN.md`（静态 900.0 常量） | `game_world.h` `kOriginalSecondsPerDay` |
| 昼夜比例是**周期 ≈895–900 的正弦**（不是锯齿） | 活体 100 点三周期拟合 | `day_phase.h` `dayPhaseFraction` / `headingTowardsMidday`，由 `game_world.h` 委托 |

## 缺席但合理（命名/结构差异，不是缺口）

| 事实 | 为何不算缺口 |
|---|---|
| `-[X update:accurateDT:isSimulation:]` 协议名（52 个类） | 这是 Ob**j**C 运行时的选择器名；重写版用自己的帧循环与 dt 参数表达同一概念 |
| `timeOfDayFraction` 原名 | app 用 `dayFraction()` 表达同一量，并有测试绑定到实测样本 |

## 待查（缺席且可能承载同一语义）

| 事实 | 为何可能要紧 | 需要什么才能判定 |
|---|---|---|
| DynamicObject 标志簇 `isNet@52` / `needsRemoved@48` / `updateNeedsToBeSent@49` / `creationDataNeedsToBeSent@50` / `unreliableUpdateNeedsToBeSent@51` | 原版用这五个字节承载**网络脏位与移除位**，而 v4 存档要保存动态对象 | 读 `app/src/main/cpp/dynamic_object_registry.{h,cpp}` 与 v4 序列化，看它是否用别的结构表达同一状态；grep 只能证明字符串不在，证明不了语义不在 |
| `worldChangedSimulateCounter`（活体 ≈30/s） | 模拟步进计数；若 app 要复现"每秒 30 次模拟更新"的节奏就需要等价物 | 同类：看 app 帧循环的模拟节奏是否有对应计数 |
| 音频 94 个未接播放点（共 275 对、已接 42） | 事件→音效语义仍缺 | 需要把播放点与游戏事件对上，属于尚未完成的逆向，不是回归 |

## 已界定（追到底了，结论有边界）

### DynamicObject 标志簇 —— 读了两个文件后判定

`app/src/main/cpp/dynamic_object_registry.h` 的 `ClientDynamicObject` 是**装载侧**模型：`type_id` / `class_name` /
`unique_id` / 整数与浮点位置 / `has_float_pos` / `ObjectLoadStatus` / 解码出的 `RecoveredState`。
**没有任何一个网络标志位**，且这不是遗漏——它压根不建模"要不要发出去"这件事。

原版那五个字节的作用分工是清楚的（**本轮读文件得到的**，不是之前的猜测）：

| 原版字段 | 语义 | app 是否有等价物 |
|---|---|---|
| `needsRemoved@48` | 标记待移除 | **语义等价**：注册表直接删除对象即可表达同一状态，结构不同不算缺口 |
| `isNet@52` / `updateNeedsToBeSent@49` / `creationDataNeedsToBeSent@50` / `unreliableUpdateNeedsToBeSent@51` | 网络复制脏位（新对象要发创建数据、变更按可靠/不可靠通道发） | **无等价物，且当前不需要**：它们服务于联机复制；重写版是否实现复制是**功能范围**问题，不是逆向缺口 |

**能定论的条件**（写清楚，免得下次又靠 grep）：如果重写版要做联机，就需要一套"新对象/变更/不可靠变更"的发送状态机，
那时这五个字段的**真值规则**（`!= 0` 即置位，signed char 负值也算 ✓，已由 `dynamicobject_flags.json` 与 C++ 契约测试固定）
就是现成的规格；在那之前，把它当"已界定"而不是"待查"。

## 一条方法学提醒

本轮之所以发现锯齿问题，是因为**拿实测去对产品代码**，而不是因为又一次静态扫描。
同类检查值得定期做：已恢复事实逐条问"app 里有没有痕迹、语义是否相同"，
但**必须保留三分类**，否则会把命名差异误报成缺陷（本次 grep 里 6 项"缺席"中只有 2 项真的值得追）。
