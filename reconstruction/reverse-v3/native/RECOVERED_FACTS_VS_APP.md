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

## 一条方法学提醒

本轮之所以发现锯齿问题，是因为**拿实测去对产品代码**，而不是因为又一次静态扫描。
同类检查值得定期做：已恢复事实逐条问"app 里有没有痕迹、语义是否相同"，
但**必须保留三分类**，否则会把命名差异误报成缺陷（本次 grep 里 6 项"缺席"中只有 2 项真的值得追）。
