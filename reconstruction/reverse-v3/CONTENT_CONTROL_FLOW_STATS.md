# Content control-flow slice statistics

本文记录从原版 `libApplication.so` 对内容关键 IMP 做 ARM 控制流分析得到的函数规模和分支复杂度。它用于约束重建范围：大函数不能被一个同名的简单替代函数冒充为兼容实现。

## 分析对象

```text
APK SHA-256: cae0371354dfda125793ba974c1f7a55b2161ed6d9c458f962da9eb468f8ec54
ELF: lib/armeabi-v7a/libApplication.so
ABI: ARMv7 / ELF32 ARM EABI5
```

分析方式：

```text
Objective-C method metadata
  → IMP address
  → `.ARM.exidx` function boundary
  → r2 ARM analysis (`af` / `afij`)
  → basic-block / edge / instruction statistics
  → selector references from the same IMP
```

这些统计是二进制控制流事实，不是源码复杂度估计。

## 关键 IMP 规模

| 类/方法 | IMP | 函数大小 | 基本块 | 指令数 | 控制流边 | 直接内容含义 |
|---|---:|---:|---:|---:|---:|---|
| `Blockhead -interactionTypeForTile...` | `0x00ba0fe0` | 34,784 B | 1,063 | 8,544 | 1,702 | Tile/物品/权限/动态对象 → InteractionType |
| `Blockhead -pickUpItemIfPossibleInTile...` | `0x00be91fc` | 13,652 B | 192 | 3,309 | 285 | Tile/freeblock/dynamic object → pickup/inventory |
| `Blockhead -pickupFreeblockIfPossible...` | `0x00c61c00` | 7,172 B | 112 | 1,762 | 167 | 容量、权限、simulation event、freeblock 移除 |
| `Blockhead -update:accurateDT:isSimulation:` | `0x00bb9238` | 151,360 B | 2,159 | 36,558 | 3,232 | Blockhead 需求、动作、交互、制作、伤害 |
| `BlockheadAI -update:isSimulation:` | `0x006d55d0` | 8,396 B | 155 | 2,039 | 228 | AI 目标/物品/睡眠/种植/照明/动作队列 |
| `World -craftItem...` | `0x005b83d0` | 1,240 B | 17 | 309 | 23 | 工作台制作动作入口 |
| `DynamicWorld -createFreeBlock...` | `0x008ddc78` | 2,368 B | 23 | 592 | 31 | 动态掉落对象创建、唯一 ID、网络和声音 |
| `DynamicWorld -createFreeBlock...forForegroundContents...` | `0x008de880` | 1,808 B | 35 | 452 | 49 | Tile contents → foreground freeblock |

`Blockhead::update` 的 151 KB/2,159 基本块和 `interactionTypeForTile` 的
34 KB/1,063 基本块说明，原版内容系统不是可以由单个 `if/else` 或一个简单
`Player::update` 等价替换的逻辑。

## 交互判定的控制流边界

`0x00ba0fe0` 的函数签名为：

```text
interactionTypeForTile:
  Tile*
  world position
  item
  pickupRejectedDueToInventoryFull*
  includeActions
  faceIndex
  allowProtectedActions
```

同一函数的直接引用集合包含：

```text
canDigBackWallforTile:atPos:withItem:includeActions:
canPickUpItemOfType:subItems:
countOfInventoryItemsOfType:includeActions:
interactionObjectAtPos:
freeBlocksAtPos:
freeBlocksExistAtPos:
workbenchAtPos
chest/door/ladder/stairs/window/wire/torch/column/elevator 查询
paintingAtPos
eggAtPos
getPlantAtPos
blockheadAtPos
tileIsLitForSelf:atPos:
tileIsProtectedAtPos:againstBlockhead:
```

因此它是一个多分支交互分类器，而不是一个单一的“可挖/不可挖”布尔判断。

## 拾取路径的控制流边界

`Blockhead -pickUpItemIfPossibleInTile:atPos:`：

```text
IMP: 0x00be91fc
192 basic blocks
```

同一 IMP 直接引用：

```text
pickupItemForTile:astPos:
pickupFreeblockIfPossible:inTile:intentional:
addItemToInventory:flash:
pickupDynamicObject:
freeBlocksAtPos:
freeBlockCreationSaveDict
freeblockCreationItemType
createFreeBlockAtPosition:ofType:dataA:dataB:subItems:...
removeColumnAtPos:
removeDoorAtPos:
removeEggAtPos:
removeElevatorMotorAtPos:
removeElevatorShaftAtPos:
removeLadderAtPos:
removePaintingAtPos:
removeStairsAtPos:
removeTorchAtPos:
removeWireAtPos:
```

这提供了内容级控制流边界：一个“拾取”动作可能先判断 Tile 内容，再判断
freeblock、dynamic object、特殊对象或宝石，最后才修改库存和世界对象。

## Blockhead 更新函数的状态范围

`Blockhead -update:accurateDT:isSimulation:`：

```text
IMP: 0x00bb9238
151,360 bytes
2,159 basic blocks
36,558 instructions
```

同一函数直接引用的状态/副作用包括：

```text
health/fullness/energy
asleep/meditating/falling/crouching/underwater
cactus/drowning/fire/starvation/oxygen/fall damage
interactionTypeForTile
startInteractingWithTileAtIndex
pickUpItemIfPossibleInTile
fillTile/removeTile/placeWorkbench/placeInteractionObject
createFreeBlockAtPosition
craftItem / craftProgressUI
removeCurrentItem/removeInteractionItem
incrementUsageOfItem/incrementFuelUsage
worldChangedAtPos/dynamicWorldChangedAtPos
sendDataToServer:reliable:
```

这证明生存状态、动作执行、内容变化、库存、网络同步和音频/粒子副作用都
在 Blockhead 模拟控制流中有交叉，而非互不关联的若干独立 demo 功能。

## AI 更新函数的状态范围

`BlockheadAI -update:isSimulation:`：

```text
IMP: 0x006d55d0
8,396 bytes
155 basic blocks
```

直接引用：

```text
testTileAtPos:
queueBlockheadAIActionToTile:atPos:forBlockhead:
itemIndexWithGoodInteractionTypeForTile:
setCurrentItemToItemAtIndex:
useCurrentItemIfPossible
sowableItemForAIItemType/sowableItemForAIItemIndex
placableLightForAIItemType/placableLightForAIItemIndex
mostCommonFoodTypeIndex
sleepOnSpotIfPossibleOtherwiseCancelActions
```

AI 控制流的正确边界是：

```text
观察 Tile/Blockhead 状态
  → 选择物品和目标
  → 注入统一 action queue
  → 由 Blockhead 更新函数执行
```

不能把 AI 实现成单独的随机游走线程后宣称兼容。

## 制作和动态对象的较小入口

制作入口相对短，但它不是最终产物逻辑：

```text
World -craftItem:atWorkbench:withBlockhead:count:
IMP: 0x005b83d0
17 basic blocks
```

直接引用：

```text
currentInteractionTypeForTile:...
queueActionWithGoalPos:...
tileIsProtectedAtPos:againstBlockhead:
activeBlockhead
```

动态掉落对象入口：

```text
DynamicWorld -createFreeBlockAtPosition:ofType:...
IMP: 0x008ddc78
23 basic blocks
```

直接引用：

```text
FreeBlock initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:...
uniqueID
creationNetDataForFreeblockAtPosition:...
sendNetDataIfNeededForObject:isCreation:
setSoundType
setCreationSoundPlayTime
```

因此制作是“建立 Blockhead 目标动作”，掉落物是“动态对象创建”，二者都
不是 UI 点击后直接修改几个整数。

## 对当前重建的直接约束

当前重建如果要逐步接近原版，最小数据和控制流边界应为：

```text
InteractionTypeResult
  interaction type
  goal tile
  face index
  protection/capacity result
  dynamic object reference

BlockheadAction
  goal position
  path type
  goal interaction
  interaction object ID
  craft object
  count/extra data
  isAI

TileState
  tile type
  back-wall type
  contents type
  dataA/dataB
  fluid/light/temperature

FreeBlock/WorldObject
  unique ID
  item/type
  subItems/dataA/dataB
  save dictionary
  network creation/update/removal state
```

然后才能把：

```text
interaction
→ action queue
→ path/arrival
→ tile/object mutation
→ inventory/freeblock mutation
→ world dirty/network/save
```

作为一个可测试闭环接入当前 C++ 框架。

## 本轮限制

- `objc_msgSend` 的 receiver 是动态的，当前统计不等于完整运行时对象类型。
- 函数体内的 selector 引用证明候选调用边界；严格执行顺序仍需基本块级
  selector 装载/发送配对或运行时 tracing。
- 函数规模证明复杂度和边界，不自动证明每个分支的语义名称。
- 本文件是原版 native 静态证据，不是当前重建的真机验收报告。
