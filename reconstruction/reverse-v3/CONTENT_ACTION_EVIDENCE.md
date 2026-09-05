# Blockheads content-action chain from exported IMPs

本文记录从原版 `libApplication.so` 的 Objective-C 方法表、IMP 地址和 ARM PIC selector 引用恢复出的内容动作链。它比全局类名/字符串扫描更强：每一行关键关系都来自具体 IMP 的方法体引用。但 Objective-C 动态派发仍使完整运行时顺序需要后续控制流或设备验证。

## 证据对象

```text
APK SHA-256: cae0371354dfda125793ba974c1f7a55b2161ed6d9c458f962da9eb468f8ec54
ELF: lib/armeabi-v7a/libApplication.so
ABI: ARMv7 / ELF32 ARM EABI5
```

关键方法地址来自：

```text
reconstruction/reverse-v3/native/libApplication_objc_methods.tsv
```

selector/CFString 引用使用 ARMv7 PIC 解析和 `.ARM.exidx` 函数边界提取。

## 1. 动作判定层：Tile + 当前物品 + 权限/库存

### Blockhead::interactionTypeForTile

```text
Blockhead -interactionTypeForTile:atPos:item:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:
IMP: 0x00ba0fe0
```

该 IMP 直接引用：

```text
canDigBackWallforTile:atPos:withItem:includeActions:
canPickUpItemOfType:subItems:
countOfInventoryItemsOfType:includeActions:
interactionObjectAtPos:
freeBlocksAtPos:
freeBlocksExistAtPos:
workbenchAtPos:
chest/door/ladder/stairs/window/wire/torch/column/elevator 查询
paintingAtPos:
eggAtPos
getPlantAtPos
blockheadAtPos
loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:
tileIsLitForSelf:atPos:
tileIsProtectedAtPos:againstBlockhead:
```

同时读取/产生的动作语义包括：

```text
interactionItem
itemType
subItems
dataA
dataB
objectType
ownerID
ironPlaceClientID
priorityBlockhead
goalInteraction
goalTilePos
```

因此 Blockheads 的“点一下 Tile 做什么”不是简单的：

```text
if tile != empty: mine
```

而是：

```text
raw Tile
+ back wall / contents / dataA / dataB
+ 当前 Item
+ 背包是否已满
+ 动态对象类型
+ 所有权/保护
+ 是否允许动作
+ faceIndex
→ InteractionType
```

### Blockhead::startInteractingWithTileAtIndex

```text
Blockhead -startInteractingWithTileAtIndex:tile:interactionType:
IMP: 0x00bb0e70
```

该 IMP 直接引用：

```text
blockheadReachedCraftDestination:craftingItem:craftingObject:count:
blockheadReachedInteractionObjectDestination:pathExtraData:
blockheadReachedAddFuelDestination:workbench:
craftItem:withBlockhead:craftProgressUI:count:
pickupDynamicObject:
stopInteracting
updateGatherSpeedAndAnimationForCurrentInterationAndItem
pickup/ride/breed/pet 相关入口
canUseDynamicObject:
setTargetVelocity:
startManagingFuelWithBlockhead:
setFuelUIShouldBeDisplayed:forBlockhead:fuelObject:
```

这个入口说明 Tile 交互不是立即改 Tile，而是可能先建立：

```text
目标 Tile
interactionType
路径目的地
动态对象
制作对象
燃料状态
动画/采集进度
```

然后由 Blockhead 抵达目标后执行具体动作。

## 2. 玩家/AI 共用的内容更新层

### Blockhead::update

```text
Blockhead -update:accurateDT:isSimulation:
IMP: 0x00bb9238
```

该 IMP 的直接引用包含以下内容边界。

### 状态/需求

```text
health
fullness
hunger/food 相关逻辑
energy
asleep
meditating
falling
crouching
underwater
 drownFraction
injured
burned
killed
shouldContinueSimulating
```

具体伤害原因字符串也存在于该 IMP：

```text
by a cactus
by drowning
by fire
by starvation
from lack of oxygen
in a fall
```

这证明需求、环境伤害和动作更新是在 Blockhead 模拟函数中共同处理的，而不是单独的 UI 数值。

### Tile/动态对象交互

同一 IMP 直接引用：

```text
interactionTypeForTile:atPos:item:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:
goodOrBadInteractionForAction:
startInteractingWithTileAtIndex:tile:interactionType:
pickUpItemIfPossibleInTile:atPos:
fillTile:atPos:withType:
fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:
removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:
removeBackWallAtPos:removeBlockhead:
removeInteractionObjectAtPos:removeBlockhead:
placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:
placeInteractionObjectWithItem:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:
```

因此内容动作的静态骨架是：

```text
Blockhead::update
  → determine InteractionType
  → start/interact or continue current interaction
  → fill/remove/place world state
  → emit world/dynamic-object change
```

### 物品使用和设备

同一 IMP 还引用：

```text
useCurrentItemIfPossible
removeCurrentItem
removeInteractionItem:
itemWillBeRemovedFromInventory:
incrementUsageOfItem:indexToUse:wasAttack:
incrementUsageOfInteractionItem:
incrementFuelUsage
hasInteractionInventoryItemAvailable
hasRequiredFuel
craftItem:atWorkbench:withBlockhead:count:
craftProgressUI
```

这说明使用物品、消耗耐久/燃料、制作进度和 Tile 修改属于同一个内容状态机，而不是独立的 UI 事件。

## 3. 掉落、拾取和背包链

### Blockhead::pickUpItemIfPossibleInTile

```text
Blockhead -pickUpItemIfPossibleInTile:atPos:
IMP: 0x00be91fc
```

该 IMP 直接引用：

```text
pickupItemForTile:astPos:
pickupFreeblockIfPossible:inTile:intentional:
addItemToInventory:flash:
pickupDynamicObject:
createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:
freeBlocksAtPos:
freeBlockCreationSaveDict
freeblockCreationItemType
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
removeDynamicObject / dynamic object cleanup
```

因此拾取不是单纯向 inventory 加一个 ID，而是可能处理：

```text
Tile foreground contents
Tile background contents
FreeBlock
Gem
DynamicObject
Door/Ladder/Stairs/Wire/Elevator/Torch/Painting/Egg
subItems
DataA/DataB
priorityBlockhead
hover/sound
```

### Blockhead::pickupFreeblockIfPossible

```text
Blockhead -pickupFreeblockIfPossible:inTile:intentional:
IMP: 0x00c61c00
```

该 IMP 直接引用：

```text
canPickUpItemOfType:subItems:dataA:dataB:
addItemToInventory:flash:
createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:
setNeedsRemoved:
addSimulationEventOfType:forBlockhead:extraData:
priorityBlockheadCannotPickup
worldUIDragging
isSimulating
```

这提供了一个可靠的内容闭环：

```text
freeblock
  → 检查 itemType/subItems/dataA/dataB
  → 检查 Blockhead 背包容量和限制
  → addItemToInventory
  → 标记 freeblock/dynamic object removal
  → 产生 simulation event
  → 必要时创建替代 freeblock 或网络状态
```

### Blockhead::addItemToInventory

基础入口：

```text
Blockhead -addItemToInventory:
IMP: 0x00c5f904
```

扩展入口：

```text
Blockhead -addItemToInventory:flash:disableWarpCheck:forceSlotIndex:
IMP: 0x00c5fa6c
```

扩展入口直接引用：

```text
addItemToFoundList:
addObjectsFromArray:
insertObject:atIndex:
removeAllObjects
checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:
flashInventoryAtIndex:subIndex:forBlockhead:color:
reportAchievementWithIdentifier:
```

由此可确认背包行为还包含：

```text
subItems
DataA/DataB
forced slot
UI flash
found-item progression
second Blockhead warp check
achievement side effect
```

当前重建的 `Player::addItem(int type, int count)` 只覆盖了最基础的 type/count 堆叠，尚未覆盖这些原版语义。

## 4. AI 内容入口

### BlockheadAI::update

```text
BlockheadAI -update:isSimulation:
IMP: 0x006d55d0
```

直接引用：

```text
testTileAtPos:
queueBlockheadAIActionToTile:atPos:forBlockhead:
itemIndexWithGoodInteractionTypeForTile:
setCurrentItemToItemAtIndex:
useCurrentItemIfPossible
sowableItemForAIItemType
sowableItemForAIItemIndex
placableLightForAIItemType
placableLightForAIItemIndex
mostCommonFoodTypeIndex
sleepOnSpotIfPossibleOtherwiseCancelActions
asleep
canSleepOnSpot
fullness
health
currentInteractionRequiresHumanInput
hasActions
isRunByAI
allBlockheadsIncludingNet
dynamicWorld
```

由此可以把 AI 内容链写成：

```text
AI update
  → inspect Tile
  → choose item suitable for interaction
  → choose food/plant/light item when needed
  → queueBlockheadAIActionToTile
  → path/interaction state
  → Blockhead update executes action
```

AI 不是另一个独立世界模拟；它向 Blockhead 的统一 action queue 注入内容动作。

## 5. 制作链

### World::craftItem

```text
World -craftItem:atWorkbench:withBlockhead:count:
IMP: 0x005b83d0
```

该 IMP 直接引用：

```text
currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:
queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:
tileIsProtectedAtPos:againstBlockhead:
activeBlockhead
```

它不是直接合成，而是先检查当前交互和保护状态，再向 Blockhead action queue 加制作目标。

### World::craftOrConfigureItem

```text
World -craftOrConfigureItem:atWorkbench:withBlockhead:count:
IMP: 0x005b88f8
```

直接引用：

```text
craftItem:atWorkbench:withBlockhead:count:
setWorkbench:blockhead:craftableItemObject:
craftableItem
craftUI
workbenchChoiceUI
paintMixUI
addBlockheadUI
showTimeCrystalUITapped
```

所以工作台制作包含两层：

```text
UI 选项/配置
  → World::craftOrConfigureItem
  → World::craftItem
  → queue Blockhead action
  → 抵达工作台
  → craft progress
  → craftItemFinished
```

### Blockhead::craftItemFinished

```text
Blockhead -craftItemFinished:atWorkbench:
IMP: 0x00c73100
```

直接引用：

```text
stopInteracting
```

虽然该小函数本身引用很少，但它位于制作动作完成边界；实际产物/库存修改由更上游的 workbench/craft progress 路径共同完成，不能把这个方法单独当成完整配方实现。

## 6. 世界改变与网络/存档副作用

### DynamicWorld freeblock 创建

```text
DynamicWorld -createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:
IMP: 0x008ddc78
```

直接引用：

```text
FreeBlock initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:
addObject:
uniqueID
creationNetDataForFreeblockAtPosition:...
sendNetDataIfNeededForObject:isCreation:
setSoundType
setCreationSoundPlayTime
multiSoundNamed:
playAtPosition:afterDelay:
```

所以掉落物是有唯一 ID、创建网络数据、声音和延迟播放状态的动态对象，不是简单坐标+物品 ID。

### DynamicWorld foreground contents 创建

```text
DynamicWorld -createFreeBlockAtPosition:forForegroundContents:forTile:priorityBlockhead:
IMP: 0x008de880
```

直接引用：

```text
destroyItemType
getSaveDict
interactionObjectAtPos:
workbenchAtPos:
paintingAtPos:
torchAtPos:
wireAtPos
stairsAtPos
columnAtPos
```

这说明 Tile 的 foreground contents 破坏后，掉落内容需要结合 Tile 原始字段和对应的动态对象类型，不能统一按 TileType-1 生成物品。

### 世界变化通知

```text
DynamicWorld -worldChangedAtPos:sendReliably:
IMP: 0x008df7a4

DynamicWorld -worldContentsChangedAtPos:
IMP: 0x008e046c

DynamicWorld -dynamicWorldChangedAtPos:objectType:
IMP: 0x008e1390
```

这些入口区分：

```text
world tile change
world contents change
dynamic world object change
```

这正是当前重建需要从单一 `foreground` 字段中拆出的三个状态边界。

## 7. 从内容反推出的最小重建模型

原版内容链要求至少保留这些对象：

```text
TileState
  tileType
  backWallType
  contentsType
  dataA
  dataB
  fluid/light/temperature fields

BlockheadAction
  goal position
  interaction type
  path type
  interaction object ID
  craft object
  craft count / extra data
  isAI

ItemStack
  item type
  subItems
  dataA
  dataB
  usage/durability

FreeBlock
  unique ID
  position
  item type
  subItems
  dataA/dataB
  dynamic object save dict
  hover/sound

WorldObject
  unique ID
  object type
  position/orientation
  inventory/state
  network data
  save dict

WorldChange
  tile change
  contents change
  dynamic object change
  reliable/unreliable network dirty state
```

最小动作闭环：

```text
tap/select item
  → interactionTypeForTile
  → queue action/path
  → startInteractingWithTile
  → Blockhead update
  → remove/fill/place/craft/pickup
  → item/freeblock/dynamic object mutation
  → worldChanged/worldContentsChanged/dynamicWorldChanged
  → inventory/network/save dirty state
```

## 8. 当前重建的真实差距

当前 `The_Blockheads_Rebuild` 已经有：

```text
基础 Tile foreground/background
基础 Player inventory
基础 drop entity
基础 CraftingManager
基础 World remove/fill
基础 BlockheadAI
```

但与导出 IMP 反推的内容模型相比，仍缺：

```text
interactionType 统一判定
Blockhead action queue
path type + goal interaction
Tile contents/dataA/dataB
FreeBlock unique ID/subItems
DynamicObject 独立层
Workbench/Chest/Bed 等交互对象状态
craft progress 与到达工作台动作
可靠/不可靠世界变更通知
Blockhead 多需求驱动的 AI action
```

所以下一步不应继续扩充散落的 `if (foreground == N)`，而应先在现有 C++ 框架中实现最小的：

```text
InteractionType
BlockheadAction
TileState contents/dataA/dataB
WorldObject/FreeBlock
```

然后再接入挖掘、拾取、放置和制作。

## 证据限制

本文件中的“直接引用”是 A 级静态 IMP/selector 证据；“动作链”是由多个直接引用组成的结构性推断。以下仍未被本轮证明：

- 每个 selector 的所有运行时分支；
- 每个 ItemType 的精确数据布局；
- `objc_msgSend` receiver 在所有状态下的实际对象类型；
- 更新函数内每个调用的严格执行顺序；
- save/network side effect 的每个字段编码。

这些不能由函数名 alone 完成，需要继续做控制流切片、运行时 tracing 或原版受控行为/存档差分。
