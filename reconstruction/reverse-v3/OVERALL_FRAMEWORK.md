# The Blockheads 1.7.6 overall framework reverse map

本文是 `com.noodlecake.blockheads` 1.7.6 的整体静态框架地图，目标是先恢复模块边界和数据流，再决定重建代码如何落地。它不是对所有函数的语义命名，也不是运行时行为完成声明。

## 当前施工计划图（GameView 数值源码恢复检查点）

```text
原版证据：固定 ELF → update 全部2460字核对 → 80调用完整清单
                                      └→ 19处局部 selector 路由已审
源码恢复：scroll inertia → pinch return → pinch inertia → translation return/初段scale cap
          独立C++已测试      已测试          已测试          本轮新增并已测试
下一片段：0x926acc 起 zoom flags → 后续输入/平移分支 → 完整调用时序与receiver审核
行为接入：上述独立片段尚未接入游戏循环；不得按整个update已恢复计数
画面还原：完整Tile字段→draw pass→atlas→shader链仍为独立验收线
平台现代化：现有Android构建独立验证；不以CI绿代替设备/游戏验收
最终闭环：原版世界加载→移动/挖掘/获得物品/放置/合成→保存→重载（未完成）
```

本检查点记录源码和证据，不把方法索引数量、局部路由或测试数量换算成整款游戏完成率。
精确调用边界与复现命令见 `native/GAMEVIEW_UPDATE_BOUNDARY.md`。
远端构建结果在规范 PR #1 的 exact-head 评论中单独登记。

## 证据对象

```text
APK: /data/data/com.termux/files/home/blockheads-work/blockheads.apk
SHA-256: cae0371354dfda125793ba974c1f7a55b2161ed6d9c458f962da9eb468f8ec54
package: com.noodlecake.blockheads
versionName: 1.7.6
versionCode: 1564553369
native ABI: armeabi-v7a
minSdk: 12
targetSdk: 27
```

静态清单和 native 元数据：

```text
Objective-C classes: 645/646 entries depending on inventory view
Objective-C ivars:   3796
file-backed ObjC methods: 10478
C++/native symbol and function inventories: retained in native/
```

主程序不是 Java 游戏逻辑，而是：

```text
VerdeApplication
  -> VerdeActivity (singleTask, portrait, fullscreen)
  -> Apportable library/runtime loader
  -> ordered native libraries
  -> libApplication.so
  -> Objective-C++ game runtime
```

## 总体分层

```text
Android/Apportable platform
  ├─ VerdeApplication / VerdeActivity
  ├─ Lifecycle / BackgroundLibraryLoader
  ├─ GLSurfaceView / Window / raw input forwarding
  ├─ LibraryManager / path + environment
  └─ AudioManagerService / BillingService / external adapters

Compatibility/runtime libraries
  ├─ libv.so
  ├─ libBridgeKit.so
  ├─ libNoodleFoundation.so
  ├─ libNoodleCompatibility.so
  ├─ libFoundation.so / CoreFoundation / CoreGraphics / CoreText
  ├─ libgles_apportable.so / libGLESv2.so
  ├─ libOpenAL.so / audio compatibility libraries
  ├─ libCFNetwork.so / Security / SystemConfiguration
  └─ libcxx.so / libSystem.so / compression and utility libraries

Game application: libApplication.so
  ├─ World + DynamicWorld
  ├─ WorldTileLoader + ClientTileLoader
  ├─ Database + DatabaseEnvironment + DatabaseConvertor
  ├─ Blockhead + BlockheadAI + BlockheadUI
  ├─ NPC/animals/vehicles/dynamic objects
  ├─ renderer/shader/texture/light/weather/particles
  ├─ WorldUI + menu/inventory/crafting/trade UIs
  ├─ BHServer / BHClient / ServerClient
  └─ save/migration/network serialization
```

## 1. Android 与 Apportable 启动层

### 已确认

Manifest 直接声明：

```text
application: com.apportable.app.VerdeApplication
launcher:    com.apportable.activity.VerdeActivity
launchMode:  singleTask
orientation: portrait
hardwareAccelerated: false
OpenGL ES:   2.0 required
native list: android.app.libs, ending with Application
native name: android.app.lib_name = Application
```

启动链不是 Activity 创建后立即进入游戏：

```text
Application create
  -> Activity create/start
  -> ordered native library load
  -> library/runtime initialization
  -> window focus
  -> valid surface
  -> native start/create/resume
  -> menu/world state
```

`Lifecycle` 会区分：

```text
create/start/resume/pause/stop/destroy
foreground/background
surface valid/invalid
EGL context valid/invalid
low-memory/configuration
new intent / URI join
```

输入层保留 raw touch/key 信息，包括 pointer ID、phase、时间和 move/cancel 数组；仅做 tap/pan/scale 的替代桥接不能视为原版输入等价。

### URI/联网入口

Manifest 直接包含：

```text
theblockheads.net/join
http://theblockheads.net
http://blockheads.noodlecake.com
```

这些入口会转入 native `nativeHandleUri`，因此联机世界进入路径与普通冷启动不是同一条状态机。

## 2. 游戏主控与世界生命周期

### 核心类簇

```text
World
WorldHelper
DynamicWorld
WorldTileLoader
ClientTileLoader
WorldImageExporter
```

静态恢复出的主链：

```text
World::loadGame
  -> load legacy `world`
  -> load/migrate `worldv2`
  -> initializeDatabases
  -> incrementalLoad
      -> WorldTileLoader
      -> DynamicWorld
      -> DatabaseConvertor
      -> dynamic objects / blockheads / lights
  -> renderer resource creation
  -> frame update/draw

World::saveAll
  -> dynamic world metadata
  -> inventories
  -> blockheads
  -> dynamic objects
  -> dirty physical blocks
  -> light blocks
  -> database commit
```

### 世界不是一个文件

原始路径/记录证据：

```text
saves/<saveID>/world
saves/<saveID>/worldv2
saves/<saveID>/world_db/{main,blocks,dw}
saves/<saveID>/server_db/
saves/<saveID>/blocks/
saves/<saveID>/lightBlocks/
saves/<saveID>/players/
saves/<saveID>/allPlayers.plist
saves/<saveID>/recentPlayers.plist
saves/<saveID>/dynamicObjects
saves/<saveID>/worldPrices
```

`World`、`DynamicWorld`、`WorldTileLoader` 和 `DatabaseConvertor` 共同组成持久化系统。当前重建项目的 `world.bin` 只能作为开发格式，不能命名为原版兼容格式。

## 3. Tile/区块/数据库层

### 物理块

静态 Objective-C 类型编码恢复出：

```text
PhysicalBlock = ii^{Tile}cCdII[32*][32C]
Tile         = CCCCCCCCCCCCCSSSsCISSSSSQ[8S]
```

已由指令和方法边界确认：

```text
一个 PhysicalBlock = 32 × 32 = 1024 Tiles
每个 Tile = 64 bytes
基础 tile 数据 = 65536 bytes
额外字段 = 1 byte + 4 bytes
压缩前记录总长度 = 65541 bytes
```

物理块持久化大致是：

```text
Tile[1024]
  + PhysicalBlock offset 13 的 1 byte
  + PhysicalBlock offset 24 的 4 bytes
  -> gzipDeflate
  -> database key: <x>_<y>_compressedBlock
```

已有静态字段证据：

```text
Tile byte 0:  TileType/air/water/solid predicates
Tile byte 1:  back-wall type
Tile byte 3:  contents type/tree/glow predicates
Tile byte 7:  temperature scale
Tile bytes 20-21: signed temperature offset
```

其余 Tile 字段不能仅凭结构大小命名，必须继续通过调用者、保存变化和运行时行为确认。

### 区块加载层

```text
WorldTileLoader
  ├─ loadPhysicalBlock:atXPos:yPos:createIfNotCreated:
  ├─ savePhysicalBlock:macroTile:sendToClients:server:sendReliably:
  ├─ compressed block inflate/deflate
  └─ dirty block / client update selection

ClientTileLoader
  └─ loadPhysicalBlock:atPos:withTilesData:lightData:extraDataDict:
```

这说明本地世界和联机客户端共享物理块语义，但客户端加载路径还会接收 lightData 和 extraData，不是单纯读取本地 Tile 数组。

## 4. DynamicWorld 数据层

### 世界元数据

`dynamicWorldv2` 记录直接引用：

```text
dynamicObjectIDCount
activeBlockheadIndex
workbenchHasBeenCrafted
poleItemTakenTimes
saveVersion
savedGlowIndices
portalPositionIndexSet
signOwnershipData
```

### Blockhead/库存

Blockhead 数据和库存是分开的记录：

```text
blockheads
<saveID>_blockheads
local_blockheads
blockhead_<uniqueID>_inventory
<saveID>_blockhead_<uniqueID>_inventory
saveItemSlotsArray
```

保存链使用 property-list 派生数据和 gzip 压缩，并通过 database key 写入。库存不是简单嵌入世界 Tile 文件。

### 动态对象

元数据和字符串表中可见：

```text
dynamicObjects
uniqueID
Chest
Bed
Door
Ladder
ElevatorShaft
PortalChestManager
TradePortal
SteamTrain
TrainCar
Boat
Wire
ArtificialLight
```

因此动态对象必须独立于 Tile 层建模，至少包含：位置、尺寸/方向、唯一 ID、状态、库存、连接关系和保存记录。

## 5. Blockhead 与 AI 层

### 已确认的对象状态方向

`Blockhead` ivar 中出现：

```text
state
path
pathNeedsRecalculated
pathRecalculationIsFallPath
waitingForPath
waitingPathGoalPos
waitingForPathInteractionType
nextInteractionType
nextInteractionSquare
nextAnimationType
nextSubAnimationType
terrainDifficulty
traverseType
underwater
usingItem
selectedToolIndex
remoteInteractionItemType
saveItemSlotsArray
```

这表明原版 Blockhead 不是“玩家坐标 + 简单重力”，而是：

```text
需求/输入/交互目标
  -> 路径查找
  -> terrain difficulty / traverse type
  -> 交互等待状态
  -> 动画/动作状态
  -> Tile/动态对象交互
  -> inventory/network/save side effects
```

### 路径系统

类和函数证据包括：

```text
PathCreator
WirePathCreator
checkCanEnterTile
 dpadFindPath
 testTile
```

路径检查会接收 Tile、DerivedTileProperties、世界和动态对象等信息，并可区分水域允许与否；因此不能用只看四邻域实心性的寻路替代完整行为。

### 角色渲染组成

原版 Blockhead 由独立部位组成：

```text
BlockheadBody
BlockheadFace
BlockheadHair
BlockheadClothing
```

对应 shader 和资源也分开。当前重建只画简化 body 时，属于替代实现，不是角色系统已经恢复。

## 6. 动态对象、NPC、动物和交通工具

静态类簇至少包括：

```text
NPC
Dodo
Donkey
DonkeyLike
ClownFish
FishingRod
Shark
CaveTroll
DropBear
GrizRat
Scorpion
SteamTrain
TrainCar
TrainStation
Boat
JetPack
```

类存在只证明模块/资源/类型存在，不自动证明每个类已经在某一场景生成。完整行为还要绑定：

```text
spawn/deserialize
update
path/interaction
collision
render pass
save/network state
```

## 7. 渲染框架

### 渲染主链

```text
World preRenderUpdate
  -> camera bounds / time / weather / light state
  -> WorldHelper reloadDrawBlock
  -> physical block draw-slot preparation
  -> opaque block pass
  -> transparent/background/water passes
  -> free block/item pass
  -> static/dynamic objects
  -> Blockhead multi-part pass
  -> light glows / particles / weather
  -> UI composition
```

原版 metadata 和 selector 直接暴露：

```text
preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:
preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:
reloadDrawBlock:world:waterAnimationIndex:slowAnimationIndex:mapPixelData:skyPixelData:
drawOpaqueObjects:...
drawFreeBlocks:...
drawInFrontOfBlocks:...
renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:
renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:
renderAndUpdate:...windMovement:
```

### Pass 不能合并成一个 terrain VBO

静态 shader/selector 证据区分：

```text
Block / BlockTransparent
StaticDrawCubes
FreeBlock / Item
BlockheadBody / Face / Hair / Clothing
LightQuads
Cloud / CloudHD
ParticleEmitter / weather
```

透明方块、自然内容物、掉落物、动态对象、角色、光照和天气不是同一种 draw call。

## 8. UI 与交互层

主要 UI 类簇：

```text
MainMenuUI
CreateWorldUI
LoadWorldUI
WorldUI
BlockheadUI
InventoryButton
InventoryItem
InventoryFullUI
CraftUI
CraftProgressUI
ChestUI
HungerUI
SleepProgressUI
MapUI
PauseUI
CustomizeBlockheadUI
TradePortalUI
TradeMissionUI
JetPackUI
```

`WorldUI` 的静态字段显示它同时持有：

```text
world
server/client
currentBlockhead
selected inventory/blockhead
inventory buttons
chestUI
pause/multiplayer controls
camera/projection matrix
portal/trade controls
fast-forward/time-crystal controls
```

因此 UI 不是单独菜单皮肤，而是世界交互控制层；它会读写世界、Blockhead、客户端和容器状态。

## 9. 网络/联机层

类和字段证据：

```text
BHServer
BHClient
BHNetServerMatch
BHNetClientMatch
ServerClient
ClientTileLoader
```

`ServerClient` 字段直接显示联机同步对象：

```text
clientID
connected
paused
isAdmin
requestedBlockIndices
requestedBlockRequestTypes
updateArraysToSend
updateUnreliableArraysToSend
creationArraysToSend
creationDataUpdateArraysToSend
removalArraysToSend
wiredBlocks
wiredDynamicObjects
lightBlockDatabase
allLightBlockIndices
heartbeat state
```

可确认的联机分层：

```text
BHServer/BHClient
  -> ServerClient per peer
  -> reliable creation/removal/update arrays
  -> unreliable update arrays
  -> physical block/light block requests
  -> dynamic object/wire updates
  -> heartbeat/admin/pause state
```

当前重建项目没有这套协议；单机存档成功不能宣称联机框架完成。

## 10. 音频、平台服务和商业 SDK

APK 还包含：

```text
OpenAL / AudioFile / AudioToolbox / AudioUnit / CoreAudio
Google Play Games
BillingService / IAP
Flurry / AppLovin / Chartboost / Vungle / Facebook Ads / IronSource
NoodleNewsClient
```

这些属于平台服务和商业/联网外围，不应与核心世界模拟混进同一个重建模块。核心重建第一阶段可以用自有音频和本地设置替代，但必须把“核心游戏完成”和“平台服务兼容”分开报告。

## 重建时的对应关系

原版模块到当前重建框架的合理映射：

```text
原版 World/DynamicWorld       -> GameWorld + WorldState
原版 Tile/PhysicalBlock       -> TileLayer + PhysicalBlock
原版 WorldTileLoader          -> chunk loader / persistence boundary
原版 Database/Convertor       -> persistence backend + migration layer
原版 Blockhead                -> Player/Agent + Needs + Action state
原版 BlockheadAI/PathCreator  -> planner/path/interaction system
原版 DynamicObject             -> WorldObject layer
原版 Item/inventory records    -> ItemStack/Container/Recipe layer
原版 multi-pass renderer       -> render snapshot + pass-specific renderer
原版 WorldUI                   -> one coordinate-space UI/event layer
原版 ServerClient              -> future network replication layer
```

当前代码中最重要的结构性差距是：

```text
原版：Tile + DynamicObject + Blockhead + DB record 分层
当前：部分内容仍折叠进 Tile/foreground/world.bin
```

所以后续应先把数据边界恢复出来，再继续堆内容；否则同一个数字会同时承担 Tile、Item、atlas、掉落和渲染语义。

## 当前结论

### 已确认

- 原版是 Apportable 迁移的 ARMv7 Objective-C++ 游戏，不是普通 Java 游戏。
- 单一 `world.bin` 不是原版存档模型。
- 世界、物理块、光照、动态对象、Blockhead 集合、单个 Blockhead 库存和服务器状态是独立数据域。
- 原版存在多 pass GLES2 渲染和角色分部位渲染。
- 原版存在路径查找、动态对象交互和可靠/不可靠网络更新两套机制。
- UI 直接参与世界状态交互，不是与游戏逻辑分离的静态层。

### 尚未确认

- 全部 Tile 64 字节字段的语义名称。
- 所有数据库 key 的完整公式和版本分支。
- 所有动态对象的状态机和每个资源到实体的最终映射。
- 原版主循环的精确线程划分、dt 规则和更新顺序。
- 所有网络消息的字段编码和版本兼容策略。
- 完整原版运行时行为；静态类名和 selector 不能代替受控设备实验。

### 直接施工含义

后续不要先把 Terraria 的对象映射进来，也不要继续扩大手写 Item ID 表。应在同一重建主线中按以下最小顺序推进：

```text
原始整体框架图
  -> replacement WorldState 数据边界
  -> Blockhead Action/Needs 边界
  -> Tile/WorldObject/Container/ItemStack 边界
  -> 单机创建→挖掘→放置→合成→保存重载
  -> 再补角色、设施、动物、载具和联机
```

本文件只记录逆向结果；它不宣称上述后续功能已经实现。
