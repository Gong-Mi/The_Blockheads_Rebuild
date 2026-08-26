# Export-derived main-loop evidence

本文专门记录从原版 `libApplication.so` 的导出符号、Objective-C IMP 地址和 ARM 函数体 selector 引用得到的主循环证据。它比类名/字符串扫描更接近真实调用边界，但仍然是静态证据；没有把 selector 的存在直接等同于运行时执行顺序。

## 证据对象

```text
APK SHA-256: cae0371354dfda125793ba974c1f7a55b2161ed6d9c458f962da9eb468f8ec54
ELF: lib/armeabi-v7a/libApplication.so
ABI: ARMv7 / ELF32 ARM EABI5
```

方法地址来自 `libApplication_objc_methods.tsv`，函数边界使用 `.ARM.exidx`，selector/CFString 引用由 `extract_objc_references.py` 的 ARM PIC 解析器提取。

## Android/native 导出边界

原版 `libApplication.so` 的 JNI 导出入口包括：

```text
JNI_OnLoad
Java_com_apportable_activity_VerdeActivity_nativeOnCreate
Java_com_apportable_activity_VerdeActivity_nativeOnStart
Java_com_apportable_activity_VerdeActivity_nativeOnResume
Java_com_apportable_activity_VerdeActivity_nativeOnPause
Java_com_apportable_activity_VerdeActivity_nativeOnStop
Java_com_apportable_activity_VerdeActivity_nativeOnDestroy
Java_com_apportable_activity_VerdeActivity_nativeOnLowMemory
Java_com_apportable_activity_VerdeActivity_nativeOnConfigurationChanged
Java_com_apportable_activity_VerdeActivity_nativeOnNewIntent
Java_com_apportable_gl_GLSurfaceView_nativeInit
Java_com_apportable_gl_GLSurfaceView_nativeOnSurfaceChanged
Java_com_apportable_ui_Window_nativeTouchesBegin
Java_com_apportable_ui_Window_nativeTouchesMove
Java_com_apportable_ui_Window_nativeTouchesEnd
Java_com_apportable_ui_Window_nativeTouchesCancel
Java_com_apportable_ui_Window_nativeKeyDown
Java_com_apportable_ui_Window_nativeKeyUp
Java_com_apportable_ui_Window_nativeOnWindowFocusChanged
Java_com_apportable_VerdeActivity_nativeHandleUri
```

这条导出链证明 Android 层只是把 Activity、surface、focus、input 和 URI 事件转入 native runtime；游戏世界不在 Java Activity 中实现。

## 帧驱动器

Objective-C 方法：

```text
EvolutionViewController -drawFrame
IMP: 0x00781a44
```

同一 IMP 的静态 selector 引用包含：

```text
view
initOpenGL
preUpdate:
update:accurateDT:
render:
presentFramebuffer
removeFromSuperview
```

其中 `initOpenGL`、`preUpdate:`、`update:accurateDT:`、`render:` 和
`presentFramebuffer` 是直接从 `0x00781a44` 函数体解析出的引用；它们不是
仅由类名或全局字符串表猜出的候选名称。

```text
startAnimation
stopAnimation
setDisplayLink:
displayLink
updateFrameInterval
```

并且 native 字符/selector 引用包含：

```text
displayLinkWithTarget:selector:
setFrameInterval:
currentRunLoop
addToRunLoop:forMode:
removeFromRunLoop:forMode:
invalidate
```

因此可以确认：

```text
CADisplayLink / displayLink
  -> EvolutionViewController::drawFrame
  -> frame-level preUpdate/render/update entry points
```

这里的 `preUpdate`、`render`、`update` 是从同一 IMP 的引用解析得到的候选调用目标；要声明严格执行先后，仍需继续对 `0x00781a44` 的完整 ARM 控制流做 selector 装载点和 `objc_msgSend` 配对。

## 世界模拟入口

Objective-C 方法：

```text
World -startSimulatingIfNeeded
IMP: 0x00566e64

DynamicWorld -simulate:
IMP: 0x008c9740

DynamicWorld -update:accurateDT:
IMP: 0x008c9810

DynamicWorld -update:accurateDT:isSimulation:
IMP: 0x008cbf40
```

`World -startSimulatingIfNeeded` 的引用包含：

```text
loadAttemptsSinceSuccess
SKIPPING SIMULATION DUE TO FAILED LOAD ATTEMPTS
actionCount
hasActions
blockheads
worldName
```

这说明模拟启动有加载失败次数和世界状态门控，不是 Activity 一创建就无条件启动。

`DynamicWorld -simulate:` 的唯一关键调用引用是：

```text
update:accurateDT:isSimulation:
```

由此得到静态调用骨架：

```text
World::startSimulatingIfNeeded
  -> simulation gate (load attempts / actions / blockheads)
  -> DynamicWorld::simulate:dt
      -> DynamicWorld::update:accurateDT:isSimulation:
```

## 世界渲染准备入口

Objective-C 方法：

```text
World -preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:
IMP: 0x00583c50
```

该方法 `0x00583c50` 的直接 selector 引用包括：

```text
loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:
update:rainFraction:snowFraction:
loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:
reasignDrawBlock:toXPos:yPos:world:
reloadDynamicObjectStaticGemometryForMacroTile:
reloadDynamicObjectStaticCylindersForMacroTile:
reloadDynamicObjectQuadsForMacroTile:
reloadDodoEggQuadsForMacroTile:
reloadDynamicObjectItemQuadsForMacroTile:
reloadLightGlowQuadsForMacroTile:
getWeatherFractionForPos:
getTreeLifeFractionForPos:
energy
death
pauseUI
waitingForBlocksCount
```

这些不是全局字符串命中，而是从该 IMP 的 ARM PIC selector 引用中解析出的
方法/字段访问证据。渲染前准备并不只是“把 Tile 数组交给 VBO”，而是会按 camera/macro tile 加载或重建：

```text
physical blocks
light glow quads
dynamic object geometry
dynamic object item quads
dodo egg quads
weather/tree state
```

当前重建项目把多个对象压进简化 chunk mesh 时，与这里存在结构性差距。

## 加载入口与模拟启动的关系

`World -incrementalLoad`：

```text
IMP: 0x0055bac8
```

同一 IMP 的引用同时出现：

```text
initializeDatabases
loadGame
loadDefaultGame
WorldTileLoader initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase:
ClientTileLoader initWithWorld:client:saveID:randomSeed:cameraPos:
DynamicWorld initWithWorld:worldTileLoader:clientTileLoader:server:client:...
DatabaseConvertor initWithWorld:worldDatabase:dynamicObjectDatabase:blockDatabase:lightBlockDatabase:serverDatabase:
loadDynamicObjects:repositionBlockheadLoadFailures:
fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:
refineTerrain
preLoad:
```

同时引用原始 renderer 资源和 shader：

```text
TileMap.png
TileDestruct.png
TileReflect.png
Items.png
ItemNormals.png
Block.vsh / Block.fsh
BlockTransparent.vsh / BlockTransparent.fsh
StaticDrawCubes
LightQuads.vsh / LightQuads.fsh
SkyBetter.vsh / SkyBetter.fsh
```

因此静态生命周期链可以收敛为：

```text
loadGame/loadDefaultGame
  -> incrementalLoad
      -> initializeDatabases
      -> WorldTileLoader / ClientTileLoader
      -> DynamicWorld
      -> DatabaseConvertor
      -> physical/dynamic/light data load
      -> renderer/shader/texture initialization
      -> startSimulatingIfNeeded
      -> displayLink drawFrame
```

其中 `startSimulatingIfNeeded` 与 `drawFrame` 的跨方法严格先后仍需继续做控制流或运行时验证；上图是由入口/引用集合形成的框架骨架，不是未经验证的时序断言。

## 持久化与帧/模拟分离

已经恢复的保存方法：

```text
World -saveAll                         0x00555a84
DynamicWorld -saveGameWithWorldData:   0x008b29bc
DynamicWorld -saveBlockheads            0x008b6f0c
DynamicWorld -saveBlockheadInventory:   0x008b8634
World -savePhysicalBlockForMacroTile:   0x005b3644
WorldTileLoader -savePhysicalBlock:     0x00859a84
```

这些方法分别写入：

```text
world metadata
blockhead collection
per-blockhead inventory
dynamic objects
physical blocks
light blocks
network peer updates
```

结合 `drawFrame` 和 `DynamicWorld::simulate/update` 的独立 IMP，可以确认重建不能把“每帧绘制”“世界模拟”“保存提交”写成一个无边界的函数。至少需要保留：

```text
frame driver
simulation update
world/chunk loading
persistence commit
network replication
```

## 导出证据限制

本轮导出/IMP 逆向已经超过类名推断，但仍有以下限制：

1. `objc_msgSend` 的目标由 selector 和 receiver 在运行时决定，静态引用只能先确定候选边界。
2. `drawFrame` 的完整执行顺序还需要按 ARM 控制流配对 selector 装载点和发送点。
3. `DynamicWorld::update` 的具体更新子系统仍需继续从其 IMP 反汇编中恢复。
4. 所有内容行为（挖掘、放置、掉落、合成、AI 决策）还不能只由模块入口命名推出。
5. 当前文件记录的是 original export/IMP evidence，不是 replacement runtime acceptance。

## 下一步

下一轮直接针对 `DynamicWorld -update:accurateDT:isSimulation:` 和 `EvolutionViewController -drawFrame` 做：

```text
ARM 控制流切块
→ selector 装载点
→ objc_msgSend receiver/argument
→ 子系统调用顺序
→ 更新字段/状态
→ 保存或网络副作用
```

优先恢复的内容路径：

```text
Blockhead action
→ tile interaction
→ item/drop/inventory
→ dynamic object or recipe
→ dirty block/network/save
```
