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

## P1 first evidence slice

在 `reverse-v3` 当前 head 上，使用 hash 已锁定的原版 `libApplication.so` 重新生成了两个目标 IMP 的有界反汇编和 selector 引用：

```text
EvolutionViewController -drawFrame
  IMP: 0x00781a44
  ARM.exidx end: 0x00781eb0
  disasm: native/disasm_draw_frame.txt
  refs:   native/refs_draw_frame.tsv
  selector refs: 10

DynamicWorld -update:accurateDT:isSimulation:
  IMP: 0x008cbf40
  ARM.exidx boundary: retained in disasm header
  disasm: native/disasm_dynamic_world_update.txt
  refs:   native/refs_dynamic_world_update.tsv
  selector refs: 39
```

`drawFrame` 的引用集合包含 `initOpenGL`、`preUpdate:`、`update:accurateDT:`、`render:`、`presentFramebuffer`；`DynamicWorld::update` 的集合包含动态对象增删、Blockhead inventory save、`updateNetObjects`、雨/世界内容变化和对象数据发送等候选边界。

这一步只完成“有界机器码 + 引用证据”收集，**没有把引用文件的排序当作执行顺序**。下一步仍需从反汇编的基本块中配对 selector 装载、receiver、参数和 `objc_msgSend`/间接调用，再记录条件边和副作用。

已增加保守的 ARM 间接调用索引：

```text
native/indirect_calls_draw_frame.tsv
  11 个 blx 点，selector_pair/receiver_pair/argument_pair 全部 unknown
native/indirect_calls_dynamic_world_update.tsv
  71 个 blx 点，selector_pair/receiver_pair/argument_pair 全部 unknown
```

该索引只回答“哪里发生了寄存器间接调用”，不回答“调用了哪个 Objective-C selector”。只有后续寄存器数据流能证明 selector、receiver 和参数关系时，才允许将 unknown 改为 confirmed。

dispatch 审计修正（旧版本的全 unknown 不是二进制限制）：

- 旧工具错误地从 `blx` 目标寄存器寻找 selector，且未使用 ESIL/CFG。
- 当前工具独立追踪目标和 r1：ARM32 的目标是函数地址，r1 才是 selector。
- 使用 ELF32 PT_LOAD 做 VA→文件偏移转换；GLOB_DAT/JUMP_SLOT 提供导入符号，RELATIVE 保留模块相对地址。输入由原版 ELF SHA-256 门禁固定。
- 使用直接 ARM 分支建立有界工作列表传播；汇合只保留相同事实。调用破坏 caller-saved 寄存器，不支持的指令保守失效。支持受限 fp/sp 保存恢复，不是通用 ARM 模拟器或完整 alias 分析。
- 静态候选仍不是动态验收：不解析 receiver/额外参数，不声称完整调用顺序。

原版 `drawFrame` 实跑：11 个寄存器 blx，2 个 selector candidates：

| call | target | selector |
|---|---|---|
| 0x00781b28 | objc_msgSend | removeFromSuperview |
| 0x00781b4c | objc_msgSend | release |

第一处的 PIC base=0x0105faf4、selref=0x00e81054、selector string VA=0x00ee9ab2；目标 GOT=0x0105b7a0 的重定位是 objc_msgSend。无需运行时 GOT 实值即可恢复这条静态链。其余 9 处保持 unknown，不代表不可恢复。

TSV 的 `selector_address` 现在是 r1 中的 selector 字符串模块 VA；新增 `target_symbol`，移除无法可靠归属的 `selector_load_address`。旧 indirect-call TSV 保持纯调用点索引，不与候选追踪表混用。

测试分层：CI 必跑不依赖 ELF/r2 的 `DispatchDataflowTest`，覆盖 r1/目标分离、覆盖写、调用 clobber、分支汇合、回边、PIC、别名、写回和栈恢复。`OriginalELFTest` 是单独原版验收，不再用空测试或全部 unknown 断言代替能力测试。

本地复现（依赖 radare2、pyelftools）：

```sh
export PYTHONDONTWRITEBYTECODE=1
export BLOCKHEADS_ELF="$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
python3 tools/test_trace_objc_dispatch.py
python3 tools/trace_objc_dispatch.py "$BLOCKHEADS_ELF" --imp 0x00781a44 --output "$TMPDIR/blockheads-dispatch.tsv"
```

r2 会报告原库没有 ELF entrypoint 并选择默认地址；分析命令通过 `af/pdfj @ 0x00781a44` 显式选定 IMP，不依赖该默认入口。诊断不再被吞掉。

## 下一步

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
