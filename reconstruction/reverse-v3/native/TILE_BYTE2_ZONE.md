# Tile byte2（偏移 +2）语义定案 —— zoneTypeIndex（地形分带标记）

对象：The Blockheads 1.7.6 armeabi-v7a `libApplication.so`
（sha256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`）
本文件只落 sub_byte2/ 工作目录；未改 git 树。

## 结论（一句话）

**byte2 = `zoneTypeIndex`（服务端 DWARF 原名）= 瓦片在“世界生成/瓦片构造”时被写入的地形分带标签：
1 = 地下带（该列生成岩线以下：岩石/矿石/岩浆/洞穴空气/地下水/生成标记），
2 = 地表带（岩线以上：泥土/沙/草 + 地表之上的空气与天空，以及全瓦片清零时的默认值），
3 = 生成期开阔水体（海洋/湖泊的水瓦片）。
它是“出身标签”，不是每帧状态位：挖开/灌水/排水都不会改写它（见下“无改写者”一节）。
确定性最高的读取方是两个递归流函数，二者都**只接受 zone==1** —— 这正是
`(byte0==2 && byte2==1)` 会被改写成满水的全部原因：byte0==2 是“空气”，byte2==1 是“地下带”，
而 `recursivelyFlowOutWaterFromTile:atPos:` 就是地下带洞穴灌水的洪泛递归。**

置信度：名称/角色 **高**（DWARF 原名 + 生成器写入点 + 存档实测 + 谓词反汇编四路互证）；
1/2/3 三档的分档判据（“岩线”一说）**中高**（实测边界与岩线一致，但没有一条已恢复的代码把
“岩线→zone”的赋值链完整连起来：生成器按列循环写 1、按湖线写 3 的循环体是 census 级）。

## 直接回答任务问题：为什么 (byte0==2 && byte2==1) 会变成满水

1. `byte0==2` = **空气**。由 ELF 内符号 `_Z9tileIsAirP4Tile`（0x00a12300）反汇编钉死：
   `ldrb r0,[r0]; cmp r0,2; moveq r0,1`。同理 `_Z11tileIsWaterP4Tile`（0x00a11690）→ `byte0==3`。
   （注：仓库旧文档 WATERLINE.md 把 2/3 记成 “still water/flowing water”，**是标错的**；
   服务器 1.7.1 DWARF 枚举 TileType：1=ROCK, 2=AIR, 3=WATER 与存档、谓词三方一致。）
2. `byte2==1` = zone 1 = 地下带。空气瓦片能带 zone 1，是因为生成器先全块 `byte2=2` 清零，
   再按列把“岩线以下”的行改写为 1——被挖空的洞穴空气（byte0=2）保持 1。
3. `recursivelyFlowOutWaterFromTile:atPos:`（0x0085c214）是**地下洞穴灌水**的深度优先洪泛：
   对 (x,y-1)、(x+1,y)、(x-1,y) 三个邻居，若 `byte0==2 && byte2==1` 就就地改写
   `byte0=3(水)、byte4=0xff(满)、byte7=0(阳光=0)`，然后经同一个选择器递归（GOT 槽 0x0085c500
   → `recursivelyFlowOutWaterFromTile:atPos:`，见 specs_waterline.json）。整片连通的 zone-1 空气
   全部变成满水。zone 门 = 限制域：地表带(2)空气和开阔水(3)瓦片永远不会被这条递归接受。

## 写入者清单（client 1.7.6，全部静态确认值）

Tile（64B 记录，`PhysicalBlock+8` 起，索引×64）：

| 方法 | 指令地址 | 值 | 语境 |
|---|---|---|---|
| WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:] (0x85e6b0) | 0x860a94 | **2** | §全瓦片清零循环（0x860910-0x860b68，BLOCK_LOAD.md §4）：每块默认 `byte2=2`、byte10=0x7f、byte4=0xff |
| 同上 | 0x86235c | **1** | 生成通道共享尾巴（配 byte1=1）；岩浆/矿石/石柱等 case 跳入（如 0x860eb4 的 0x1f 岩浆 case） |
| 同上 | 0x8624b4 | **1** | 同上类 case |
| 同上 | 0x8625a8 / 0x862654 / 0x862700 / 0x8627c0 | **1** | 世界四分之一列网格标记（`colX == (W*32)/4 × {1,2,3}`、`colX==0`），配 byte1=0x26..0x29（N/S/W/E pole id） |
| 同上 | 0x862c80 | **1** | 深部矿石分支（byte3=0x5e 一带） |
| 同上 | 0x862e5c | **3** | §最终循环：湖线以下的水行 `byte0=3/byte2=3/byte4=0xff`（BLOCK_LOAD.md §6） |
| 同上 | 0x862fd8 / 0x863164 / 0x8632dc / 0x863484 | **1** | 四分之一列标记在深度窗口下的重复写入 |
| WorldTileLoader -[updatePhysicalBlockToLatestVersion:] (0x8650b0) | 0x8655a0 | **1** | 存档迁移：燧石带修补，就地重写 tile（配 byte1=1、byte0=2），随后生成宝箱/巨魔（BLOCK_MIGRATION.md） |
| World -[saveAll] (saveAll 体内联) | 0x562038 | **1** | 创建初始传送门基石瓦片：`byte0=0x19(25=INITIAL_PORTAL_BASE_STONE)/byte3=0/byte2=1` |
| DynamicWorld -[loadDynamicObjectsForMacroTile:includeSurfaceBlocks:] | 0x8beb64 | **1** | 同一“传送门基石”惯用法（tileAtWorldPositionLoaded 返回的指针） |

非 Tile 的 byte2 写入（已排除，避免误报）：

| 方法 | 地址 | 目标结构 |
|---|---|---|
| DynamicWorld -[loadGlowBlockIfNeededAtPos:tile:] 同文件 | 0x8bfb48/0x8bfba0/0x8c1da4/0x8c1dec（strh） | 带 float@0x18 的其它对象，不是 Tile |
| DynamicWorld -[loadTreeAtPosition:...] | 0x8e4e88 等（strh×16） | 2×halfword 小结构 |
| World -[loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:...] | 0x5b3ed0 | **MacroTile** 结构（CCC^{PhysicalBlock}… 的第 3 字节，非 Tile） |
| DynamicWorld -[removeDynamicObjectsForMacroTile:] | 0x8b6840 | MacroTile 类记录（配 word@0xc 写） |
| World -[savePhysicalBlockForMacroTile:...] 相关加载器段 | 0x85f004（在 tile_storage 文件内） | 同为 MacroTile 头字节（+4 存 PhysicalBlock*） |
| ArtificialLight/TulipPlant/FreeBlock/electricity/Blockhead drawBoxes 等 | 0xa925f8 / 0x9a0280 / 0x632268 / 0x5ca5a8 / 0xc836c0 / 0xd867dc | 各自类的小结构，非 Tile |

**没有发现把 Tile byte2 清成 0 的指令**；没有 0/其它常量写入者。实际值域只有 {1,2,3}。

## 读取者清单（corpus 全量扫描，26 个文件有 +2 访问，过滤后）

| 方法 | 地址 | 语义 |
|---|---|---|
| WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:] | 0x85c2b4/0x85c3a0/0x85c48c（`ldrb; cmp 1`） | **水洪泛门：只灌 `byte0==2 && byte2==1` 的瓦片** |
| WorldTileLoader -[recursivelyFlowOutDirtFromTile:atPos:] | 0x85c5e4/0x85c7c0/0x85c9bc/0x85cb6c/0x85cd68（×5，同一门） | **土重分布门：邻居 `byte0∈{2,3} && byte2==1` → fillDirtTile:（worldDirtHeight=99999999, parentType=parent->byte0）并递归** |
| DynamicWorld -[loadGlowBlockIfNeededAtPos:tile:] | 0x8f5088（`ldrsb … ; ==0`） | 存疑：指针对 +4 读 int，疑非 Tile（未定） |
| World -[decommisionBlock:blockToSavePhyscialBlock:] | 0x5b3d38（`ldrsb …; ==0`） | 存疑：同上（未定） |
| Weather -[cloudColorForWeatherFraction:...] / World -[dayColorForPosition:] / World -[preRenderUpdate:...] | 0x7eb95c / 0x583830 / 0x58719c | 假阳性：`base + i*4 + 2` 的 4 字节步长数组，非 Tile |
| DynamicWorld -[loadTreeAtPosition:...] | 0x8e562c 等 | 假阳性：lodrh/strh，非 Tile |

## 存档实测证据（独立于反汇编）

`server-world-archive`（40 个 64KB 块，40960 tiles）：
- raw[2] 值域 = {1: 34116, 2: 5972, 3: 872}，**0 次 0**。
- 交叉表：type=1(ROCK)/31(LAVA)/12/14/16/17/19/25 → zone 1；type=6(DIRT)/7/8/27(GRASS)/58 → zone 2；
  type=3(WATER) → zone 1（地下）或 3（海洋）；type=2(AIR) → 天空/地表=2、洞穴=1。
- 空间结构（按列分析，见 analyze_byte2_columns.py）：每列 1→2 边界 = 该列岩线（岩石/土 interface，
  在海区等于“生成海床”）；2→3 边界 = 水体；被灌过水的岩层空腔（如 19_14 的 132 格）保持 zone 1，
  说明灌水不改写 zone。四分之一列标记（0x26..0x29 写在 byte1）+ zone 1 与生成器代码一致。

## 与 SurfaceBlock / 其它水系统的关系

- SurfaceBlock -[takeAnyWaterFromTileAtPos:tile:] / -[subtractWater:fromOtherTile:atPos:] /
  -[removeIfFloatingAndEmptyOfWater]、World -[removeWaterTileAtPos:]、DynamicWorld -[waterChangedAtPos:fullBlock:]：
  **全部不读写 byte2**（扫描为 0 命中）。它们改写 byte0/byte4（byte4 = 水量 0..0xff），
  takeAnyWater 用 tileIsWater()（==3）判定后写 byte0=3。
- 结论：byte2 的门只出现在 WorldTileLoader 的两个地下水/土递归里；地表水体系的放置/流动与 byte2 无关。

## 触发链（谁调用了水洪泛）

- WorldTileLoader -[refineTerrain]（0x854c54，WORLDTILELOADER_REFINETERRAIN.md）：挖洞穴（punch）
  时若 `tile->byte0 != 0x1f` 就写 `byte0=3/byte4=0xff/byte7=0` 并调用
  `recursivelyFlowOutWaterFromTile:atPos:`（0x855058/0x855374/…四处同构），
  于是地下水把与该格连通的 zone-1 空气全部灌满。这就是存档里“地下带含水洞穴”的来源。
- 另有 saveAll / loadDynamicObjectsForMacroTile 的“传送门基石”瓦片生成（zone=1）走构造器路径。

## 边界与未决

- 服务端 DWARF 是 1.7.1 Linux；本批已用 client 1.7.6 的生成器写入点 + 谓词 + 存档值域三方交叉，
  偏移 0..0x16 与字段语义一致（byte0 type / +1 backwall / +2 zone / +3 contents / +4 水量 /
  +0xE..0x14 自发光与热 半字）。仍未在 client 侧找到显式写入“zone=1/2/3”的语义命名符号。
- 剩余 2 个 `ldrsb [x,2]; ==0` 读取点（loadGlowBlockIfNeededAtPos、decommisionBlock）未能确证是
  Tile 指针；若是 Tile，则说明这些路径期望 zone 可为 0（本批未观测到任何写 0 者）。
- refineTerrain 的 punch 在“土带”上的水不会横向扩散（门只放行 zone 1），符合“灌水=地下洪水填充”。

## 产物

- probe_byte2_save_archive.py / byte2_save_archive_probe.txt（值域与交叉表）
- map_byte2_blocks.py / byte2_blocks_inventory.txt / byte2_blocks_maps_selected.txt（空间图）
- analyze_byte2_columns.py / byte2_columns_selected.txt（按列边界分析）
- r2_tileIs_predicates.txt（tileIsWater/tileIsAir/tileIsAirOrSnow 反汇编）
- byte2_writers_readers.tsv（机器可读清单）
