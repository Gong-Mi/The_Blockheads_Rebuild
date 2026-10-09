# tileIsSemiTransparentSolidBlock 材质码全解码（冰/玻璃/黑玻璃/宝石块）

任务：解码 `tileIsSemiTransparentSolidBlock(Tile*)` 判定的全部 byte0 材质码，逐码定名 + 旁证。
二进制：`~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`
SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`（与项目钉定值一致，见 `so_sha256.txt`）。
只读作业；本目录 `~/blockheads-work/bh-work/bh-waterline/sub_glasscodes/` 为唯一写入点。

---

## 0. 结论速览（终表）

| byte0 码 | 名称（DWARF 枚举） | 中文 | 置信度 |
|---|---|---|---|
| **0x18** (24) | `TILE_GLASS` | 玻璃 | **决定性**（四层独立证据） |
| **0x3b** (59) | `TILE_BLACK_GLASS` | 黑玻璃 | **决定性**（四层独立证据） |
| **4** | `TILE_ICE` | 冰 | **决定性**（四层独立证据） |
| **0x47** (71) | `TILE_AMETHYST_BLOCK` | 紫水晶块 | **决定性** |
| **0x48** (72) | `TILE_SAPPHIRE_BLOCK` | 蓝宝石块 | **决定性** |
| **0x49** (73) | `TILE_EMERALD_BLOCK` | 绿宝石块 | **决定性** |
| **0x4a** (74) | `TILE_RUBY_BLOCK` | 红宝石块 | **决定性** |
| **0x4b** (75) | `TILE_DIAMOND_BLOCK` | 钻石块 | **决定性** |

即：**判定 = {玻璃, 黑玻璃, 冰} ∪ {五种宝石块}**。0x18/0x3b 均为玻璃族（不是"窗"；窗是动态物体码 31=0x1f，见 §5）。

---

## 1. 函数全文（0x00a128b0，172 字节，到下一函数 0xa1295c 为止）

伪代码（由下面逐指令译出，分支结构 = 短路 or 链）：

```c
BOOL tileIsSemiTransparentSolidBlock(Tile* t) {
    if (t == NULL) return false;
    uint8_t b0 = t[0];
    if (b0 == 0x18) return true;          // TILE_GLASS
    if (b0 == 0x3b) return true;          // TILE_BLACK_GLASS
    if (b0 == 4)    return true;          // TILE_ICE
    return tileTypeIsGemBlock(b0);        // 0x47..0x4b
}
```

**重要更正**：初读"尾部还有更多比较"不成立 —— 172 字节恰好覆盖全函数，第 4 个比较（`cmp r1, 4` @0xa12914）之后即 **`bl tileTypeIsGemBlock`**（@0xa12928），没有任何遗漏的字面量比较。"尾部若干码"就是 gem 调用，其本体在 0xa1229c。

逐指令（r2 配方，完整件见 `disasm_tileIsSemiTransparentSolidBlock_full.txt`）：

```
0x00a128b0  push {fp, lr};  mov fp, sp;  sub sp, sp, 0x10
0x00a128bc  movw r1, 0;  movw r2, 0
0x00a128c4  str r0, [fp, -4]                ; Tile* arg
0x00a128c8  ldr r0, [fp, -4];  cmp r0, r2
0x00a128d0  str r1, [sp, 8]                 ; 结果槽默认 0
0x00a128d4  beq 0xa12948                    ; tile == NULL → false
0x00a128d8  movw r0, 1
0x00a128dc  ldr r1, [fp, -4];  ldrb r1, [r1]        ; byte0
0x00a128e4  cmp r1, 0x18                    ; 玻璃
0x00a128ec  beq 0xa12940
0x00a128f0  movw r0, 1
0x00a128f4  ldr r1, [fp, -4];  ldrb r1, [r1]
0x00a128fc  cmp r1, 0x3b                    ; 黑玻璃
0x00a12904  beq 0xa12940
0x00a12908  movw r0, 1
0x00a1290c  ldr r1, [fp, -4];  ldrb r1, [r1]
0x00a12914  cmp r1, 4                       ; 冰
0x00a1291c  beq 0xa12940
0x00a12920  ldr r0, [fp, -4];  ldrb r0, [r0]
0x00a12928  bl tileTypeIsGemBlock(TileType) ; ← 尾部分支本体
0x00a1292c  sxtb r0, r0;  cmp r0, 0
0x00a12934  movw r0, 0;  movne r0, 1
0x00a1293c  str r0, [sp, 4]
0x00a12940  ldr r0, [sp, 4];  str r0, [sp, 8]
0x00a12948  ldr r0, [sp, 8];  and r0, r0, 1;  sxtb r0, r0
0x00a12954  mov sp, fp;  pop {fp, pc}
```

`tileTypeIsGemBlock`（0xa1229c，100B，件 `disasm_tileTypeIsGemBlock.txt`）：true 当码 ∈ {**0x47, 0x48, 0x49, 0x4a, 0x4b**}（依次 cmp @0xa122a8/b4/c0/cc/d8）。

---

## 2. 证据层 A：DWARF 枚举名（server_types.json）

`pr-methods/save/reconstruction/reverse-v3/native/server_types.json` 的 `TileType`（78 值，来自 Linux x86-64 原版服务器 DWARF）：
`TILE_ICE=4`、`TILE_GLASS=24(0x18)`、`TILE_BLACK_GLASS=59(0x3b)`、`TILE_AMETHYST_BLOCK=71`、`TILE_SAPPHIRE_BLOCK=72`、`TILE_EMERALD_BLOCK=73`、`TILE_RUBY_BLOCK=74`、`TILE_DIAMOND_BLOCK=75`。
同表：`TILE_AIR=2`、`TILE_WATER=3`、`TILE_SNOW=5`、`TILE_ROCK=1`。

宝石顺序 anchor：同枚举的传送门基座石族按 `AMETHYST(33) → SAPPHIRE(34) → EMERALD(35) → RUBY(36) → DIAMOND(37)` 排列（initial/placed/trade 三族同序），与游戏内升级序一致，故 71-75 按同名顺序对应。

## 3. 证据层 B：客户端 ↔ 枚举数值空间对齐（四组独立交叉验证）

| 客户端实测（本目录反汇编件） | 枚举名 | 吻合 |
|---|---|---|
| `tileIsAir(Tile*)`: byte0==2（`disasm_tileIsAir.txt`） | TILE_AIR=2 | ✓ |
| `tileIsWater(Tile*)`: byte0==3（`disasm_tileIsWater.txt`） | TILE_WATER=3 | ✓ |
| `tileTypeIsPortalBaseStone`: {0x19,0x21-0x25,0x2A-0x2F,0x3C-0x41}（reverse-v1 `tiletype-evidence.md`） | 25=INITIAL; 33-37=INITIAL_VARIANTS; 42-47=PLACED; 60-65=TRADE —— 全部是"传送门基座石" | ✓ 逐值命中 |
| `tileTypeIsRock`: {0x01,0x0A-0x14,0x1A,0x1D,0x1E,0x33-0x39,0x43-0x45,0x4C,0x4D} | 1=ROCK；10-20=石料家族；26=GOLD_BLOCK；29/30=LAPIS 系；51-57=BASALT..STEEL；67-69=PLATINUM/TITANIUM/CARBON_FIBER；76/77=PLASTER 系 | ✓ 全部石/金属 |
| 物体空间：`-[TulipPlant objectType]`=0x3b、网络链 0x18/0x1b/0xb/0xe/0x2e 专项 | DynamicObjectType: TULIP_PLANT=59, BLOCKHEAD=24, CARROT_PLANT=27, SUNFLOWER=11, FREE_BLOCK=14, CHEST=46 | ✓ 全部命中 |

## 4. 证据层 C：tile→Item 映射（`original_tile_item_map.tsv`，客户端 `itemTypeFromTileIsForegorund` @0xa18044 提取）

| tile | ItemType | 枚举名 | 对应上一行邻居（同表连续性） |
|---|---|---|---|
| 4 | 1060 | **ITEM_ICE** | 1039-1041=FLAX_MAT 系（tile 21-23）→ 1042=GLASS(tile 24) |
| 24 | 1042 | **ITEM_GLASS** | ↑ |
| 59 | 1076 | **ITEM_BLACK_GLASS** | 1075=ITEM_BLACK_SAND(tile 58) |
| 71 | 1098 | **ITEM_AMETHYST_BLOCK** | 1099-1102 连号五连 |
| 72 | 1099 | **ITEM_SAPPHIRE_BLOCK** | |
| 73 | 1100 | **ITEM_EMERALD_BLOCK** | |
| 74 | 1101 | **ITEM_RUBY_BLOCK** | |
| 75 | 1102 | **ITEM_DIAMOND_BLOCK** | |

（邻居映射与 tile 序列一致，逐一核实过：tile21/22/23→1039-1041 FLAX_MAT 三色、tile24→1042 GLASS、tile58→1075 BLACK_SAND、tile59→1076 BLACK_GLASS、tile76→1103 PLASTER。）

## 5. 证据层 D：每码的其它使用场景（旁证）

### 全二进制调用面（BL 编码线性扫描，覆盖全 .text 0x1bf44d0 字节）
`tileIsSemiTransparentSolidBlock` 全部调用点 **14 个，全部在两个光照引擎内**：
- 阳光引擎 `+[WorldHelper recursivelyUpdateSunLightWithList:...]` @0xa19c0c：0xa1a520 / 0xa1a664 / 0xa1a784 / 0xa1a8a4 / 0xa1a9c8 / 0xa1aaf4（×6）
- 人造光引擎 `-[ArtificialLight recursivelyUpdateLightWithList:]` @0xa8f22c：0xa8f864 / 0xa8fbe0 / 0xa8ff80 / 0xa903e4 / 0xa9084c / 0xa90bf8 / 0xa90fa4 / 0xa91350（×8）

衰减上下文（阳光引擎 0xa1a4e4-0xa1a554，原件 `disasm_worldhelper_recursiveupdatesunlight.txt`）：
```
base=2；邻居 tile[7]<=0xef → base=8
if (tile[0]==3 || tileIsSemiTransparentSolidBlock(tn)) base=0x10   ← 半透明固体与水同档，光透过衰减16
else if (!tileIsAirOrSnow(tn)) base=0x41（不透明固体，衰减65）
```
→ 语义即函数名：**固体、非全透明，光可透但有衰减**。人造光引擎同款（0xa8f850-0xa8f884，`disasm_artificiallight_recursiveupdate.txt`）。

### 0x18 = GLASS
- 光引擎（上，衰减档 0x10）
- `tileIsPaintable`（`disasm_tileIsPaintable_full.txt`）字节0 链 @0xa11a08、字节1（背墙）链终审 @0xa11e44 → **玻璃可上漆**（与黑玻璃、石料装饰块同族；**4=冰不在可上漆集**）
- `itemIndexWithGoodInteractionTypeForTile` @0xc67bb0：flag = `tileIsRock(tile) || tile[0]∈{0x18,0x3b,4}`（玻璃/黑玻璃/冰与岩石族并列进入"选合适工具"判定）
- `Blockhead -[updateGatherSpeedAndAnimationForCurrentInterationAndItem]` @0xbaf2dc：交互目标为 {0x18,0x3b,4} → 走常量 4 / 4.0f 路径
- tile→item：24→ITEM_GLASS

### 0x3b = BLACK_GLASS
- 与 0x18 完全同组：光衰减、paintable（@0xa11a18 fg、@0xa11e54 bg 是 true 返回前最后两比之一）、itemIndex（@0xc67bc8/0xc67c4c 内联两处）、gatherSpeed（@0xbaf304）
- `World -[fillTile:...]` @0x57e968：case 臂把 0x3b 写入 tile 型局部（与 0x15/0x16/0x17/0x18/0x33 等臂并列；分派器未钉，见 §7 边界）
- tile→item：59→ITEM_BLACK_GLASS

### 4 = ICE
- 光引擎（衰减档 0x10）
- 雪/冰线（SNOWLINE.md E118 + sl_09）：`-[SnowSurfaceBlock update:...]` @0xd8ea18 `tile[0]==4` 且 @0xd8ea24 `tile[9]>0` → 融冰章；同函数另有两处 @0xd8f56c / @0xd8f624；`updateSnowContent:` @0xd90ec4、`removeAllSnow` @0xd912a0、`worldChanged:` @0xd91788、`updateInTimeSinceSaved` @0xd8dc7c —— 冰在雪面机器的全套检查（雪不积于冰面等）
- `KelpPlant -[update:...]` ×4（0x8174d8 / 0x817538 / 0x81765c / 0x8176fc）—— 海带与冰的共现检查（冰封水面语境）
- `fillTile:` 内 `tile[0]==4` 检查 ×3（0x57ff28 / 0x580598 / 0x580a10）
- itemIndex / gatherSpeed 同 {0x18,0x3b,4} 组
- **不在** tileIsPaintable 集合（≠玻璃族的可上漆性）
- tile→item：4→ITEM_ICE

### 0x47-0x4b = 五种宝石块
- `tileRequiresGlowBlock` @0xa1486c（`disasm_tileRequiresGlowBlock.txt`）：`{TILE_TIME_CRYSTAL=0x10, GOLD_BLOCK=0x1a, LUMINOUS_PLASTER=0x4d} ∪ tileTypeIsGemBlock` → **宝石块需要发光块**（发光/反光类方块），与时间水晶、金块同列
- `tileTypeIsRock` @0xa134b8：宝石块算岩石族（cave 里嵌在岩石）
- `tileIsPaintable` @0xa11960（字节0 链）/ @0xa11bfc（字节1 链）：**可上漆**
- 世界生成：`WorldTileLoader -[placeGemsInCaveForPhysicalBlock:...]`（E95 邻域，含 tile[0]=0x10 时间水晶写入 + tile[3] {0x5e,0x90,0x91} 财宝标记；宝石码经局部变量写入未字面直出）
- 未定位第 6 调用点 0xbd0084（`Blockhead update:` 巨桶内，tile[0]→gem 判定；函数体未定位）
- tile→item：71-75→五连 ITEM_*_BLOCK

## 6. 码空间陷阱（下次 grep 防误报）

同一数值在不同字节空间含义完全不同，**只有 `ldrb rX,[tile]`（偏移0）的 cmp 才是材质码**：
- **物体空间**：0x18=Blockhead、0x3b=TulipPlant（`sendNetDataIfNeeded...` 的 cmp 链 0x18/0x1b/0x3b/0xb 全是 DynamicObjectType）
- **tile[0xb]（内容/火把族）**：{0x33,0x35,0x37,0x39,0x3b}——光源引擎的 0x3c→0x3b 重写、drawboxes 的 0x33..0x3b 链都是这个空间（E72 torch 系）
- **tile[3]（contents）**：CoffeeTree 状态码 {0x18,0x19,0x1a,0x29,0x2a}、财宝/巨魔标记 {0x5e,0x90,0x91}
- **ItemType**：1000+ 段（1042=GLASS 等）
- **窗**：`DYNAMIC_OBJECT_TYPE_WINDOW=31(0x1f)`，动态物体；与 0x18/0x3b 无关。"玻璃窗"是 Window 物体，不是这两个 tile 码。

## 7. 边界（诚实）

- 纯静态 + 钉定 ELF；无运行期测量。
- 调用面扫描按 ARM 态 BL/BLX 立即数全量解码；未假设存在 thumb 体。
- `fillTile:`（0x57c11c-0x580be0）内 {0x18,0x3b,4} 的 case 臂（写入 tile 型局部）分派器未展开钉死——记录为观测量。
- 0xbd0084 的 gem 调用点未定位到具体函数体（落在 `Blockhead update:` 大桶 0xbb9238-0xbe5854 内）。
- 环境（对父任务）：`WATERLINE.md` 记录的 fillTile 常量 0x422/0x423 经枚举核查 = `ITEM_FREEZE_WATER(1058)`/`ITEM_MELT_WATER(1059)`（Item 空间），不是 tile 码；引用 E118 时注意该数是 Item 序号而非 tile 类型。

## 8. 本目录产物清单

| 文件 | 内容 |
|---|---|
| `disasm_tileIsSemiTransparentSolidBlock_full.txt` | 全函数逐指令（172B） |
| `disasm_tileTypeIsGemBlock.txt` | gem 判定本体（0xa1229c） |
| `disasm_tileIsAir.txt` / `disasm_tileIsWater.txt` / `disasm_tileIsSolid.txt` | 空间对齐锚点 |
| `disasm_tileIsPaintable_full.txt` / `_heads.txt` / `_gemctx_A/B.txt` | 可上漆集全量 + gem 调用上下文 |
| `disasm_itemIndexWithGoodInteractionTypeForTile_full.txt` / `_heads.txt` | 工具选择判定 + 内联 {0x18,0x3b,4} |
| `disasm_updateGatherSpeed_groupctx.txt` | {0x18,0x3b,4} → 4/4.0 常量路径 |
| `disasm_tileRequiresGlowBlock.txt` | 宝石块→发光块 |
| `disasm_tileTypeIsRock_gemctx.txt` | 宝石∈岩石族 |
| `disasm_tileIsUnplacedBlockMinableWithPickaxe.txt` | 镐类集合（不含玻璃/冰/宝石） |
| `disasm_bd0084_ctx.txt` | 未定位 gem 调用点 |
| `cmp_scan_4_raw.txt` / `cmp_scan_hex18_raw.txt` / `cmp_scan_hex3b_raw.txt` | 全语料 cmp 扫描原件 |
| `codes_mapping.json` | 机器可读映射+证据 |
| `so_sha256.txt` | 二进制哈希钉 |
