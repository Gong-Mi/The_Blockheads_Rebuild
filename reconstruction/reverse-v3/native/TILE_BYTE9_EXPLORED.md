# Tile byte9 定名报告：exploredFraction（探索度字节）

任务：确定 libApplication.so (1.7.6, armeabi-v7a) Tile 结构 offset +9 的字节角色。
结论：**byte9 = `exploredFraction`**（原始源码字段名，来自服务器调试符号；中文可译"探索度/探索光记忆"）。
不是"冰冻结前的水量记忆"，也不是损伤/年龄计数器。

## 1. 名称的一手来源（决定性）

- `pr-methods/save/reconstruction/reverse-v3/native/server_tile_dwarf.json`
  —— Linux 服务器 1.7.1 原版 ELF（sha256 `b1534f723ac524e1ed283e1cad01bb8cdfb6caf03c98642e25730266f0cfd5ea`）
  的 DWARF，DIE `0x41129`，`DW_TAG_structure_type` `Tile`，64 字节，26 成员。
  offset 9 = `exploredFraction`（uint8_t）。提取工具 `tools/recover_server_tile.py`（hash 门槛校验）。
- `server_types.json`：同一来源的汇总，conflicts=[]；同时给出 TileType 枚举
  `TILE_AIR=2, TILE_WATER=3, TILE_ICE=4, TILE_SNOW=5`。
- 完整成员（offset: 名）：
  0 typeIndex / 1 backWallTypeIndex / 2 zoneTypeIndex / 3 contents / 4 partialContentLeft /
  5 gatherProgress / 6 light / 7 sunLight / 8 seasonOffset / **9 exploredFraction** /
  10 terrainSlowFactor / 11 foregroundContents / 12 backgroundContents / 14..16 artificialLightR/G/B /
  18 artificialHeat / 22 onFire / 24 dynamicObjectOwnerOld / 28..38 paint* / 40 dynamicObjectOwner / 48 padding。

## 2. Android 1.7.6 消费者逐指令交叉验证（与上述名字全部自洽）

排除了大量同模式噪音（Charset/CloudInterface 区间 0x86da28、draw-block stride-12 区间
0xa1eca4..0xa2dbb0、BlockheadAI self+0x1dd ivar 写点 0x6d2d18 等，均非 Tile）后，Tile+9 的
全部指令级访问点如下（全库 245 条 `ldr[b]/strb [Rn,#9]` 编码扫描 + 文本 grep `, 9]` / `, 0x9]` 双向核对）：

| # | 地址 | 指令 | 函数 | 语义 |
|---|------|------|------|------|
| 1 | 0x00a1d27c | ldrb r0,[r0,9] | WorldHelper +[recalculateLightingForPhysicalBlockIfNeeded:...] | 读，选择写路径（tile[9]==0 ?）——disasm_worldhelper_recalculatelighting.txt:524 |
| 2 | 0x00a1d2a0 | strb r1,[r2,9] | 同上 | **写**：tile[9]=newLight（exploredFraction 单调取 max）—— 同文件:533 |
| 3 | 0x00a1d508 | ldrb r1,[r1,9] | 同上 | 读：newLight > tile[9] ?——同文件:687 |
| 4 | 0x00a1d520 | strb r1,[r2,9] | 同上 | **写**：tile[9]=newLight —— 同文件:693 |
| 5 | 0x00a19df0 | ldrb r0,[r0,9] | +[recursivelyUpdateSunLightWithList:...] | 读：==0 则跳过该 tile（阳光传播门）——disasm_worldhelper_recursiveupdatesunlight.txt:127 |
| 6 | 0x00d8ea24 | ldrb r0,[r0,9] | SnowSurfaceBlock -[update:accurateDT:isSimulation:] | 读：tile0==4(TILE_ICE) && byte9>0 才进入融冰/结冰章 ——disasm_worldtileloader_sl_09.txt:323 |
| 7 | 0x0094a284 | ldrb r1,[r1,9] | ClientTileLoader -[loadPhysicalBlock:atPos:withTilesData:lightData:extraDataDict:] | 读：tile[6](light)=max(lightData[i], tile[9]) ——disasm_tile_storage.txt:7695 |
| 8 | 0x0094c3bc | ldrb r1,[r1,9] | ClientTileLoader -[lightBlockDataRecievedFromServer:] | 读：同 7 的同一合流式（tile[6]=max(lightData,tile[9])）|
| 9 | 0x0086099c | strb r3,[r2,9] | WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:] | **写 0**：新 tile 初始化清零 ——disasm_tile_storage.txt:3693（同指令亦见 disasm_worldtileloader_loadphysicalblock_*.txt:2241）|
| 10 | 0x006d1f1c | ldrb r0,[r0,9] | BlockheadAI -[testTileAtPos:] | 读：byte9==0 则拒绝该 tile（AI 只考虑"已探索"tile）|
| 11 | 0x006d2ae8 | ldrb r0,[r0,9] | 同上 | 读：同上门（第二处）|

另外 verified：
- **全库没有第二处"写入点"**：fillTile:atPos:withType:（4785 词大函数，含 0x422/0x423 融冰/结冰规则）
  内 `off +9` 指令 = 0 条；其"水量保护"逻辑走局部 [fp,-0xc8]（入口取 tile[4]），随后把水量灌入
  下方 tile 的 byte4，从不写 byte9。→ "冰记忆冻结前水量"假设被否（无任何写点支持）。
- recalculateLighting 的变更报告：第 2/4 号写点置 flag→`lightChangedAtMacroPos:sendReliably:0 sendAtAll:0`；
  byte6/extra 写点→`exploreLightChangedAtMacroPos:clientLightBlockIndex:`（selector 单元 0xE84CE8/0xE84CEC 已解析）。

## 3. 存档实测（服务器真实物理块数据）

`server-world-archive/`（原版服务器导出的 40 个物理块，manifest+blobs）：
- 块 4_16（探针探索过的区域）：byte9>0 的 60 个 tile 与 byte6>0 **完全一一对应**；
  数值 = 以探索中心为圆心的径向光衰减梯度 {18, 38, 46, 54, 81, 92, 119, 139, 185...}，
  且 byte9==byte6 逐 tile 相等。相邻 tile 类型非冰（1/6/25/27 等）同样带值。
- 块 3_17/4_17/5_17（全天空 sunLight=255）但 byte9=0、byte6=0：**未探索**区域即使满阳光也不写。
- 深地块（如 21_7）byte6=byte7=byte9 全 0。
→ 实测符合 "exploredFraction = 探索光记忆（单调取大的探索数值）"，与冰/水量无关。

## 4. 复用命名建议（reconstruction 侧）

- `original_save_format.h` 目前未命名 byte9；建议补 `exploredFraction`。
- 顺带修正两处旧名（依据 DWARF）：raw[7] `temperatureScaleByte` → 原名 `sunLight`
  （温度计算把它当 scale 用，旧名是按用途命名）；raw[20-21] `temperatureOffset` → 原名
  `artificialHeat`（人工光热量累加器，ARTIFICIALLIGHT 批已验证 +0xe/+0x10/+0x12/+0x14 累加）。

## 5. 置信度与遗留

- **命名置信度：很高**（DWARF 原始符号 + 11 处指令行为全部自洽 + 存档实测三向一致）。
- **"非水量记忆"置信度：很高**（写入点穷举：唯一有意义写入者 = 光照/探索 pass；fillTile 融冰/结冰规则不碰 +9）。
- 遗留：
  1) Android 1.7.6 编码含第 14 个 C（offset 13 有字节），server 1.7.1 该处为 padding——不影响 byte9（0..12 全体一一对应且有行为互证），但两平台 13 号字节语义待定。
  2) `exploredFraction` 变更→`lightChanged`、`light` 变更→`exploreLightChanged` 的广播挂接与字段名有交叉，机制已钉、命名交叉原因未解释。
  3) 未找到把 exploredFraction 下调的写点（所有观测写入为 max 或 0 初始化）；若有"重新变暗"机制其路径未定位。
  4) `updateSnowContent:tile:` 写的是 b4 还是 b7 未终核（与旧称 "coverage byte7" 有关；现已知 b7=DWARF sunLight）。
