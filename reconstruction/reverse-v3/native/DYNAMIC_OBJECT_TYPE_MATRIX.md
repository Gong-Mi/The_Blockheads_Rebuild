# DynamicObjectType 1..64 类名矩阵（native 证据）

## 来源

- ELF: `extracted/lib/armeabi-v7a/libApplication.so`
- ELF SHA-256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
- 函数: `_Z25classForDynamicObjectTypei` @ `0x00b597bc`
- 跳转表: `0x00b597fc`（PC 相对偏移表，base PC = 0x00b597f8，PIC 基址 0x0105faf4）
- 恢复脚本: `tools/recover_dynamic_object_type_matrix.py`（`--check` 门禁，产物 stale 即失败）
- 证据契约: `tools/test_dynamic_object_type_matrix_evidence.py`
- 数据产物: `reconstruction/reverse-v3/native/dynamicobject_type_matrix.json`（schema 1）

解码方法：对 type_id 1..64，从跳转表读取 PC 相对偏移得到 case 分支目标地址；在目标起 48 字节窗口内扫描 `ldr r3, [pc, #imm]`（0xe59f3000 掩码 0xfffff000）加载的 PIC 字面量，经 PIC 基址换算得到类指针槽，再沿 class → (+16) ro → (+16) name 读出 C++ 类名字符串。全部 64 项均由二进制直接解码，无手工推断。

## 完整映射（1..64）

| type_id | class_name | jump_target |
|---|---|---|
| 1 | AppleTree | 0x00b59900 |
| 2 | MapleTree | 0x00b5993c |
| 3 | MangoTree | 0x00b59978 |
| 4 | PineTree | 0x00b599b4 |
| 5 | CactusTree | 0x00b599f0 |
| 6 | CoconutTree | 0x00b59a2c |
| 7 | OrangeTree | 0x00b59a68 |
| 8 | CherryTree | 0x00b59aa4 |
| 9 | CoffeeTree | 0x00b59ae0 |
| 10 | FlaxPlant | 0x00b59b1c |
| 11 | SunflowerPlant | 0x00b59b58 |
| 12 | CornPlant | 0x00b59b94 |
| 13 | Dodo | 0x00b59c48 |
| 14 | FreeBlock | 0x00b59c84 |
| 15 | InteractionObject | 0x00b59cc0 |
| 16 | FireObject | 0x00b59cfc |
| 17 | Torch | 0x00b59d38 |
| 18 | GlowBlock | 0x00b59d74 |
| 19 | Ladder | 0x00b59db0 |
| 20 | Door | 0x00b59dec |
| 21 | ArtificialLight | 0x00b59e28 |
| 22 | SurfaceBlock | 0x00b59e64 |
| 23 | Bed | 0x00b59ea0 |
| 24 | Blockhead | 0x00b59f18 |
| 25 | DropBear | 0x00b59f54 |
| 26 | GatherBlock | 0x00b59f90 |
| 27 | CarrotPlant | 0x00b59fcc |
| 28 | Donkey | 0x00b5a008 |
| 29 | SnowSurfaceBlock | 0x00b5a080 |
| 30 | Egg | 0x00b5a0bc |
| 31 | Window | 0x00b5a0f8 |
| 32 | Boat | 0x00b5a134 |
| 33 | ChilliPlant | 0x00b5a170 |
| 34 | KelpPlant | 0x00b5a1ac |
| 35 | ClownFish | 0x00b5a1e8 |
| 36 | Shark | 0x00b5a224 |
| 37 | LimeTree | 0x00b5a260 |
| 38 | Wire | 0x00b5a29c |
| 39 | CaveTroll | 0x00b5a2d8 |
| 40 | Rail | 0x00b5a314 |
| 41 | HandCar | 0x00b5a350 |
| 42 | SteamTrain | 0x00b5a38c |
| 43 | FreightCar | 0x00b5a3c8 |
| 44 | PassengerCar | 0x00b5a404 |
| 45 | Workbench | 0x00b5a440 |
| 46 | Chest | 0x00b5a47c |
| 47 | Sign | 0x00b5a4b8 |
| 48 | TradingPost | 0x00b5a4f4 |
| 49 | TrainStation | 0x00b5a530 |
| 50 | TradePortal | 0x00b5a56c |
| 51 | Scorpion | 0x00b5a5a8 |
| 52 | Painting | 0x00b5a5e4 |
| 53 | Column | 0x00b5a620 |
| 54 | Stairs | 0x00b5a65c |
| 55 | ElevatorMotor | 0x00b5a698 |
| 56 | ElevatorShaft | 0x00b5a6d4 |
| 57 | GemTree | 0x00b5a710 |
| 58 | VinePlant | 0x00b5a74c |
| 59 | TulipPlant | 0x00b5a788 |
| 60 | OwnershipSign | 0x00b5a7c8 |
| 61 | WheatPlant | 0x00b59bd0 |
| 62 | TomatoPlant | 0x00b59c0c |
| 63 | Yak | 0x00b5a044 |
| 64 | Mirror | 0x00b59edc |

## 对外部开源推断的纠正

此前外部开源项目对部分枚举值的类名属于推断，本矩阵以 native 跳转表直接解码为准，纠正/补充如下：

| type_id | 外部推断 | native 实际 |
|---|---|---|
| 14 | DroppedItem | **FreeBlock** |
| 16 | Fire | **FireObject** |
| 42 | SteamLocomotive | **SteamTrain** |
| 22 | （缺失） | **SurfaceBlock**（补充） |
| 24 | （缺失） | **Blockhead**（补充） |
| 29 | （缺失） | **SnowSurfaceBlock**（补充） |

其余关键锚点与已知证据一致：1=AppleTree、13=Dodo、20=Door、23=Bed、25=DropBear、28=Donkey、30=Egg、35=ClownFish、36=Shark、39=CaveTroll、45=Workbench、46=Chest、50=TradePortal、51=Scorpion、63=Yak、64=Mirror。

注意跳转表槽位顺序与 type_id 并非单调：61/62（WheatPlant/TomatoPlant）、63（Yak）、64（Mirror）的分支目标回填到较早地址区段，这是编译器对 switch 布局的结果，解码时以跳转表偏移为准，不按地址排序推断 id。
