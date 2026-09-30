# 客户端离线组装 App 骨架（batch b5a）

本批把「存档 → 客户端离线组装」的生产侧结构搭起来：**框架先立、桩函数占位、
证据分级**。没有假装完成任何未恢复的类型。

## 为什么要先搭架子

B 线（PR #3）的读回侧已经积累了 60/60 个 `initWithWorld:` 前端方法的静态证据
和 13 个 Level-B 执行差分切片，但这些能力此前只存在于 `reconstruction/` 的
契约库里：没有一条**生产 app 侧**的装配路径把它们串起来。架子先立之后：

- 每个恢复批次接入的是一个**已存在的工厂槽**（`registerFactory`），而不是重写
  一条新链路；
- 「未恢复」是显式状态（`Stub` + 原因字符串），不是沉默的默认为零；
- 报告把无法识别的记录单独计数（缺 type 键 / 越界 type / 非 plist / 索引坏行），
  所以「组装成功」这四个字有可核对的边界。

## 组件与数据流

```text
snapshot root（tools/assemble_server_snapshot.py 的产物）
  ├── blocks/index.tsv      → OriginalClientWorld（真实 decoder 输出，65,541B/块）
  │                           已存在的 b3 批次产物，本批复用不改
  └── dynamic/index.tsv     → OriginalClientApp::open
        └── 每个 payload     → parseXmlPlist（SaveDict 桩层）
              └── dynamicObjects[] → 取 type：记录键后缀 `<x>_<y>/<type>`（b5b 主来源；
                                     objectType/dynamicObjectType 仅作组装元数据回退，
                                     分歧计入 type_disagreement）→ DynamicObjectRegistry
                    └── ClientDynamicObject（基类字段 + 装载状态）
                          └── report（按类型直方图 + 桩计数）+ toJson()
```

生产侧文件（`app/src/main/cpp/`，同时被 Android `native-lib` 与宿主 CI 目标编译）：

| 文件 | 角色 | 状态 |
|---|---|---|
| `original_save_dict.{h,cpp}` | GNUstep/Foundation 取值桩：最小 XML plist 读取 + `objectForKey:`/`intValue`/`floatValue`/`doubleValue`/`unsignedLongValue`/`boolValue`/`count`/`objectAtIndex:` 语义（nil 规则与恢复契约一致） | **桩**（未建模的选择器走 `noteStub()` 计数） |
| `dynamic_object_registry.{h,cpp}` | type_id 1..64 → 类名注册表；每槽默认桩工厂，只读已解码的基类字段 | **桩**（64/64 桩；`registerFactory` 是唯一晋级通道） |
| `original_client_app.{h,cpp}` | 装配骨架：开快照、读动态索引、按类型构造、出报告/JSON | **骨架**（记录级问题计数，不猜） |
| `generated/dynamic_object_type_table.inc` | 64 行 `{type_id, class_name, jump_target}`，由 `tools/gen_dynamic_object_type_table.py` 生成 | **解码产物**（`--check` 门禁） |

类型表的唯一真源是 `reconstruction/reverse-v3/native/dynamicobject_type_matrix.json`
（`_Z25classForDynamicObjectTypei` 跳转表 0x00b597fc 解码，64/64 项）。骨架里
没有任何手工誊写的类名；`static_assert(kTypeCount == 64)` 在编译期钉住行数。

## 桩的边界（明确写死，不允许漂移）

- **类型选择键**：记录键后缀 `<x>_<y>/<type>` 为主来源（b5b，经真实存档快照证实：
  10 条 dw 记录 16 个对象全部由键解析，`DW_RECORD_KEY_TYPE_EVIDENCE.md`）；
  `objectType`/`dynamicObjectType` 仅作组装元数据回退，与键不一致时计入
  `type_disagreement`，键获胜。三个来源的使用次数都进报告（`type_key_used`）。
- **8 个共享 objectType 类**（13 Dodo / 25 DropBear / 28 Donkey / 35 ClownFish /
  36 Shark / 39 CaveTroll / 51 Scorpion / 63 Yak）没有类级 `objectType` 覆盖：
  仅凭类型号不足以定类，构造出的对象会被 `shared_object_type_objects` 计数标记。
- **基类字段**只有已解码的四项：`uniqueID`→`unsignedLongValue`（+40）、
  `pos_x`/`pos_y`→`intValue`（+16/+20）、`floatPos`→`objectAtIndex:0/1`→`floatValue`。
  其余键一律不读、不猜。
- **缺 type 键**：不构造、计入 `unidentified_objects`；**type 越界**：
  `out_of_range_objects`；**非 plist / 无 `dynamicObjects`**：`opaque_records`；
  **索引坏行 / 不安全路径 / 尺寸不符**：`malformed_records` 或 `open()` 直接失败。
- 记录级问题不中断整批装载（真实快照里一条坏记录不该毁掉整次加载），但索引级
  问题必须响亮失败，且失败的 re-open 不破坏上一次成功状态。

## 复现（本机）

```text
python3 tools/gen_dynamic_object_type_table.py --check
python3 tools/make_client_app_fixture.py /tmp/bh-snapshot   # 合成快照
cmake -S reconstruction/recovered -B build-b5a -DCMAKE_BUILD_TYPE=Release
cmake --build build-b5a --target client_app_skeleton_cli test_original_client_app
./build-b5a/client_app_skeleton_cli /tmp/bh-snapshot          # 人读报告
./build-b5a/client_app_skeleton_cli /tmp/bh-snapshot --json   # 机器报告
ctest --test-dir build-b5a --output-on-failure                # 含 original_client_app
python3 tools/test_client_app_skeleton_evidence.py             # 门禁（静态 + 宿主）
```

## 晋级路径（下一步怎么接）

1. **b4 类执行差分每落地一个类型**：写 `reconstruction/recovered/<type>_load.cpp`
   契约 → 在该类型的工厂里调用它 → `registerFactory(id, …, Recovered)`；差分
   通过后再把状态改成 `Verified`。工厂槽已经存在，接入不需要改骨架。
   b5b 已按此路径落地第一例：`plant_full_factory`（TulipPlant 59）在构造时执行
   恢复链并把状态交给调用方，`plant_full` 测试在 O0/O2 下钉住。
2. **真实 dw 记录键名证实**（b5b 已落地）：记录键后缀即类型来源，
   回退键只在无键后缀的快照形状下生效；真实快照上
   `unidentified_objects` 16 → 0（`DW_RECORD_KEY_TYPE_EVIDENCE.md`）。
3. **接生产 APK 启动路径**（b5b 设备片已落地）：`GameActivity` 的 `initNative`
   在 Managers 分配后打开 `<files>/original-snapshot`（存在才开），计数进
   `game_log.txt`，完整报告写 `original_snapshot_report.json`；缺失时显式一行
   `not present`。替代世界 `world.bin` 路径不变，两条链互不替代。
4. **真机闭环**（b5b 设备片已验收）：设备实产日志 `blocks=40 records=10
   objects=16 stub=16 unidentified=0 out_of_range=0`，直方图与宿主 CLI 逐项一致；
   快照推送与 APK 装配步骤见 PR #3 的进度评论与下节。

## 边界

本批交付的是**骨架 + 桩 + 报告**：b5a 时没有声称任何具体类型已反序列化，
`Recovered`/`Verified` 计数当时在 CI 与宿主复现中都是 0；b5b 起按类型的工厂
逐例推进，当前工厂类型（1..64 中已注册者）产出 Recovered，其余仍是桩。
「7 项基类字段之外」的一切按各工厂 reason 声明证据级别。b5b 设备片已把该骨架
接进启动路径并完成真机装载验收（见下节）；APK 玩法（渲染/交互消费原版世界）
尚未接入。
CTest 侧新增 `original_client_app`（保存/重载、桩计数、插槽晋级、路径与索引安全）。

## 恢复状态所有权（state ownership，2026-09-30）

工厂运行恢复链后算出的每类型状态**归对象所有**：`ClientDynamicObject` 持有
`shared_ptr<const RecoveredState>`（family 名 = 解码它的模块结构，如
`PlantFullState`），`stateAs<State>(family)` 做族精确匹配的类型读回。注册表在
`construct()` 结构性拒绝「Recovered/Verified 但无状态」的对象——「工厂跑了、
状态以 nullptr 丢弃」的旧缺陷不可能再静默回归。20 个模块工厂全部经
`attachRecoveredState` 携带状态；CLI/`--json` 报告新增 `state_family` 字段；
b5a 守卫与快照 run 测试逐类型钉状态族。边界不变：状态是已保存字段面的
捕获，item-payload/world-gate 仍按各 reason 声明未执行；本节不声称玩法消费或
设备验收。

## 真机验收（2026-09-27，0.2-b5b + JNI 片）

- 设备：`com.noodlecake.blockheads.rebuild` 0.2-b5b（手工装配，v1/v2/v3 签名）。
- 快照：`reverse-probe-001` 组装产物（2.7MB / 53 文件）推到
  `<external files>/original-snapshot/`。
- `game_log.txt`（设备实产）：`Original snapshot loaded: blocks=40 records=10
  objects=16 stub=16 unidentified=0 out_of_range=0 opaque=0 malformed=0`，
  直方图 1:2 / 4:1 / 7:1 / 11:1 / 12:2 / 13:2 / 28:1 / 45:1 / 59:4 / 62:1。
- `original_snapshot_report.json`：16 个对象（类名/坐标/stub 状态）。
- 同轮替代世界 `world.bin` 照常加载，无崩溃；宿主 CLI 对同一快照的输出与设备
  逐项一致（见 `REVERSE_COVERAGE_LEDGER` 之外的 `DW_RECORD_KEY_TYPE_EVIDENCE.md`
  post-fix 段）。

## 世界数据源（world data source，2026-09-30，层1+2）

`original_world_import.cpp` 把解码后的原版块域导入替代 `GameWorld`：
Tile[0]（原版 TileType）只经 `original_tile_item_map.tsv` 的 **68 行 direct**
映射（44 项产出 ItemType → 经 `ItemManager::fromOriginalType` 落兼容 id；
24 行原体存字面 0 → 保持空），条件行（含 tile 6 泥土等 9 个世界相关分支）
**不猜、计数**（`unmapped_by_tile_type`）。Tile[1]/Tile[3] 暂不映射（替代
Tile 语义不同且无 A 级逐值映射），报告可见。导入全成全败；失败回退旧生成
路径并记日志。

启动序（`game_engine.cpp`）：快照存在 **且无 world.bin** → 一次性种子导入 +
立即存 world.bin；此后 world.bin 权威（玩家改动在重启后存活），快照保持证据
副本不被反复导入。Host 测试：`world_import`（双块、映射/未映射/item-0 三计
数、网格与网格重建、44+24 表核对）、`data_source`（种子一次 → world.bin 接
管 → 快照不重导）。边界：动态对象与玩家状态仍未导入；条件 TileType 的运行时
解析是下一批；本层不声称设备/原版运行验收。
