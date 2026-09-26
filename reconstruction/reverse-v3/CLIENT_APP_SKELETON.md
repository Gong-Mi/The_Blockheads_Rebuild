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
              └── dynamicObjects[] → 取 type 键（objectType，或组装元数据键
                                     dynamicObjectType）→ DynamicObjectRegistry
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

- **类型选择键**：`objectType`（客户端可见类型号；56/64 类的类级常量等于类型号）
  为主，`dynamicObjectType` 作为组装元数据覆盖键。两个键的使用次数都进报告
  （`type_key_used`），因为真实 dw 记录里到底出现哪个键**尚未用真实快照证实**。
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
2. **真实 dw 记录键名证实后**：把 `objectType`/`dynamicObjectType` 的假设收敛成
   单一确定键（在 `original_client_app.cpp` 里改一处），报告直方图会立刻反映。
3. **接生产 APK `PersistenceManager`**（PR #3 未勾选项）：把
   `OriginalClientApp::open/loadDynamicObjects` 挂到 `GameActivity` 的起步路径，
   让替换端能直接吃原版快照。
4. **真机闭环**：`client_app_skeleton_cli` 的同一份逻辑在 Android 上跑，用真机
   日志核对报告计数。

## 边界

本批交付的是**骨架 + 桩 + 报告**：没有声称任何具体类型已反序列化，
`Recovered`/`Verified` 计数在 CI 与宿主复现中都是 0，未接 APK 玩法、
未做真机验收，「7 项基类字段之外」的一切都还是桩。CTest 侧新增
`original_client_app`（保存/重载、桩计数、插槽晋级、路径与索引安全）。
