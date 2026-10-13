# b4r — 九个 tree 家族 LONG 加载器：执行层差分

本批是 b3i（静态 level-A）的执行层对应物：把静态判定为「同一份逐字节相同的
62 词共享函数体 + 每类各自的 superref/selector 尾单元」的九个 tree 家族
long-variant 加载器，在原始 ARM32 指令上真跑一遍，与恢复的 C++ 契约做逐位比对。

## 目标（9 个方法 / 同一个 selector）

selector：
`-[<Class> initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]`
`types @32@0:4@8@12@16@20@24@28`

| 类 | IMP | 边界 | superref 单元 | selector 单元 |
|---|---:|---:|---:|---:|
| CactusTree | 0x00b533bc | 0x00b534b4 | 0x00e8bea8 | 0x00e86a10 |
| CherryTree | 0x00d0df2c | 0x00d0e024 | 0x00e8bf08 | 0x00e88488 |
| CoconutTree | 0x00a99948 | 0x00a99a40 | 0x00e8be50 | 0x00e85594 |
| CoffeeTree | 0x007deb28 | 0x007dec20 | 0x00e8bd58 | 0x00e818f4 |
| GemTree | 0x00529134 | 0x0052922c | 0x00e8bc54 | 0x00e7d970 |
| LimeTree | 0x00809c3c | 0x00809d34 | 0x00e8bd64 | 0x00e81c58 |
| MangoTree | 0x00d4b4f4 | 0x00d4b5ec | 0x00e8bf20 | 0x00e88a38 |
| MapleTree | 0x00db5fb4 | 0x00db60ac | 0x00e8bf50 | 0x00e88f70 |
| OrangeTree | 0x00a96604 | 0x00a966fc | 0x00e8be4c | 0x00e85538 |

共享函数体 sha256（九类同一值，word 0..58）：
`0e8602818e17da1dec064c73afc901040ccef3c477b0ef8f7654c5beec4db765`
运行时 superclass：**九类全部 = Tree**（从 class 结构 +4 解析，不按名字猜）。
自有 key / 自有 ivar：**九类全部为空**（字面量池扫描结论）。

## 执行钉死的语义

1. **六参全量转发**：`objc_sendSuper2(objc_super{self, own-class}, @selector(...),
world, dynamicWorld, saveDict, cache, treeDensityNoiseFunction, seasonOffsetNoiseFunction)`。
前两个参数走 r2/r3，其余四个走栈（`n_stack=4`）。参数顺序经执行验证为
`world, dynamicWorld, saveDict, cache, treeDensity, seasonOffset` —— 顺序错位会在
两侧同时体现为不匹配。
2. **objc_super 的 class 字**是**本类自己的 class 对象**（`__objc_superrefs` 指向
own class，运行期再走 `current_class->superclass`），不是 Tree。执行断言的就是
「单元地址 → 解引用后的 class 字 == 该类的 class 对象」。
3. **恰好一条消息**：九个函数体各自只发出一次 super 转发；除它之外不发任何
   msgSend（harness 额外把 `objc_msgSend` GOT 槽也打了桩，任何额外发送都会被记为
   额外调用而失配）。
4. **nil 守卫**：super 返回 nil ⇒ 直接返回 nil，且实例内存**保持全零不被写入**
   （用例断言整块 image 仍为零）。
5. **九个 happy-path trace 逐位相同** —— 这是 b3i「共享函数体」静态结论在执行层
   的对应证明（report 的 `identical_trace_across_entries`）。

## 用例表（9 类 × 2 = 18 个用例，全部 bit-exact）

```text
<class>_happy       trace 1  (转发六参 + 返回 self 0x60000000)
<class>_nil_super   trace 1  (转发六参 + 返回 nil，实例内存保持零)
```

每类两个用例的比对维度：返回寄存器、六参转发元组、objc_super 结构
（receiver + own-class 字）、selector 字符串、消息调用序列（ARM 侧实测 vs C++
契约的 (code,arg) trace），C++ 侧同时跑 `-O0` 与 `-O2`。

独立期望（不依赖恢复 C++ 的一侧）：六参元组的具体 token 值、选择器字符串、
own-class 字与 class 对象相等、nil 用例的整块零内存。

## 负向对照（`--self-test`，5 个变异全部被检出）

在 CactusTree 函数体内做指令级变异，要求每个变异都被**注意到**：或者被它该破坏的
那条断言抓住，或者在执行被变异后的指令流时直接报错（`UC_ERR_READ_UNMAPPED` 等）。
「跑完且比对仍相等」才是不合格。
变异：`world` 参数来源改为 dynamicWorld 溢出槽、删掉 super 转发（`blx r8` → nop）、
nil 守卫改自比较、`saveDict` 参数来源改为 treeDensity 槽、跳过 superref 解引用
（存单元地址而不是 class 对象）。

**教训（Unicorn 翻译块缓存）**：Unicorn 跨 `emu_start` 缓存已翻译的基本块，把
「改字节 → 跑 → 还原字节」的变异对照放在同一个 uc 上做，**还原后的字节不会被重新
翻译**，后续变异实际复用的是第一次变异的翻译，于是对照静默变成「未检出」。变异对照
必须**每次重建 session**（本批的 `make_session()`），不能原地还原后复用；重建之后
才会暴露真实行为（例如删掉 super 转发后函数体会直接执行到未映射地址）。

实测（重建 session 之后）：

```text
cactus_world_arg_source    assertion (forwarded argument placement)
cactus_super_call_removed  assertion (expected exactly one super message)
cactus_nil_guard_moved     assertion (return)
cactus_savedict_arg_source fault while executing the mutated body (UC_ERR_READ_UNMAPPED)
cactus_class_deref_skipped assertion (objc_super.class)
5/5 mutations detected
```

## 产物

```text
reconstruction/recovered/treefamily9_long_init.{h,cpp}          一份共享契约
reconstruction/recovered/treefamily9_long_init_classes.h        每类薄包装（X-macro）
reconstruction/recovered/treefamily9_long_init_classes.inc      生成表（--check 门控）
tools/gen_treefamily9_class_table.py                            从 b3i JSON 生成上表
tools/arm_harness/super_forward.py                              共享 Unicorn 模块
tools/test_treefamily9_long_init_arm.py                         薄壳（目标表 + 用例表）
tools/treefamily9_long_init_arm_bridge.cpp                      -O0/-O2 桥
tools/test_treefamily9_long_init.cpp                            CTest 驱动（9 个 target）
tools/test_treefamily9_long_init_arm_evidence.py                双模式守卫
reconstruction/reverse-v3/native/disasm_<class>_long_initwithworld.txt  ×9 listing
```

复现：

```text
python3 tools/gen_treefamily9_class_table.py --check
python3 tools/test_treefamily9_long_init_arm.py <pinned-elf> --output-dir <repo 外目录>
python3 tools/test_treefamily9_long_init_arm.py <pinned-elf> --output-dir <dir> --self-test
cmake -S reconstruction/recovered -B build-tree9 -DCMAKE_BUILD_TYPE=Release
cmake --build build-tree9 --target test_treefamily9_long_init
LD_LIBRARY_PATH=$PREFIX/lib ctest --test-dir build-tree9 -R treefamily9
python3 tools/test_treefamily9_long_init_arm_evidence.py
```

## Boundary

本级只覆盖这九个方法本身：合成 fixture（打桩的 super 初始化器、合成实例/世界
token），不是 Foundation，不是原版 app 运行时，没有 APK / 真机验收。super 背后的
Tree 加载器本体（save-dict 读取）不在本次差分范围内。九个类的体转发语义至此有了
执行证据；它们作为 `initWithWorld:` 前端成员，静态 level-A 证据在 b3i。
