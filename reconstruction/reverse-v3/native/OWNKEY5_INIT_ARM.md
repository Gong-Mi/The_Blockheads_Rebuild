# ownkey5 — b3j 五个「先转发再读 key」加载器：执行层差分

本批是 b3j（静态 level-A）的执行层对应物：五个中量级
`-[<Class> initWithWorld:dynamicWorld:saveDict:cache:…]` 加载器在原始 ARM32 指令上
真跑一遍，与恢复的 C++ 契约逐位比对。五个方法共用一份恢复引擎
（`ownkey_loader.cpp`）+ 五张薄描述表（`ownkey5_init.cpp`）。

## 目标（5 个方法）

| 类 | IMP | 词数 | selector | 运行时 super |
|---|---:|---:|---|---|
| AppleTree | 0x009bd3b0 | 102（long 变体） | `initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:` | Tree |
| TrainStation | 0x00b38f88 | 105 | `initWithWorld:dynamicWorld:saveDict:cache:` | InteractionObject |
| Plant | 0x009559d0 | 114（long 变体） | 同上 long 变体 | DynamicObject |
| GatherBlock | 0x008695a0 | 128 | 4 参 | DynamicObject |
| Yak | 0x0095dae4 | 134 | 4 参 | DonkeyLike |

共享形状：`objc_msgSendSuper2` 同形转发 → nil 守卫 → 若干
`[saveDict[@"key"] <conv>]` 读入自有 ivar（宽度/顺序按字面量池与执行证据）→
可选收尾 hook → 返回 self。Plant 只转发 4 参 EXACT selector，把两个 noise 参数吞进
自有 ivar；AppleTree 转发全 6 参。

## 执行纠正了两处静态解码（本批的主要产出）

b3j 的静态解码把「key ↔ 转换方式 ↔ 目标 ivar」的配对弄反了两处，两处都由执行钉死，
并与 ivar 符号表交叉验证一致：

1. **GatherBlock**：实测选择器序列是
   `objectForKey:timer → floatValue →（vcvt.u32.f32 / vcvt.f32.u32 往返）→ store@56`，
   然后 `objectForKey:lastKnownGatherValue → intValue → store@60`。
   符号表 `OBJC_IVAR_$_GatherBlock.timer = 56`、`.lastKnownGatherValue = 60` —— 每个 key
   写自己的 ivar，往返浮点链属于 `timer`。静态解码把两者对调了。
2. **Yak**：实测读序是 **milk 在前**（→ @1136，milk 自己的 ivar），然后 hair（→ @1140），
   再 `updateTextures`。静态解码写成了 hair 在前。
   符号表 `OBJC_IVAR_$_Yak.milk = 1136`、`.hair = 1140`。

两处纠正同时改进了三处：harness 描述表、harness 的独立期望表、C++ 契约的步骤表；
CTest 契约驱动里的期望也同步（否则 CI 会在没有 ELF 的环境里替错误模型背书）。

## 用例表（5 方法 × 若干用例 = 37 个，全部 bit-exact）

```text
AppleTree     10 cases（含 float 边界：+0/-0/+inf/NaN/subnormal/大有限/负数、nil_super、distinct_tokens）
TrainStation   6 cases（含 token 全 1 / 0 / 低位、nil_super、distinct_tokens）
Plant          6 cases（noise 双参数、预置 ivar、zero/nil 变体、nil_super、nil_dyn_ivar）
GatherBlock    8 cases（往返截断 3.999、NaN、1e30 饱和、int_min、nil_super、zero）
Yak            7 cases（含 NaN+inf、subnormal、同值、nil_super、distinct_tokens）
```

每例比对：返回寄存器、实例整块 image（含预置 ivar 的 pre-state）、
(code,arg) 调用 trace，C++ 侧同时跑 `-O0` 与 `-O2`。
另有不依赖恢复 C++ 的独立期望：期望 trace 序列、期望 ivar 值、nil 路径下实例
必须停在 pre-state（一个字节都不许被写）。

## 本批为让执行可信而修掉的 harness 缺陷（都留了注释）

1. **五个方法共用一个 Unicorn session**：CODE 钩子累积，第二个方法起会先触发上一个
   方法的 super/send 桩（断言到别人的 own_class）。→ 每个方法重建 session。
2. **`_ensure_mapped` 以 `id(uc)` 缓存**：换 session 后对象 id 会被复用，陈旧条目会
   跳过映射，第一条桩指令就崩。→ 改为容忍已映射。
3. **store 钩子假定基址寄存器已含 `self+offset`**：实际存在
   `str r0,[r1,r2]` 寄存器偏移形式。→ 按指令编码区分（Rn = bits 19-16，Rm = bits 3-0，
   第一次实现把两个位域取反了，被自己的断言抓住）。
4. **long 方法的入栈实参个数被 `forward_long` 绑死**：Plant 的两个 noise 参数读出 0。
   → 入栈恒为四个（saveDict/cache/treeDensity/season），`forward_long` 只决定 super 桩
   断言几个参数。
5. **nil-super 断言「整块零内存」**：对带预置 ivar 的类不成立。→ 改为断言回到
   pre-state，并把同一份 pre-state 显式传给 C++ 侧（桥新增 preset 参数），
   两侧从同一初始状态起跑。
6. **失败域分离**：原来一个方法失配就 abort 整批，已绿的方法连报告都拿不到。
   → 逐方法独立计数/独立报告，`per_method_status` 进 report，全绿才退出 0。

## 产物

```text
reconstruction/recovered/ownkey_loader.{h,cpp}       一份共享引擎（步骤：读 key/存参数/收尾 hook/通知）
reconstruction/recovered/ownkey5_init.{h,cpp}        五张薄描述表（唯一的每类代码）
tools/arm_harness/ownkey.py                          共享 Unicorn 驱动（OwnKeyRunner）
tools/test_ownkey5_arm.py                            薄壳：描述表 + 用例表 + 独立期望
tools/ownkey5_init_arm_bridge.cpp                    -O0/-O2 桥（含 pre-state 参数）
tools/test_ownkey5_init.cpp                          CTest 契约驱动
tools/test_ownkey5_init_arm_evidence.py              双模式证据守卫
reconstruction/reverse-v3/native/disasm_<class>_ownkey5.txt  ×5 listing
```

复现：

```text
python3 tools/test_ownkey5_arm.py <pinned-elf> --output-dir <仓库外目录>
cmake -S reconstruction/recovered -B build-ownkey5 -DCMAKE_BUILD_TYPE=Release
cmake --build build-ownkey5 --target test_ownkey5_init && LD_LIBRARY_PATH=$PREFIX/lib ./build-ownkey5/test_ownkey5_init
python3 tools/test_ownkey5_init_arm_evidence.py
```

## Boundary

本级只覆盖这五个方法本身：合成 fixture（打桩的 super 初始化器、合成实例/世界 token、
合成 saveDict 盒子），不是 Foundation，不是原版 app 运行时，没有 APK / 真机验收。
super 背后的 Tree / InteractionObject / DynamicObject 初始化器本体不在本次差分范围。
五个方法作为 `initWithWorld:` 前端成员，静态 level-A 证据在 b3j。
