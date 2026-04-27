# Leona 检测点矩阵

更新时间：2026-04-23  
适用范围：`/Users/a/back/Game/cq`

---

## 1. 文档目的

这份文档把 Leona 当前与下一步建议支持的环境检测点整理成统一矩阵，便于：

- 对齐 SDK 当前真实能力
- 映射可参考的 GitHub 开源实现
- 给后续 `Android SDK ↔ Server` 风险评分提供统一事件口径
- 作为补齐 `tamper / debug / virtual env / zygisk` 等模块的 backlog 基线

---

## 2. 当前代码落点

Android SDK 检测核心主要在：

- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/injection_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/environment_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/root_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/xposed_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/unidbg_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/tamper_detector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/report/collector.cpp`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/AppIntegrity.kt`

---

## 3. 当前已实现检测矩阵

| 类别 | 当前检测点 | Leona 文件 |
|---|---|---|
| Frida / 注入 | `TracerPid`、Frida 库名、ARM64 trampoline 机器码特征 | `injection_detector.cpp` / `frida_signatures.cpp` |
| Root / Magisk / KernelSU / Riru | `su` 路径、Magisk 路径、Zygisk/KernelSU/Riru 残留、`ro.secure`、`ro.debuggable`、`test-keys` | `root_detector.cpp` |
| Xposed / LSPosed / EdXposed | Xposed/LSPosed/EdXposed 路径、`/proc/self/maps` 中 `liblspd.so` 等库痕迹 | `xposed_detector.cpp` |
| Emulator / 云机基础特征 | AVD、Genymotion、LDPlayer、Nox、MuMu、BlueStacks、QEMU 属性与设备节点 | `environment_detector.cpp` |
| Unidbg | `CNTFRQ_EL0`、`CNTVCT_EL0` 时间一致性、父进程、`/proc/cpuinfo` 形态 | `unidbg_detector.cpp` / `timing_probe.cpp` |
| Tamper（骨架） | `FLAG_DEBUGGABLE`、installer 缺失、`sourceDir` 异常、证书摘要缺失 | `AppIntegrity.kt` / `tamper_detector.cpp` |

---

## 4. 完整检测点矩阵

### 4.1 Root / 提权环境

#### 已实现

- 常见 `su` 路径
- `Superuser.apk`
- Magisk 安装目录
- Magisk modules 目录
- Zygisk LSPosed / Shamiko 模块目录
- KernelSU 目录
- Riru 目录
- `ro.build.tags=test-keys`
- `ro.secure=0`
- `ro.debuggable=1`
- 非标准 `su` 路径

#### 建议补齐

- `ro.boot.verifiedbootstate`
- `ro.boot.flash.locked`
- `ro.boot.vbmeta.device_state`
- SELinux permissive
- mount namespace / overlay 异常
- `which su`
- system 分区写权限异常
- 可疑管理器 app 检测（Magisk、KernelSU、LSPosed）

#### 参考项目

- [scottyab/rootbeer](https://github.com/scottyab/rootbeer)
- [reveny/Android-Native-Root-Detector](https://github.com/reveny/Android-Native-Root-Detector)
- [apkunpacker/MagiskDetection](https://github.com/apkunpacker/MagiskDetection)
- [Dr-TSNG/ApplistDetector](https://github.com/Dr-TSNG/ApplistDetector)

---

### 4.2 Xposed / LSPosed / Zygisk / Hook 框架

#### 已实现

- `XposedBridge.jar`
- Xposed 安装器目录
- `zygisk_lsposed`
- `lspd`
- `riru_edxposed`
- `/proc/self/maps` 中：
  - `liblspd.so`
  - `libriru_`
  - `libedxp_`
  - `libepic.so`

#### 建议补齐

- ART method inline hook 痕迹
- JNI native method 替换检测
- classloader 异常
- stack trace 中 Xposed/LSPosed 痕迹
- Zygisk ptrace/event 侧信号
- LSPatch 特征

#### 参考项目

- [vvb2060/XposedDetector](https://github.com/vvb2060/XposedDetector)
- [apkunpacker/DetectZygisk](https://github.com/apkunpacker/DetectZygisk)
- [JingMatrix/Demo](https://github.com/JingMatrix/Demo)
- [byxiaorun/Ruru](https://github.com/byxiaorun/Ruru)

---

### 4.3 Frida / 动态注入 / Inline Hook

#### 已实现

- `TracerPid`
- `/proc/self/maps` 中 Frida 相关库名
- ARM64 trampoline 机器码特征扫描

#### 建议补齐

- thread name 检测
- named pipe/socket 检测
- mem-disk compare
- GOT / PLT hook 检测
- 匿名可执行内存更细粒度分类
- 自身代码段自校验

#### 参考项目

- [darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)
- [muellerberndt/frida-detection](https://github.com/muellerberndt/frida-detection)
- [TUGOhost/anti_Android](https://github.com/TUGOhost/anti_Android)

---

### 4.4 Debug / 调试器

#### 当前状态

- `TracerPid` 已通过 `injection_detector.cpp` 间接覆盖

#### 建议拆分为独立模块

- `android.os.Debug.isDebuggerConnected()`
- `waitForDebugger`
- JDWP 端口
- `gdbserver` / `lldb` 痕迹
- 断点/单步 timing 异常
- `ptrace` 自保护

#### 参考项目

- [muhammedalikcb/securecheck](https://github.com/muhammedalikcb/securecheck)
- [TUGOhost/anti_Android](https://github.com/TUGOhost/anti_Android)
- [securing/IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite)

---

### 4.5 Emulator / 云手机 / 虚拟空间 / 多开

#### 已实现

- AVD
- Genymotion
- LDPlayer
- Nox
- MuMu
- BlueStacks
- QEMU 属性
- `qemu_pipe`
- `qemud`
- `genyd`
- 厂商残留 so / data 目录

#### 建议补齐

- 传感器缺失
- Telephony / SIM / 基带异常
- OpenGL renderer/vendor 异常
- 电池/温度/充电状态模式异常
- dataDir / uid / sourceDir 一致性
- VirtualApp / 双开容器包检测
- Binder/process name 异常

#### 参考项目

- [framgia/android-emulator-detector](https://github.com/framgia/android-emulator-detector)
- [lamster2018/EasyProtector](https://github.com/lamster2018/EasyProtector)
- [talsec/Free-RASP-Community](https://github.com/talsec/Free-RASP-Community)

---

### 4.6 Tamper / Repack / 签名 / 完整性

#### 当前第二阶段

- `FLAG_DEBUGGABLE`
- installer 缺失
- `sourceDir` 缺失或非 `.apk`
- 签名摘要为空
- **配置化基线比对**：
  - `expectedPackageName`
  - `allowedInstallerPackages`
  - `allowedSigningCertSha256`
  - `expectedSigningCertificateLineageSha256`
  - `expectedApkSigningBlockSha256`
  - `expectedApkSigningBlockIdSha256`
  - `expectedApkSha256`
  - `expectedNativeLibSha256`
  - `expectedManifestEntrySha256`
  - `expectedResourcesArscSha256`
  - `expectedResourceInventorySha256`
  - `expectedResourceEntrySha256`
  - `expectedDexSha256`
  - `expectedDexSectionSha256`
  - `expectedDexMethodSha256`
  - `expectedSplitApkSha256`
  - `expectedSplitInventorySha256`
  - `expectedDynamicFeatureSplitSha256`
  - `expectedDynamicFeatureSplitNameSha256`
  - `expectedConfigSplitAxisSha256`
  - `expectedConfigSplitNameSha256`
  - `expectedConfigSplitAbiSha256`
  - `expectedConfigSplitLocaleSha256`
  - `expectedConfigSplitDensitySha256`
  - `expectedDeclaredPermissionFieldValues`
  - `expectedComponentSignatureSha256`
  - `expectedComponentAccessSemanticsSha256`
  - `expectedComponentOperationalSemanticsSha256`
  - `expectedComponentFieldValues`
  - `expectedProviderUriPermissionPatternsSha256`
  - `expectedProviderPathPermissionsSha256`
  - `expectedProviderAuthoritySetSha256`
  - `expectedProviderSemanticsSha256`
  - `expectedProviderAccessSemanticsSha256`
  - `expectedProviderOperationalSemanticsSha256`
  - `expectedIntentFilterSha256`
  - `expectedIntentFilterActionSha256`
  - `expectedIntentFilterCategorySha256`
  - `expectedIntentFilterDataSha256`
  - `expectedIntentFilterDataSchemeSha256`
  - `expectedIntentFilterDataAuthoritySha256`
  - `expectedIntentFilterDataPathSha256`
  - `expectedIntentFilterDataMimeTypeSha256`
  - `expectedIntentFilterSemanticsSha256`
  - `expectedGrantUriPermissionSha256`
  - `expectedGrantUriPermissionSemanticsSha256`
  - `expectedUsesFeatureSha256`
  - `expectedUsesFeatureNameSha256`
  - `expectedUsesFeatureRequiredSha256`
  - `expectedUsesFeatureGlEsVersionSha256`
  - `expectedUsesFeatureFieldValues`
  - `expectedUsesSdkSha256`
  - `expectedUsesSdkMinSha256`
  - `expectedUsesSdkTargetSha256`
  - `expectedUsesSdkMaxSha256`
  - `expectedUsesSdkFieldValues`
  - `expectedSupportsScreensSha256`
  - `expectedSupportsScreensSmallScreensSha256`
  - `expectedSupportsScreensNormalScreensSha256`
  - `expectedSupportsScreensLargeScreensSha256`
  - `expectedSupportsScreensXlargeScreensSha256`
  - `expectedSupportsScreensResizeableSha256`
  - `expectedSupportsScreensAnyDensitySha256`
  - `expectedSupportsScreensRequiresSmallestWidthDpSha256`
  - `expectedSupportsScreensCompatibleWidthLimitDpSha256`
  - `expectedSupportsScreensLargestWidthLimitDpSha256`
  - `expectedCompatibleScreensSha256`
  - `expectedCompatibleScreensScreenSizeSha256`
  - `expectedCompatibleScreensScreenDensitySha256`
  - `expectedUsesLibrarySha256`
  - `expectedUsesLibraryNameSha256`
  - `expectedUsesLibraryRequiredSha256`
  - `expectedUsesLibraryFieldValues`
  - `expectedUsesLibraryOnlySha256`
  - `expectedUsesLibraryOnlyNameSha256`
  - `expectedUsesLibraryOnlyRequiredSha256`
  - `expectedUsesNativeLibrarySha256`
  - `expectedUsesNativeLibraryNameSha256`
  - `expectedUsesNativeLibraryRequiredSha256`
  - `expectedUsesNativeLibraryFieldValues`
  - `expectedQueriesSha256`
  - `expectedQueriesPackageSha256`
  - `expectedQueriesPackageNameSha256`
  - `expectedQueriesPackageSemanticsSha256`
  - `expectedQueriesProviderSha256`
  - `expectedQueriesProviderAuthoritySha256`
  - `expectedQueriesProviderSemanticsSha256`
  - `expectedQueriesIntentSha256`
  - `expectedQueriesIntentActionSha256`
  - `expectedQueriesIntentCategorySha256`
  - `expectedQueriesIntentDataSha256`
  - `expectedQueriesIntentDataSchemeSha256`
  - `expectedQueriesIntentDataAuthoritySha256`
  - `expectedQueriesIntentDataPathSha256`
  - `expectedQueriesIntentDataMimeTypeSha256`
  - `expectedQueriesIntentSemanticsSha256`
  - `expectedApplicationSemanticsSha256`
  - `expectedApplicationSecuritySemanticsSha256`
  - `expectedApplicationRuntimeSemanticsSha256`
  - `expectedApplicationFieldValues`
  - `expectedMetaDataType`
  - `expectedMetaDataValueSha256`
  - `expectedManifestMetaDataEntrySha256`
  - `expectedManifestMetaDataSemanticsSha256`
  - `expectedMetaData`
- **server 下发 baseline**：
  - SDK 支持从 `/v1/handshake` 的 `tamperBaseline` 读取远端策略
  - 远端策略会与本地 Builder baseline 合并，远端标量/集合优先，map 类按 key 合并
- **采集范围扩展**：
  - signing certificate lineage fingerprint
  - APK Signing Block fingerprint
  - APK Signing Block ID value fingerprint（如 `0x7109871a`）
  - base APK 中 `AndroidManifest.xml` 条目 hash
  - base APK 中 `resources.arsc` 条目 hash
  - base APK 中 `resources.arsc` / `res/...` / `assets/...` 条目名集合 fingerprint
  - base APK 中 `res/...` / `assets/...` resource entry hash
  - `classes*.dex` 条目 hash
  - DEX 内部 section hash（如 `classes.dex#code_item`）
  - DEX method code hash（如 `classes.dex#Lcom/example/MainActivity;->isTampered()Z`）
  - split APK 文件 hash
  - split APK inventory fingerprint（split 文件名集合）
  - dynamic feature split fingerprint
  - dynamic feature split raw filename fingerprint
  - config split axis fingerprint
  - config split raw filename fingerprint
  - config split ABI / locale / density 子指纹
  - ELF section hash（如 `libleona.so#.text`）
  - ELF export symbol fingerprint（如 `libleona.so#JNI_OnLoad`）
  - ELF export graph fingerprint（如 `libleona.so`）
  - requested permissions fingerprint
  - requested permission semantics fingerprint
  - declared permission semantics fingerprint
  - declared permission field drift（如 `permission:com.example.permission.GUARD#protectionLevel`）
  - component fingerprint（如 `activity:com.example.MainActivity`）
  - component access semantics fingerprint（如 exported / permission）
  - component operational semantics fingerprint（如 enabled / processName / directBootAware）
  - component field drift（如 `activity:com.example.MainActivity#exported`）
  - provider `uriPermissionPatterns` fingerprint
  - provider `pathPermissions` fingerprint
  - provider authority set fingerprint（处理多 authority / 分号顺序）
  - provider combined semantics fingerprint（authority/exported/permission/path-permission/grantUriPermissions）
  - provider access semantics fingerprint（authority/readPermission/writePermission/grantUriPermissions/path-permission/uriPermissionPattern）
  - provider operational semantics fingerprint（enabled/exported/processName/directBootAware/multiprocess/initOrder）
  - raw manifest intent-filter fingerprint
  - raw manifest intent-filter action/category/data fingerprint
  - raw manifest intent-filter data subfield fingerprint（scheme / authority / path / mimeType）
  - normalized manifest intent-filter semantics fingerprint
  - raw manifest `grant-uri-permission` fingerprint
  - normalized manifest `grant-uri-permission` semantics fingerprint
  - raw manifest `uses-feature` / `uses-sdk` / `supports-screens` / `compatible-screens` / `uses-library` / `uses-native-library` / `queries` fingerprint
  - raw manifest `uses-feature` name / required / glEsVersion 子指纹
  - raw manifest `uses-feature` field drift（如 `uses-feature:android.hardware.camera#required`）
  - raw manifest `uses-sdk` minSdkVersion / targetSdkVersion / maxSdkVersion 子指纹
  - raw manifest `uses-sdk` field drift（如 `uses-sdk#targetSdkVersion`）
  - raw manifest `supports-screens` small/normal/large/xlarge/resizeable/anyDensity/requiresSmallestWidthDp/compatibleWidthLimitDp/largestWidthLimitDp 子指纹
  - raw manifest `compatible-screens` screenSize / screenDensity 子指纹
  - raw manifest `uses-library` / `uses-native-library` name / required 子指纹
  - raw manifest `uses-library` field drift（如 `uses-library:org.apache.http.legacy#required`）
  - raw manifest `uses-native-library` field drift（如 `uses-native-library:com.example.sec#required`）
  - raw manifest `queries` package/provider/intent 子指纹
  - raw manifest `queries` package name / provider authorities 子指纹
  - raw manifest `queries intent` action/category/data 及 data scheme/authority/path/mimeType 子指纹
  - normalized manifest `queries` package/provider/intent semantics fingerprint
  - raw manifest `application` 组合语义 fingerprint
  - raw manifest `application` security semantics fingerprint（allowBackup/backupAgent/dataExtractionRules/networkSecurityConfig/usesCleartextTraffic 等）
  - raw manifest `application` runtime semantics fingerprint（name/appComponentFactory/hasCode/hardwareAccelerated/largeHeap/localeConfig/testOnly）
  - raw manifest `application` 字段漂移（如 `usesCleartextTraffic` / `networkSecurityConfig` / `extractNativeLibs` / `allowBackup` / `debuggable` / `fullBackupContent` / `dataExtractionRules` / `requestLegacyExternalStorage`）
  - provider field drift（`grantUriPermissions` / `multiprocess` / `initOrder`）
  - raw manifest meta-data entry / semantics fingerprint
  - 运行时 manifest meta-data 类型 / 值 hash
  - 运行时 manifest meta-data 值

#### 下一步必须补齐

- dex section / method-level finer-grained hashing
- split APK 渠道白名单与动态特征
- 关键 native 导出符号 hash / symbol graph
- manifest component / permission 更细粒度语义漂移（剩余 intent-filter / manifest 原始 grant-uri-permission 标签）

#### 参考项目

- [mukeshsolanki/Android-Tamper-Detector](https://github.com/mukeshsolanki/Android-Tamper-Detector)
- [tepikin/AndroidTamperingProtection](https://github.com/tepikin/AndroidTamperingProtection)
- [muhammedalikcb/securecheck](https://github.com/muhammedalikcb/securecheck)

---

### 4.7 Unidbg / Native 仿真环境

#### 已实现

- `CNTFRQ_EL0 == 0`
- `CNTVCT_EL0` 进度异常
- wall clock / virtual timer skew
- parent process 非 `zygote`
- `/proc/cpuinfo` 为空或字段畸形

#### 建议补齐

- `getauxval(AT_HWCAP)` / `AT_HWCAP2`
- JNI / `ActivityThread` / `Looper` 一致性
- `clock_gettime` 多源对比
- syscall coverage probe
- `/proc/self/exe`
- `dl_iterate_phdr` 自身一致性
- mmap/page size 行为异常

#### 参考项目

- [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg)
- [JingMatrix/Demo](https://github.com/JingMatrix/Demo)
- [apkunpacker/MagiskDetection](https://github.com/apkunpacker/MagiskDetection)

---

## 5. 建议的代码模块规划

| 优先级 | 建议模块 | 目标文件 |
|---|---|---|
| P0 | Tamper 完整性校验正式版 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/tamper_detector.cpp` + `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/AppIntegrity.kt` |
| P0 | Debug 独立模块 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/debug_detector.cpp` |
| P0 | 可疑 app/管理器检测 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/SuspiciousApps.kt` |
| P1 | Hook/GOT/PLT/pipe/thread 检测 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/hook_detector.cpp` |
| P1 | Zygisk 专项检测 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/zygisk_detector.cpp` |
| P1 | Virtual env / 多开检测 | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/VirtualEnv.kt` |
| P2 | Boot integrity / Verified Boot | `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/boot_integrity_detector.cpp` |

---

## 6. 近期实现优先级建议

### P0

1. 补齐 tamper 正式版：
   - 证书 allowlist
   - APK / SO hash
   - installer allowlist
2. 把 debug 从 injection 里拆出独立事件域
3. 增加可疑包名/管理器检测
4. 增加 Frida thread/pipe/socket 检测

### P1

1. Zygisk 专项检测
2. LSPatch / classloader / stacktrace 异常
3. VirtualApp / 多开容器检测
4. mem-disk compare / GOT-PLT hook

### P2

1. Unidbg 深化
2. ART method / inline hook
3. Verified Boot / SELinux
4. 行为型模拟器信号

---

## 7. 结论

Leona 当前最有差异化的点在：

- native-first 检测路径
- BoxId 服务端裁决架构
- ARM64 Frida trampoline 特征
- Unidbg 定时器一致性检测

当前最需要补齐的工程短板在：

- tamper / repack / 签名完整性
- debug 独立模块
- 可疑 app / 管理器检测
- Frida 非特征名路径（thread / pipe / socket）覆盖

这份矩阵应作为后续 SDK 与服务端风险聚合的事件基线。
