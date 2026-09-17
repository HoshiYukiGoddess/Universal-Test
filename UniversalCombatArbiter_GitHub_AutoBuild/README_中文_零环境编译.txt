UniversalCombatArbiter：零本地开发环境编译说明
================================================

你不需要安装 Visual Studio、CMake、vcpkg，也不需要会 C++。
编译交给 GitHub 的 Windows 云端机器完成。

你需要：
1. 一个 GitHub 账号。
2. 能正常运行 Skyrim 1.6.1170 + SKSE + Address Library 的现有环境。

最简单操作：

A. 在 GitHub 新建一个空仓库
   名字随便，例如 UniversalCombatArbiter-Test。
   Public / Private 都可以。

B. 把本压缩包解压后的“所有内容”上传到仓库根目录
   注意 .github 文件夹也必须上传。
   最终 GitHub 页面根目录应该能看到：
     .github/
     config/
     src/
     CMakeLists.txt

C. 打开仓库上方的 Actions
   左侧选择：Build UniversalCombatArbiter DLL
   点击右侧 Run workflow -> Run workflow。

D. 等待云端编译
   第一次可能较慢，因为会下载/构建 C++ 依赖。
   绿色对勾 = 编译成功。
   红叉 = 失败，把失败页面或日志截图/链接给 ChatGPT，不需要你自己读代码。

E. 下载 DLL
   点进成功的那次运行，页面底部 Artifacts 下载：
     UniversalCombatArbiter-1.6.1170-PoC
   解压后结构已经是：
     Data/SKSE/Plugins/UniversalCombatArbiter.dll
     Data/SKSE/Plugins/UniversalCombatArbiter.ini

F. 用 MO2 安装更安全
   把下载的 artifact 压缩成 zip，作为普通 Mod 加入 MO2。
   强烈建议单独测试 Profile + 测试存档。

第一次测试配置：
   打开 UniversalCombatArbiter.ini
   建议先设：
     bPlayerHasAbsoluteDamage=1
     bTerminalDeath=0

   然后进入游戏，对 Vilushina 使用无附魔普通武器轻击。
   不需要技能、不需要法术、不需要快捷键。

   第一轮只观察：
   原来只有 3~6 点的掉血，是否变成明显更高的正常伤害。

日志位置：
   Documents\My Games\Skyrim Special Edition\SKSE\UniversalCombatArbiter.log

安全说明：
- 这是未实机验证的底层 PoC，会改全局 Actor vtable。
- 第一次一定不要使用主存档。
- 如果启动即 CTD 或攻击时 CTD，把 Crash Logger 日志和
  UniversalCombatArbiter.log 一起发回即可。

版本：
- 编译使用 CommonLibSSE-NG v8.1.0。
- 目标为 SE/AE 多运行时插件，包含 Skyrim 1.6.1170。
- 游戏端仍需要正确版本的 SKSE 和 Address Library。
