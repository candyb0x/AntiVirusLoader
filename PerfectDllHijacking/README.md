内容来自：https://github.com/ElliotKillick/LdrLockLiberator/tree/main

在解决方案资源管理器窗口中选择当前的 Visual Studio 项目，然后在菜单栏中导航至`项目 > 属性 `。从顶部的下拉`配置`菜单中，选择`所有配置`和`所有平台 `。现在，转到`链接器 > 输入 `，然后添加到`附加依赖项 `：`ntdll.lib`。