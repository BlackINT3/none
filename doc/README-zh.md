# UNONE & KNONE

### 简介
* [英文说明](https://github.com/BlackINT3/none/blob/master/README.md)

UNONE和KNONE是一套开源的C++基础库，它使得Windows平台上的软件开发变得简单。我们的方向是程序开发、逆向工程和探索Windows内部原理，并向提升稳定性、可维护性的路线发展。

### 架构

![image](arch/none-arch.png)

* Str - 字符串操作封装
* Os - 系统环境相关
* Ps - 进程、线程相关工具库
* Fs - 文件、目录相关
* Mm - 内存、Section相关操作
* Ob - 对象工具库
* Se - 安全相关函数
* Tm - 时间工具库
* Pe - PE解析器相关操作
* Net - 网络工具库
* Reg - 注册表相关
* Int - 内部接口
* Native - Windows Native 结构体、类型定义和一些未公开的API原型和操作
* Plugins - 第三方库封装以及基于UNONE开发的一些代码库

### 如何使用？
使用Nuget包
* 通过本地文件安装：打开VS控制台（例如：视图 - 其它窗口 - 程序包管理器控制台，输入:Install-Package C:\vs2015-unone.1.0.0.nupkg），执行即可。
* 通过服务端安装：设置Nuget源（工具 - 选项 - Nuget包管理器 - 程序包源），在工程管理器右键 - 管理Nuget程序包，找到相应的包安装即可。
* 卸载：使用命令Uninstall-Package，例如 Uninstall-Package vs2015-unone。当然也可和上面的方式来卸载。
* 注意：VS2010上要手动安装Nuget插件

使用静态库或DLL
* 包含头文件和静态库/DLL，编译即可。
 
### 哪些项目在用 ?
  * [OpenArk](https://github.com/BlackINT3/OpenArk) - 一款开源的ARK工具
  * 期待更多...

### 发布
* 二进制 (静态库/DLL/包)
  * 32位、64位静态库 (UNONE)
  * 32位、64位动态CRT库 (UNONE/KNONE)
  * 32位、64位DLL (UNONE)
  * .nupkg Nuget程序包 (UNONE/KNONE)
* 包管理器
  * [Nuget](https://docs.microsoft.com/en-us/nuget/) - Nuget核心程序
  * [CoApp](http://coapp.org/) - Nuget包制作程序
  * [Klondike](https://github.com/chriseldredge/Klondike) - Nuget包服务器
* 支持的编译器
  * Visual Studio 2010 (vc100)
  * Visual Studio 2012 (vc110)
  * Visual Studio 2013 (vc120)
  * Visual Studio 2015 (vc140)
  * Visual Studio 2017 (vc141)
  * Visual Studio 2019 (vc142)  


### 参与项目
  * 欢迎提交Issue和PR