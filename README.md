# UNONE & KNONE

### Introduction

* [中文说明](https://github.com/BlackINT3/none/blob/master/doc/README-zh.md)

UNONE and KNONE is a couple of open source c++ base library that makes it easy to develop software on Windows. It aimmed at programming, reversing, diving into Windows internal, and evolving into reliable and maintainable project.

### Architecture

![image](doc/arch/none-arch.png)

* Str - String wrapper
* Os - System environment
* Ps - Process and Thread utility
* Fs - File and Directory utility
* Mm - Memory and Section
* Ob - Object utility
* Se - Security and Privilege
* Tm - Time utility
* Pe - PE Parser
* Net - Network utility
* Reg - Registry
* Int - Internal features
* Native - Windows Native structures, types, undocument API and more
* Plugins - 3rd-library and wrapper and unone-based componments

### How to use ?
Use nuget package
* Install by disk: Open Visual Studio console (eg: View - Other Windows - Package Manager Conosle, type in Install-Package C:\vs2015-unone.1.0.0.nupkg)
* Install by server: Set Nuget sources url (Tools - Options - Nuget Package Manager - Package Sources), and right click on project - Manage Nuget Packages - Browse package, just install it.
* Uninstall: use command Uninstall-Package, eg: Uninstall-Package vs2015-unone, also be opposite to upon.
* BTW: Nuget addons must be installed manualy in Visual Studio 2010.

Use libs or dlls
* Include headers and libs/dlls, then build it.
 
### Who used ?
  * [OpenArk](https://github.com/BlackINT3/OpenArk)
  * more in future...

### Distributions
* Binaray (lib/dll/package)
  * static lib 32/64 bit (UNONE)
  * dynamic lib 32/64 bit (UNONE/KNONE)
  * dynamic dll 32/64 bit (UNONE)
  * .nupkg Nuget Package (UNONE/KNONE)
* Package Manager
  * [Nuget](https://docs.microsoft.com/en-us/nuget/) - Nuget Core
  * [CoApp](http://coapp.org/)  - Nuget package build toolkit
  * [Klondike](https://github.com/chriseldredge/Klondike) - Nuget package web server
* Supported Compiler
  * Visual Studio 2010 (vc100)
  * Visual Studio 2012 (vc110)
  * Visual Studio 2013 (vc120)
  * Visual Studio 2015 (vc140)
  * Visual Studio 2017 (vc141)
  * Visual Studio 2019 (vc142)  


### Contributing
  * Issues and Push request is welcome.