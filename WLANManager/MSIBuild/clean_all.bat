@echo off
nmake.exe /ls Clean LANG=en_US CFG=Debug   PLAT=Win32
nmake.exe /ls Clean LANG=en_US CFG=Debug   PLAT=x64
nmake.exe /ls Clean LANG=en_US CFG=Debug   PLAT=ARM64
nmake.exe /ls Clean LANG=en_US CFG=Release PLAT=Win32
nmake.exe /ls Clean LANG=en_US CFG=Release PLAT=x64
nmake.exe /ls Clean LANG=en_US CFG=Release PLAT=ARM64
