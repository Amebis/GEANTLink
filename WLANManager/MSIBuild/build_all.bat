@echo off
nmake.exe /ls All LANG=en_US CFG=Debug   PLAT=Win32
nmake.exe /ls All LANG=en_US CFG=Debug   PLAT=x64
nmake.exe /ls All LANG=en_US CFG=Debug   PLAT=ARM64
nmake.exe /ls All LANG=en_US CFG=Release PLAT=Win32
nmake.exe /ls All LANG=en_US CFG=Release PLAT=x64
nmake.exe /ls All LANG=en_US CFG=Release PLAT=ARM64
