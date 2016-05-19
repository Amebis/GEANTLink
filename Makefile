#
#    Copyright 1991-2016 Amebis
#    Copyright 2016 GÉANT
#
#    This file is part of GEANTLink.
#
#    GEANTLink is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    GEANTLink is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with GEANTLink. If not, see <http://www.gnu.org/licenses/>.
#

PRODUCT_NAME=GEANTLink
OUTPUT_DIR=output
#PUBLISH_DIR=\\amebis.doma\Splet\WWW\Apache\www.amebis.si-prenos\$(PRODUCT_NAME)
PUBLISH_DIR=C:\Users\Simon\ownCloud\GÉANT\$(PRODUCT_NAME)

!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
PLAT=x64
REG_FLAGS=/f /reg:64
REG_FLAGS32=/f /reg:32
!ELSE
PLAT=Win32
REG_FLAGS=/f
!ENDIF


All ::

Clean ::
	cd "MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean
	cd "$(MAKEDIR)"
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=Win32 CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=Win32 CFG=Debug
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=x64   CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=x64   CFG=Debug
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=Win32 CFG=Release
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=Win32 CFG=Debug
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=x64   CFG=Release
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=x64   CFG=Debug
	cd "$(MAKEDIR)"
	devenv.com "VS10Solution.sln" /clean "Release|Win32"
	devenv.com "VS10Solution.sln" /clean "Debug|Win32"
	devenv.com "VS10Solution.sln" /clean "Release|x64"
	devenv.com "VS10Solution.sln" /clean "Debug|x64"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi"

!IFNDEF HAS_VERSION

######################################################################
# 1st Phase
# - Version info parsing
######################################################################

All \
Setup \
SetupDebug \
Register \
Unregister \
StopServices \
StartServices \
Publish :: "MSI\MSIBuild\Version\Version.mak"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) HAS_VERSION=1 $@

"MSI\MSIBuild\Version\Version.mak" ::
	cd "MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Version
	cd "$(MAKEDIR)"

GenRSAKeypair :: \
	"include\KeyPrivate.bin" \
	"include\KeyPublic.bin"

"include\KeyPrivate.bin" :
	if exist $@ del /f /q $@
	if exist "$(@:"=).tmp" del /f /q "$(@:"=).tmp"
	openssl.exe genrsa 2048 | openssl.exe rsa -inform PEM -outform DER -out "$(@:"=).tmp"
	move /y "$(@:"=).tmp" $@ > NUL

"include\KeyPublic.bin" : "include\KeyPrivate.bin"
	if exist $@ del /f /q $@
	if exist "$(@:"=).tmp" del /f /q "$(@:"=).tmp"
	openssl.exe rsa -in $** -inform DER -outform DER -out "$(@:"=).tmp" -pubout
	move /y "$(@:"=).tmp" $@ > NUL

!ELSE

######################################################################
# 2nd Phase
# - The version is known, do the rest.
######################################################################

!INCLUDE "MSI\MSIBuild\Version\Version.mak"
!INCLUDE "include\MSIBuildCfg.mak"

PUBLISH_PACKAGE_DIR=$(PUBLISH_DIR)\$(MSIBUILD_VERSION_STR)
PUBLISH_PACKAGE_URL=http://www.amebis.si/prenos/$(PRODUCT_NAME)/$(MSIBUILD_VERSION_STR)

REDIST_EN_WIN32="$(PUBLISH_PACKAGE_DIR)\$(PRODUCT_NAME)32.msi"
REDIST_EN_X64="$(PUBLISH_PACKAGE_DIR)\$(PRODUCT_NAME)64.msi"
#REDIST_SL_WIN32="$(PUBLISH_PACKAGE_DIR)\$(PRODUCT_NAME)Sl32.msi"
#REDIST_SL_X64="$(PUBLISH_PACKAGE_DIR)\$(PRODUCT_NAME)Sl64.msi"


######################################################################
# Main targets
######################################################################

All :: \
	Setup

Setup :: \
	"$(OUTPUT_DIR)\Setup" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi"

SetupDebug :: \
	"$(OUTPUT_DIR)\Setup" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi"

Register :: \
	StopServices \
	RegisterDLLs \
	StartServices \
#	RegisterShortcuts

Unregister :: \
#	UnregisterShortcuts \
	StopServices \
	UnregisterDLLs \
	StartServices

StartServices ::
	cmd.exe /c <<"$(TEMP)\start_EapHost.bat"
@echo off
net.exe start EapHost
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP
# Enable dot3svc service (Wired AutoConfig) and start it
	sc.exe config dot3svc start= auto
	cmd.exe /c <<"$(TEMP)\start_dot3svc.bat"
@echo off
net.exe start dot3svc
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP
# Enable Wlansvc service (WLAN AutoConfig) and start it
	sc.exe config Wlansvc start= auto
	cmd.exe /c <<"$(TEMP)\start_Wlansvc.bat"
@echo off
net.exe start Wlansvc
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP

StopServices ::
	-net.exe stop Wlansvc
	-net.exe stop dot3svc
	-net.exe stop EapHost

RegisterDLLs :: \
	"$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll"
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532"    /ve                           /t REG_SZ    /d "$(PRODUCT_NAME)"                                        /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21" /v "PeerDllPath"              /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll"     /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21" /v "PeerFriendlyName"         /t REG_SZ    /d "@$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll,-1" /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21" /v "PeerInvokePasswordDialog" /t REG_DWORD /d 0                                                        /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21" /v "PeerInvokeUsernameDialog" /t REG_DWORD /d 0                                                        /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21" /v "Properties"               /t REG_DWORD /d 389871807                                                /f > NUL

UnregisterDLLs ::
	-reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532" /f > NUL

#RegisterShortcuts :: \
#	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)" \
#	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)\$(PRODUCT_NAME).lnk"
#
#UnregisterShortcuts ::
#	-if exist "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)" rd /s /q "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)"

Publish :: \
	"$(PUBLISH_PACKAGE_DIR)" \
	$(REDIST_EN_WIN32) \
	$(REDIST_EN_X64) \
	"$(PUBLISH_PACKAGE_DIR)\CredWrite.exe" \
#	$(REDIST_SL_WIN32) \
#	$(REDIST_SL_X64)


######################################################################
# Folder creation
######################################################################

"$(OUTPUT_DIR)" \
"$(OUTPUT_DIR)\Setup" \
"$(PUBLISH_DIR)" \
"$(PUBLISH_PACKAGE_DIR)" \
"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)" :
	if not exist $@ md $@

"$(OUTPUT_DIR)\Setup" : "$(OUTPUT_DIR)"

"$(PUBLISH_PACKAGE_DIR)" : "$(PUBLISH_DIR)"


######################################################################
# File copy
######################################################################

"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi" \
$(REDIST_EN_WIN32) : "$(OUTPUT_DIR)\$(PRODUCT_NAME)32.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi" : "$(OUTPUT_DIR)\$(PRODUCT_NAME)32D.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi" \
$(REDIST_EN_X64) : "$(OUTPUT_DIR)\$(PRODUCT_NAME)64.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi" : "$(OUTPUT_DIR)\$(PRODUCT_NAME)64D.3.msi"
	copy /y $** $@ > NUL

#"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi" \
#$(REDIST_SL_WIN32) : "$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32.3.msi"
#	copy /y $** $@ > NUL
#
#"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi" : "$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32D.3.msi"
#	copy /y $** $@ > NUL
#
#"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi" \
#$(REDIST_SL_X64) : "$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64.3.msi"
#	copy /y $** $@ > NUL
#
#"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi" : "$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64D.3.msi"
#	copy /y $** $@ > NUL

"$(PUBLISH_PACKAGE_DIR)\CredWrite.exe" : "$(OUTPUT_DIR)\Win32.Release\CredWrite.exe"
	copy /y $** $@ > NUL


######################################################################
# Shortcut creation
######################################################################

#"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(PRODUCT_NAME)\$(PRODUCT_NAME).lnk" : "$(OUTPUT_DIR)\$(PLAT).Debug\$(PRODUCT_NAME).exe"
#	cscript.exe "bin\MkLnk.wsf" //Nologo $@ "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(PRODUCT_NAME).exe"


######################################################################
# Building
######################################################################

"$(OUTPUT_DIR)\Win32.Release\CredWrite.exe" \
"$(OUTPUT_DIR)\Win32.Release\EAPMethodEvents.dll" \
"$(OUTPUT_DIR)\Win32.Release\EAPTTLS.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)32.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32.3.msi" \
::
	devenv.com "VS10Solution.sln" /build "Release|Win32"

"$(OUTPUT_DIR)\Win32.Debug\CredWrite.exe" \
"$(OUTPUT_DIR)\Win32.Debug\EAPMethodEvents.dll" \
"$(OUTPUT_DIR)\Win32.Debug\EAPTTLS.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)32D.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32D.3.msi"
::
	devenv.com "VS10Solution.sln" /build "Debug|Win32"

"$(OUTPUT_DIR)\x64.Release\CredWrite.exe" \
"$(OUTPUT_DIR)\x64.Release\EAPMethodEvents.dll" \
"$(OUTPUT_DIR)\x64.Release\EAPTTLS.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)64.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64.3.msi"
::
	devenv.com "VS10Solution.sln" /build "Release|x64"

"$(OUTPUT_DIR)\x64.Debug\CredWrite.exe" \
"$(OUTPUT_DIR)\x64.Debug\EAPMethodEvents.dll" \
"$(OUTPUT_DIR)\x64.Debug\EAPTTLS.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)64D.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64D.3.msi"
::
	devenv.com "VS10Solution.sln" /build "Debug|x64"

"$(OUTPUT_DIR)\$(PRODUCT_NAME)32.3.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=Win32 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\$(PRODUCT_NAME)32D.3.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=Win32 CFG=Debug
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\$(PRODUCT_NAME)64.3.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=x64 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\$(PRODUCT_NAME)64D.3.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=x64 CFG=Debug
	cd "$(MAKEDIR)"

#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32.3.msi" ::
#	cd "MSI\Base"
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=Win32 CFG=Release
#	cd "$(MAKEDIR)"
#
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32D.3.msi" ::
#	cd "MSI\Base"
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=Win32 CFG=Debug
#	cd "$(MAKEDIR)"
#
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64.3.msi" ::
#	cd "MSI\Base"
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=x64 CFG=Release
#	cd "$(MAKEDIR)"
#
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64D.3.msi" ::
#	cd "MSI\Base"
#	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=x64 CFG=Debug
#	cd "$(MAKEDIR)"

!ENDIF
