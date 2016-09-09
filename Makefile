#
#    Copyright 1991-2016 Amebis
#    Copyright 2016 GÉANT
#
#    This file is part of GÉANTLink.
#
#    GÉANTLink is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    GÉANTLink is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
#

PRODUCT_NAME=GEANTLink
OUTPUT_DIR=output

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
	-if exist "$(OUTPUT_DIR)\locale\ca_ES\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\ca_ES\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\cs_CZ\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\cs_CZ\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\de_DE\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\de_DE\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\el_GR\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\el_GR\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\es_ES\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\es_ES\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\eu_ES\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\eu_ES\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\fi_FI\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\fi_FI\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\fr_CA\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\fr_CA\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\fr_FR\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\fr_FR\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\gl_ES\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\gl_ES\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\hu_HU\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\hu_HU\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\it_IT\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\it_IT\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\lt_LT\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\lt_LT\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\nb_NO\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\nb_NO\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\nl_NL\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\nl_NL\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\pl_PL\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\pl_PL\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\pt_PT\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\pt_PT\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\ru_RU\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\ru_RU\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\sk_SK\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\sk_SK\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\sl_SI\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\sl_SI\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\sv_SE\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\sv_SE\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\tr_TR\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\tr_TR\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\locale\vi_VN\wxstd.mo"        del /f /q "$(OUTPUT_DIR)\locale\vi_VN\wxstd.mo"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64.msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64.msi"
#	-if exist "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\CredWrite.exe"          del /f /q "$(OUTPUT_DIR)\Setup\CredWrite.exe"
	-if exist "$(OUTPUT_DIR)\Setup\MsiUseFeature.exe"      del /f /q "$(OUTPUT_DIR)\Setup\MsiUseFeature.exe"
	-if exist "$(OUTPUT_DIR)\Setup\WLANManager.exe"        del /f /q "$(OUTPUT_DIR)\Setup\WLANManager.exe"

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
Localization \
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

PUBLISH_PACKAGE_DIR=..\$(PRODUCT_NAME)-dist
#PUBLISH_PACKAGE_DIR=..\$(PRODUCT_NAME)-dist\$(MSIBUILD_VERSION_STR)
#PUBLISH_PACKAGE_URL=http://www.amebis.si/prenos/$(PRODUCT_NAME)/$(MSIBUILD_VERSION_STR)

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
	"$(OUTPUT_DIR)\Setup\CredWrite.exe" \
	"$(OUTPUT_DIR)\Setup\MsiUseFeature.exe" \
	"$(OUTPUT_DIR)\Setup\WLANManager.exe"

SetupDebug :: \
	"$(OUTPUT_DIR)\Setup" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)32D.msi" \
	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)64D.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl32D.msi" \
#	"$(OUTPUT_DIR)\Setup\$(PRODUCT_NAME)Sl64D.msi"

Register :: \
	StopServices \
	Localization \
	RegisterSettings \
	RegisterDLLs \
	StartServices \
	RegisterShortcuts

Unregister :: \
	UnregisterShortcuts \
	StopServices \
	UnregisterDLLs \
	UnregisterSettings \
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

RegisterSettings ::
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" /t REG_SZ /d "$(MAKEDIR)\$(OUTPUT_DIR)\locale" $(REG_FLAGS) > NUL
!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" /t REG_SZ /d "$(MAKEDIR)\$(OUTPUT_DIR)\locale" $(REG_FLAGS32) > NUL
!ENDIF

UnregisterSettings ::
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" $(REG_FLAGS) > NUL
!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" $(REG_FLAGS32) > NUL
!ENDIF

RegisterDLLs :: \
	"$(OUTPUT_DIR)\$(PLAT).Debug\Events.dll" \
	"$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll" \
	"$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLSUI.dll"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{3f65af01-ce8f-4c7d-990b-673b244aac7b}" /ve                           /t REG_SZ    /d "$(MSIBUILD_PRODUCT_NAME)-Events"                        /f > NUL
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{3f65af01-ce8f-4c7d-990b-673b244aac7b}" /v "MessageFileName"          /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\Events.dll"      /f > NUL
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{3f65af01-ce8f-4c7d-990b-673b244aac7b}" /v "ResourceFileName"         /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\Events.dll"      /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532"                                            /ve                           /t REG_SZ    /d "$(MSIBUILD_PRODUCT_NAME)"                               /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerDllPath"              /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll"     /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerConfigUIPath"         /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLSUI.dll"   /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerIdentityPath"         /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLSUI.dll"   /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerInteractiveUIPath"    /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLSUI.dll"   /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerFriendlyName"         /t REG_SZ    /d "@$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EAPTTLS.dll,-1" /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerInvokePasswordDialog" /t REG_DWORD /d 0                                                        /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "PeerInvokeUsernameDialog" /t REG_DWORD /d 0                                                        /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21"                                         /v "Properties"               /t REG_DWORD /d 389871807                                                /f > NUL

UnregisterDLLs ::
	-reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\67532" /f > NUL

RegisterShortcuts :: \
	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" \
	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)\$(MSIBUILD_PRODUCT_NAME) Event Monitor.lnk"

UnregisterShortcuts ::
	-if exist "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" rd /s /q "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)"

Publish :: \
	"$(PUBLISH_PACKAGE_DIR)" \
	$(REDIST_EN_WIN32) \
	$(REDIST_EN_X64) \
	"$(PUBLISH_PACKAGE_DIR)\CredWrite.exe" \
	"$(PUBLISH_PACKAGE_DIR)\MsiUseFeature.exe" \
	"$(PUBLISH_PACKAGE_DIR)\WLANManager.exe" \
#	$(REDIST_SL_WIN32) \
#	$(REDIST_SL_X64)

Localization :: \
	"$(OUTPUT_DIR)\locale\ca_ES\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\cs_CZ\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\de_DE\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\el_GR\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\es_ES\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\eu_ES\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\fi_FI\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\fr_CA\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\fr_FR\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\gl_ES\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\hu_HU\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\it_IT\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\lt_LT\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\nb_NO\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\nl_NL\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\pl_PL\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\pt_PT\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\ru_RU\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\sk_SK\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\sl_SI\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\sv_SE\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\tr_TR\wxstd.mo" \
	"$(OUTPUT_DIR)\locale\vi_VN\wxstd.mo"


######################################################################
# Folder creation
######################################################################

"$(OUTPUT_DIR)" \
"$(OUTPUT_DIR)\Setup" \
"$(PUBLISH_PACKAGE_DIR)" \
"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" :
	if not exist $@ md $@

"$(OUTPUT_DIR)\Setup" : "$(OUTPUT_DIR)"


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

"$(OUTPUT_DIR)\Setup\CredWrite.exe" \
"$(PUBLISH_PACKAGE_DIR)\CredWrite.exe" : "$(OUTPUT_DIR)\Win32.Release\CredWrite.exe"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\MsiUseFeature.exe" \
"$(PUBLISH_PACKAGE_DIR)\MsiUseFeature.exe" : "$(OUTPUT_DIR)\Win32.Release\MsiUseFeature.exe"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\WLANManager.exe" \
"$(PUBLISH_PACKAGE_DIR)\WLANManager.exe" : "$(OUTPUT_DIR)\Win32.Release\WLANManager.exe"
	copy /y $** $@ > NUL


######################################################################
# Shortcut creation
######################################################################

"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)\$(MSIBUILD_PRODUCT_NAME) Event Monitor.lnk" : "$(OUTPUT_DIR)\$(PLAT).Debug\EventMonitor.exe"
	cscript.exe "bin\MkLnk.wsf" //Nologo $@ "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\EventMonitor.exe"


######################################################################
# Building
######################################################################

"$(OUTPUT_DIR)\locale\ca_ES\wxstd.mo" : "$(WXWIN)\locale\ca.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\cs_CZ\wxstd.mo" : "$(WXWIN)\locale\cs.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\de_DE\wxstd.mo" : "$(WXWIN)\locale\de.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\el_GR\wxstd.mo" : "$(WXWIN)\locale\el.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\es_ES\wxstd.mo" : "$(WXWIN)\locale\es.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\eu_ES\wxstd.mo" : "$(WXWIN)\locale\eu.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\fi_FI\wxstd.mo" : "$(WXWIN)\locale\fi.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\fr_CA\wxstd.mo" : "$(WXWIN)\locale\fr.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\fr_FR\wxstd.mo" : "$(WXWIN)\locale\fr.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\gl_ES\wxstd.mo" : "$(WXWIN)\locale\gl_ES.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\hu_HU\wxstd.mo" : "$(WXWIN)\locale\hu.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\it_IT\wxstd.mo" : "$(WXWIN)\locale\it.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\lt_LT\wxstd.mo" : "$(WXWIN)\locale\lt.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\nb_NO\wxstd.mo" : "$(WXWIN)\locale\nb.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\nl_NL\wxstd.mo" : "$(WXWIN)\locale\nl.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\pl_PL\wxstd.mo" : "$(WXWIN)\locale\pl.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\pt_PT\wxstd.mo" : "$(WXWIN)\locale\pt.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\ru_RU\wxstd.mo" : "$(WXWIN)\locale\ru.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\sk_SK\wxstd.mo" : "$(WXWIN)\locale\sk.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\sl_SI\wxstd.mo" : "$(WXWIN)\locale\sl.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\sv_SE\wxstd.mo" : "$(WXWIN)\locale\sv.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\tr_TR\wxstd.mo" : "$(WXWIN)\locale\tr.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\locale\vi_VN\wxstd.mo" : "$(WXWIN)\locale\vi.po"
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**

"$(OUTPUT_DIR)\Win32.Release\CredWrite.exe" \
"$(OUTPUT_DIR)\Win32.Release\MsiUseFeature.exe" \
"$(OUTPUT_DIR)\Win32.Release\WLANManager.exe" \
"$(OUTPUT_DIR)\Win32.Release\Events.dll" \
"$(OUTPUT_DIR)\Win32.Release\EAPTTLS.dll" \
"$(OUTPUT_DIR)\Win32.Release\EAPTTLSUI.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)32.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32.3.msi" \
:: Localization
	devenv.com "VS10Solution.sln" /build "Release|Win32"

"$(OUTPUT_DIR)\Win32.Debug\CredWrite.exe" \
"$(OUTPUT_DIR)\Win32.Debug\MsiUseFeature.exe" \
"$(OUTPUT_DIR)\Win32.Debug\WLANManager.exe" \
"$(OUTPUT_DIR)\Win32.Debug\Events.dll" \
"$(OUTPUT_DIR)\Win32.Debug\EAPTTLS.dll" \
"$(OUTPUT_DIR)\Win32.Debug\EAPTTLSUI.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)32D.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl32D.3.msi"
:: Localization
	devenv.com "VS10Solution.sln" /build "Debug|Win32"

"$(OUTPUT_DIR)\x64.Release\CredWrite.exe" \
"$(OUTPUT_DIR)\x64.Release\MsiUseFeature.exe" \
"$(OUTPUT_DIR)\x64.Release\WLANManager.exe" \
"$(OUTPUT_DIR)\x64.Release\Events.dll" \
"$(OUTPUT_DIR)\x64.Release\EAPTTLS.dll" \
"$(OUTPUT_DIR)\x64.Release\EAPTTLSUI.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)64.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64.3.msi"
:: Localization
	devenv.com "VS10Solution.sln" /build "Release|x64"

"$(OUTPUT_DIR)\x64.Debug\CredWrite.exe" \
"$(OUTPUT_DIR)\x64.Debug\MsiUseFeature.exe" \
"$(OUTPUT_DIR)\x64.Debug\WLANManager.exe" \
"$(OUTPUT_DIR)\x64.Debug\Events.dll" \
"$(OUTPUT_DIR)\x64.Debug\EAPTTLS.dll" \
"$(OUTPUT_DIR)\x64.Debug\EAPTTLSUI.dll" \
"$(OUTPUT_DIR)\$(PRODUCT_NAME)64D.3.msi" \
#"$(OUTPUT_DIR)\$(PRODUCT_NAME)Sl64D.3.msi"
:: Localization
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
