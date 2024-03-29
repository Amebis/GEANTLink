#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

!INCLUDE "include\MSIBuildCfg.mak"

!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
PLAT=x64
REG_FLAGS=/f /reg:64
REG_FLAGS32=/f /reg:32
PROGRAM_FILES_32=C:\Program Files (x86)
!ELSEIF "$(PROCESSOR_ARCHITECTURE)" == "ARM64"
PLAT=ARM64
REG_FLAGS=/f /reg:64
REG_FLAGS32=/f /reg:32
PROGRAM_FILES_32=C:\Program Files (x86)
!ELSE
PLAT=Win32
REG_FLAGS=/f
PROGRAM_FILES_32=C:\Program Files
!ENDIF
MSBUILDFLAGS=/v:m /m


All ::

Clean :: \
	CleanSetup

CleanSetup ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean
	cd "$(MAKEDIR)\MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean
	cd "$(MAKEDIR)"
	-if exist "output\Setup\CredWrite.exe"     del /f /q "output\Setup\CredWrite.exe"
	-if exist "output\Setup\MsiUseFeature.exe" del /f /q "output\Setup\MsiUseFeature.exe"
	-if exist "output\Setup\PDB.zip"           del /f /q "output\Setup\PDB.zip"


######################################################################
# Version info parsing
######################################################################

SetupVersion ::
	cd "MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Version
	cd "$(MAKEDIR)"


######################################################################
# Default target
######################################################################

All :: \
	Setup


######################################################################
# Setup
######################################################################

Setup :: \
	Localization \
	SetupVersion \
	SetupCompile \
	"output\Setup" \
	"output\Setup\CredWrite.exe" \
	"output\Setup\MsiUseFeature.exe" \
	"output\Setup\PDB.zip"

SetupDebug :: \
	Localization \
	SetupVersion \
	SetupDebugCompile \
	"output\Setup"


######################################################################
# Registration
######################################################################

Register :: \
	StopServices \
	Localization \
	RegisterCompile \
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

RegisterCompile ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Build /p:Platform=$(PLAT) /p:Configuration=Debug

RegisterSettings ::
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "Language"                   /t REG_SZ /d "en_US"                    $(REG_FLAGS) > NUL
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" /t REG_SZ /d "$(MAKEDIR)\output\locale" $(REG_FLAGS) > NUL
!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64" || "$(PROCESSOR_ARCHITECTURE)" == "ARM64"
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "Language"                   /t REG_SZ /d "en_US"                    $(REG_FLAGS32) > NUL
	reg.exe add "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" /t REG_SZ /d "$(MAKEDIR)\output\locale" $(REG_FLAGS32) > NUL
!ENDIF

UnregisterSettings ::
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "Language"                   $(REG_FLAGS) > NUL
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" $(REG_FLAGS) > NUL
!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64" || "$(PROCESSOR_ARCHITECTURE)" == "ARM64"
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "Language"                   $(REG_FLAGS32) > NUL
	-reg.exe delete "HKLM\Software\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)" /v "LocalizationRepositoryPath" $(REG_FLAGS32) > NUL
!ENDIF

RegisterDLLs ::
#	wevtutil.exe im "lib\Events\res\EventsETW.man" /rf:"$(MAKEDIR)\output\$(PLAT).Debug\Events.dll" /mf:"$(MAKEDIR)\output\$(PLAT).Debug\Events.dll"
	regsvr32.exe /s "$(MAKEDIR)\output\$(PLAT).Debug\Events.dll"

UnregisterDLLs ::
	-reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)"                                             /f > NUL
	-reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)"                                   /f > NUL
	-reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational" /f > NUL
	-reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic"    /f > NUL
#	-wevtutil.exe um "lib\Events\res\EventsETW.man"

RegisterShortcuts :: \
	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" \
	"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)\$(MSIBUILD_PRODUCT_NAME) Event Monitor.lnk"

UnregisterShortcuts ::
	-if exist "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" rd /s /q "$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)"


######################################################################
# Folder creation
######################################################################

"output" \
"output\locale" \
"output\Setup" \
"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)" :
	if not exist $@ md $@

"output\locale" \
"output\Setup" : "output"


######################################################################
# File copy
######################################################################

"output\Setup\CredWrite.exe" : "output\Win32.Release\CredWrite.exe"
	copy /y $** $@ > NUL

"output\Setup\MsiUseFeature.exe" : "output\Win32.Release\MsiUseFeature.exe"
	copy /y $** $@ > NUL


######################################################################
# Shortcut creation
######################################################################

"$(PROGRAMDATA)\Microsoft\Windows\Start Menu\Programs\$(MSIBUILD_PRODUCT_NAME)\$(MSIBUILD_PRODUCT_NAME) Event Monitor.lnk" : "output\$(PLAT).Debug\EventMonitor.exe"
	cscript.exe "bin\MkLnk.wsf" //Nologo $@ "$(MAKEDIR)\output\$(PLAT).Debug\EventMonitor.exe"


######################################################################
# Building
######################################################################

"output\Setup\PDB.zip" :
	-if exist "$(@:"=).tmp" del /f /q "$(@:"=).tmp"
	zip.exe -9 "$(@:"=).tmp" $**
	move /y "$(@:"=).tmp" $@ > NUL


######################################################################
# EAP Module Specific
######################################################################

EAPMETHOD_TYPE=21
EAPMETHOD_NAME=EAP-TTLS
!INCLUDE "MakefileEAPMethod.mak"

######################################################################
# Platform Specific
######################################################################

PLAT=Win32
PLAT_SUFFIX=-x86
!INCLUDE "MakefilePlat.mak"

PLAT=x64
PLAT_SUFFIX=-x64
!INCLUDE "MakefilePlat.mak"

PLAT=ARM64
PLAT_SUFFIX=-ARM64
!INCLUDE "MakefilePlat.mak"


######################################################################
# Language Specific
######################################################################

LANG=ca_ES
LANG_BASE=ca
!INCLUDE "MakefileLang.mak"

LANG=de_DE
LANG_BASE=de
!INCLUDE "MakefileLang.mak"

LANG=el_GR
LANG_BASE=el
!INCLUDE "MakefileLang.mak"

LANG=en_US
LANG_BASE=en
!INCLUDE "MakefileLang.mak"

LANG=es_ES
LANG_BASE=es
!INCLUDE "MakefileLang.mak"

LANG=et_EE
LANG_BASE=et
!INCLUDE "MakefileLang.mak"

LANG=hr_HR
LANG_BASE=hr
!INCLUDE "MakefileLang.mak"

LANG=hu_HU
LANG_BASE=hu
!INCLUDE "MakefileLang.mak"

LANG=it_IT
LANG_BASE=it
!INCLUDE "MakefileLang.mak"

LANG=nb_NO
LANG_BASE=nb
!INCLUDE "MakefileLang.mak"

LANG=pl_PL
LANG_BASE=pl
!INCLUDE "MakefileLang.mak"

LANG=pt_PT
LANG_BASE=pt
!INCLUDE "MakefileLang.mak"

LANG=ro_RO
LANG_BASE=ro
!INCLUDE "MakefileLang.mak"

LANG=sl_SI
LANG_BASE=sl
!INCLUDE "MakefileLang.mak"

LANG=sr_RS
LANG_BASE=sr
!INCLUDE "MakefileLang.mak"

LANG=tr_TR
LANG_BASE=tr
!INCLUDE "MakefileLang.mak"
