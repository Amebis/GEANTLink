#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

Clean ::
	-if exist "output\locale\$(LANG)\wxstd.mo" del /f /q "output\locale\$(LANG)\wxstd.mo"


######################################################################
# Localization
######################################################################

Localization :: \
	"output\locale\$(LANG)" \
	"output\locale\$(LANG)\wxstd.mo"

!IF "$(LANG)" != "en_US"
LocalizationImport : \
	"EAPMethods\locale\$(LANG).po" \
	"EventMonitor\locale\$(LANG).po" \
	"lib\wxExtend\locale\$(LANG).po" \
	"MSI\Base\locale\$(LANG).po" \
	"MSI\MSIBuild\Core\locale\$(LANG).po" \
	"WLANManager\locale\$(LANG).po"
!ENDIF


######################################################################
# Folder creation
######################################################################

"output\locale\$(LANG)" :
	if not exist $@ md $@

"output\locale\$(LANG)" : "output\locale"


######################################################################
# Localization import from Transifex
######################################################################

!IF EXISTS("EAPMethods\locale\eapmethods_$(LANG).po")
"EAPMethods\locale\$(LANG).po" : "EAPMethods\locale\eapmethods_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("EAPMethods\locale\eapmethods_$(LANG_BASE).po")
"EAPMethods\locale\$(LANG).po" : "EAPMethods\locale\eapmethods_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF

!IF EXISTS("EventMonitor\locale\eventmonitor_$(LANG).po")
"EventMonitor\locale\$(LANG).po" : "EventMonitor\locale\eventmonitor_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("EventMonitor\locale\eventmonitor_$(LANG_BASE).po")
"EventMonitor\locale\$(LANG).po" : "EventMonitor\locale\eventmonitor_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF

!IF EXISTS("lib\wxExtend\locale\wxextend_$(LANG).po")
"lib\wxExtend\locale\$(LANG).po" : "lib\wxExtend\locale\wxextend_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("lib\wxExtend\locale\wxextend_$(LANG_BASE).po")
"lib\wxExtend\locale\$(LANG).po" : "lib\wxExtend\locale\wxextend_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF

!IF EXISTS("MSI\Base\locale\msibase_$(LANG).po")
"MSI\Base\locale\$(LANG).po" : "MSI\Base\locale\msibase_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("MSI\Base\locale\msibase_$(LANG_BASE).po")
"MSI\Base\locale\$(LANG).po" : "MSI\Base\locale\msibase_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF

!IF EXISTS("MSI\MSIBuild\Core\locale\core_$(LANG).po")
"MSI\MSIBuild\Core\locale\$(LANG).po" : "MSI\MSIBuild\Core\locale\core_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("MSI\MSIBuild\Core\locale\core_$(LANG_BASE).po")
"MSI\MSIBuild\Core\locale\$(LANG).po" : "MSI\MSIBuild\Core\locale\core_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF

!IF EXISTS("WLANManager\locale\wlanmanager_$(LANG).po")
"WLANManager\locale\$(LANG).po" : "WLANManager\locale\wlanmanager_$(LANG).po"
	copy /y $** $@ > NUL
!ELSEIF EXISTS("WLANManager\locale\wlanmanager_$(LANG_BASE).po")
"WLANManager\locale\$(LANG).po" : "WLANManager\locale\wlanmanager_$(LANG_BASE).po"
	copy /y $** $@ > NUL
!ENDIF


######################################################################
# Building
######################################################################

"output\locale\$(LANG)\wxstd.mo" : \
!IF EXISTS("$(WXWIN)\locale\$(LANG).po")
	"$(WXWIN)\locale\$(LANG).po"
!ELSEIF EXISTS("$(WXWIN)\locale\$(LANG_BASE).po")
	"$(WXWIN)\locale\$(LANG_BASE).po"
!ELSE
	"$(WXWIN)\locale\wxstd.pot"
!ENDIF
	msgfmt.exe --output-file=$@ --alignment=1 --endianness=little $**


######################################################################
# Platform-configuration Specific
######################################################################

PLAT=Win32
PLAT_SUFFIX=-x86

CFG=Release
CFG_SUFFIX=
!INCLUDE "MakefileLangPlatCfg.mak"

CFG=Debug
CFG_SUFFIX=D
!INCLUDE "MakefileLangPlatCfg.mak"

PLAT=x64
PLAT_SUFFIX=-x64

CFG=Release
CFG_SUFFIX=
!INCLUDE "MakefileLangPlatCfg.mak"

CFG=Debug
CFG_SUFFIX=D
!INCLUDE "MakefileLangPlatCfg.mak"

PLAT=ARM64
PLAT_SUFFIX=-ARM64

CFG=Release
CFG_SUFFIX=
!INCLUDE "MakefileLangPlatCfg.mak"

CFG=Debug
CFG_SUFFIX=D
!INCLUDE "MakefileLangPlatCfg.mak"
