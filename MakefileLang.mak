#
#    Copyright 1991-2020 Amebis
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

Clean ::
	-if exist "$(OUTPUT_DIR)\locale\$(LANG)\wxstd.mo" del /f /q "$(OUTPUT_DIR)\locale\$(LANG)\wxstd.mo"


######################################################################
# Localization
######################################################################

Localization :: \
	"$(OUTPUT_DIR)\locale\$(LANG)" \
	"$(OUTPUT_DIR)\locale\$(LANG)\wxstd.mo"

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

"$(OUTPUT_DIR)\locale\$(LANG)" :
	if not exist $@ md $@

"$(OUTPUT_DIR)\locale\$(LANG)" : "$(OUTPUT_DIR)\locale"


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

"$(OUTPUT_DIR)\locale\$(LANG)\wxstd.mo" : \
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
