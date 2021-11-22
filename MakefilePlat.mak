#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2020 Amebis
#    Copyright © 2016 GÉANT

CleanSetup ::
	-if exist "$(OUTPUT_DIR)\Setup\WLANManager$(PLAT_SUFFIX).exe" del /f /q "$(OUTPUT_DIR)\Setup\WLANManager$(PLAT_SUFFIX).exe"
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Clean /p:Platform=$(PLAT) /p:Configuration=Release
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Clean /p:Platform=$(PLAT) /p:Configuration=Debug


######################################################################
# Setup
######################################################################

Setup :: \
	"$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX).msi" \
	"$(OUTPUT_DIR)\Setup\WLANManager$(PLAT_SUFFIX).exe"

SetupDebug :: \
	"$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX)D.msi"

SetupCompile ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Build /p:Platform=$(PLAT) /p:Configuration=Release

SetupDebugCompile ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Build /p:Platform=$(PLAT) /p:Configuration=Debug


######################################################################
# Publishing
######################################################################

Publish :: \
	"$(PUBLISH_PACKAGE_DIR)\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX).msi" \
	"$(PUBLISH_PACKAGE_DIR)\WLANManager$(PLAT_SUFFIX).exe"


######################################################################
# File copy
######################################################################

"$(PUBLISH_PACKAGE_DIR)\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX).msi" : "$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX).msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\WLANManager$(PLAT_SUFFIX).exe" \
"$(PUBLISH_PACKAGE_DIR)\WLANManager$(PLAT_SUFFIX).exe" : "$(OUTPUT_DIR)\$(PLAT).Release\WLANManager.exe"
	copy /y $** $@ > NUL


######################################################################
# Configuration Specific
######################################################################

CFG=Release
CFG_SUFFIX=
!INCLUDE "MakefilePlatCfg.mak"

CFG=Debug
CFG_SUFFIX=D
!INCLUDE "MakefilePlatCfg.mak"
