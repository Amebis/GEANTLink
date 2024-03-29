#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

CleanSetup ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Clean /p:Platform=$(PLAT) /p:Configuration=Release
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Clean /p:Platform=$(PLAT) /p:Configuration=Debug


######################################################################
# Setup
######################################################################

Setup :: \
	"output\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX).msi"

SetupDebug :: \
	"output\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX)D.msi"

SetupCompile ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Build /p:Platform=$(PLAT) /p:Configuration=Release

SetupDebugCompile ::
	msbuild.exe $(MSBUILDFLAGS) "$(MSIBUILD_PRODUCT_NAME_ID).sln" /t:Build /p:Platform=$(PLAT) /p:Configuration=Debug

"output\Setup\PDB.zip" : output\$(PLAT).Release\*.pdb


######################################################################
# Configuration Specific
######################################################################

CFG=Release
CFG_SUFFIX=
!INCLUDE "MakefilePlatCfg.mak"

CFG=Debug
CFG_SUFFIX=D
!INCLUDE "MakefilePlatCfg.mak"
