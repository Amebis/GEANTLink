#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2020 Amebis
#    Copyright © 2016 GÉANT

CleanSetup ::
	-if exist "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).msi" del /f /q "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).msi"
	-if exist "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).mst" del /f /q "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).mst"

"$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).2.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=$(LANG) PLAT=$(PLAT) CFG=$(CFG)
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).msi" : \
	"$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\$(PLAT).$(CFG).inf"
	-if exist $@ del /f /q $@
	copy /y "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).2.msi" "$(@:"=).tmp" > NUL
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:SetCAB //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\$(PLAT).$(CFG).inf"
	"$(WINDOWSSDKVERBINPATH)x86\msiinfo.exe" "$(@:"=).tmp" /nologo /U 4
	move /y "$(@:"=).tmp" $@ > NUL

"$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).mst" : \
	"$(OUTPUT_DIR)\en_US.$(PLAT).$(CFG).msi" \
	"$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).msi"
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:MakeMST //Nologo "$(OUTPUT_DIR)\en_US.$(PLAT).$(CFG).msi" "$(OUTPUT_DIR)\$(LANG).$(PLAT).$(CFG).msi" $@
