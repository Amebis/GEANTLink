#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

CleanSetup ::
	-if exist "output\$(LANG).$(PLAT).$(CFG).msi" del /f /q "output\$(LANG).$(PLAT).$(CFG).msi"
	-if exist "output\$(LANG).$(PLAT).$(CFG).mst" del /f /q "output\$(LANG).$(PLAT).$(CFG).mst"

"output\$(LANG).$(PLAT).$(CFG).2.msi" ::
	cd "MSI\Base"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=$(LANG) PLAT=$(PLAT) CFG=$(CFG)
	cd "$(MAKEDIR)"

"output\$(LANG).$(PLAT).$(CFG).msi" : \
	"output\$(LANG).$(PLAT).$(CFG).2.msi" \
	"output\$(PLAT).$(CFG).inf"
	-if exist $@ del /f /q $@
	copy /y "output\$(LANG).$(PLAT).$(CFG).2.msi" "$(@:"=).tmp" > NUL
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:SetCAB //Nologo "$(@:"=).tmp" "output\$(PLAT).$(CFG).inf"
	"$(WINDOWSSDKVERBINPATH)x86\msiinfo.exe" "$(@:"=).tmp" /nologo /U 4
	move /y "$(@:"=).tmp" $@ > NUL

"output\$(LANG).$(PLAT).$(CFG).mst" : \
	"output\en_US.$(PLAT).$(CFG).msi" \
	"output\$(LANG).$(PLAT).$(CFG).msi"
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:MakeMST //Nologo "output\en_US.$(PLAT).$(CFG).msi" "output\$(LANG).$(PLAT).$(CFG).msi" $@
