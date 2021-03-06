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

CleanSetup ::
	-if exist "$(OUTPUT_DIR)\$(PLAT).$(CFG).ddf"  del /f /q "$(OUTPUT_DIR)\$(PLAT).$(CFG).ddf"
	-if exist "$(OUTPUT_DIR)\$(PLAT).$(CFG).cab"  del /f /q "$(OUTPUT_DIR)\$(PLAT).$(CFG).cab"
	-if exist "$(OUTPUT_DIR)\$(PLAT).$(CFG).inf"  del /f /q "$(OUTPUT_DIR)\$(PLAT).$(CFG).inf"
	-if exist "$(OUTPUT_DIR)\$(PLAT).$(CFG).rpt"  del /f /q "$(OUTPUT_DIR)\$(PLAT).$(CFG).rpt"
	-if exist "$(OUTPUT_DIR)\$(PLAT).$(CFG).msi"  del /f /q "$(OUTPUT_DIR)\$(PLAT).$(CFG).msi"
	-if exist "$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX)$(CFG_SUFFIX).msi" del /f /q "$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX)$(CFG_SUFFIX).msi"


######################################################################
# Building
######################################################################

"$(OUTPUT_DIR)\$(PLAT).$(CFG).ddf" : \
	"$(OUTPUT_DIR)\ca_ES.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\de_DE.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\el_GR.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\es_ES.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\et_EE.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\hr_HR.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\hu_HU.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\it_IT.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\nb_NO.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\pl_PL.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\pt_PT.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\ro_RO.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\sl_SI.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\sr_RS.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\tr_TR.$(PLAT).$(CFG).2.msi" \
	"$(OUTPUT_DIR)\en_US.$(PLAT).$(CFG).2.msi"
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:MakeDDF //Nologo "$(@:"=).tmp" $** /O:"$(OUTPUT_DIR)\$(PLAT).$(CFG)" /C:LZX
	move /y "$(@:"=).tmp" $@ > NUL

"$(OUTPUT_DIR)\$(PLAT).$(CFG).cab" \
"$(OUTPUT_DIR)\$(PLAT).$(CFG).inf" \
"$(OUTPUT_DIR)\$(PLAT).$(CFG).rpt" : "$(OUTPUT_DIR)\$(PLAT).$(CFG).ddf"
	makecab.exe /F $**

"$(OUTPUT_DIR)\$(PLAT).$(CFG).msi" : \
	"$(OUTPUT_DIR)\ca_ES.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\de_DE.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\el_GR.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\es_ES.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\et_EE.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\hr_HR.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\hu_HU.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\it_IT.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\nb_NO.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\pl_PL.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\pt_PT.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\ro_RO.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\sl_SI.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\sr_RS.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\tr_TR.$(PLAT).$(CFG).mst" \
	"$(OUTPUT_DIR)\en_US.$(PLAT).$(CFG).msi"
	-if exist $@ del /f /q $@
	-if exist "$(@:"=).tmp" del /f /q "$(@:"=).tmp"
	copy /y "$(OUTPUT_DIR)\en_US.$(PLAT).$(CFG).msi" "$(@:"=).tmp" > NUL
	attrib.exe -r "$(@:"=).tmp"
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\ca_ES.$(PLAT).$(CFG).mst" 1027 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\de_DE.$(PLAT).$(CFG).mst" 1031 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\el_GR.$(PLAT).$(CFG).mst" 1032 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\es_ES.$(PLAT).$(CFG).mst" 1034 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\et_EE.$(PLAT).$(CFG).mst" 1061 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\hr_HR.$(PLAT).$(CFG).mst" 1050 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\hu_HU.$(PLAT).$(CFG).mst" 1038 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\it_IT.$(PLAT).$(CFG).mst" 1040 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\nb_NO.$(PLAT).$(CFG).mst" 1044 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\pl_PL.$(PLAT).$(CFG).mst" 1045 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\pt_PT.$(PLAT).$(CFG).mst" 2070 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\ro_RO.$(PLAT).$(CFG).mst" 1048 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\sl_SI.$(PLAT).$(CFG).mst" 1060 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\sr_RS.$(PLAT).$(CFG).mst" 2074 /L
	cscript.exe "MSI\MSIBuild\MSI.wsf" //Job:AddStorage //Nologo "$(@:"=).tmp" "$(OUTPUT_DIR)\tr_TR.$(PLAT).$(CFG).mst" 1055 /L
	move /y "$(@:"=).tmp" $@ > NUL

"$(OUTPUT_DIR)\Setup\$(MSIBUILD_PRODUCT_NAME_ID)$(PLAT_SUFFIX)$(CFG_SUFFIX).msi" : \
	"$(OUTPUT_DIR)\$(PLAT).$(CFG).msi" \
	"$(OUTPUT_DIR)\$(PLAT).$(CFG).cab" \
	"$(OUTPUT_DIR)\$(PLAT).$(CFG).inf"
	$(MAKE) /f "MSI\MSIBuild\CAB.mak" /$(MAKEFLAGS) MSIBUILD_ROOT="MSI\MSIBuild" MSIBUILD_TARGET_MSI=$@ MSIBUILD_SOURCE_MSI="$(OUTPUT_DIR)\$(PLAT).$(CFG).msi" MSIBUILD_INF="$(OUTPUT_DIR)\$(PLAT).$(CFG).inf" MSIBUILD_CAB="$(OUTPUT_DIR)\$(PLAT).$(CFG).cab" MSIBUILD_PRODUCT_NAME="$(MSIBUILD_PRODUCT_NAME)"

