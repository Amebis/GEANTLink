#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

######################################################################
# MSI General Package Information

MSIBUILD_VENDOR_NAME=GÉANT
MSIBUILD_PRODUCT_NAME=GÉANTLink
EAPMETHOD_AUTHOR_ID=67532
EVENT_PROVIDER_GUID={3f65af01-ce8f-4c7d-990b-673b244aac7b}


######################################################################
# Language specific settings

!IF "$(LANG)" == "bg_BG"
MSIBUILD_LANGID=1026
MSIBUILD_LANG_GUID=0402
MSIBUILD_CODEPAGE=1251
!ELSEIF "$(LANG)" == "ca_ES"
MSIBUILD_LANGID=1027
MSIBUILD_LANG_GUID=0403
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "cs_CZ"
MSIBUILD_LANGID=1029
MSIBUILD_LANG_GUID=0405
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "cy_UK"
MSIBUILD_LANGID=1106
MSIBUILD_LANG_GUID=0452
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "de_DE"
MSIBUILD_LANGID=1031
MSIBUILD_LANG_GUID=0407
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "el_GR"
MSIBUILD_LANGID=1032
MSIBUILD_LANG_GUID=0408
MSIBUILD_CODEPAGE=1253
!ELSEIF "$(LANG)" == "es_ES"
MSIBUILD_LANGID=1034
MSIBUILD_LANG_GUID=040A
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "et_EE"
MSIBUILD_LANGID=1061
MSIBUILD_LANG_GUID=0425
MSIBUILD_CODEPAGE=1257
!ELSEIF "$(LANG)" == "eu_ES"
MSIBUILD_LANGID=1069
MSIBUILD_LANG_GUID=042D
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "fi_FI"
MSIBUILD_LANGID=1035
MSIBUILD_LANG_GUID=040B
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "fr_CA"
MSIBUILD_LANGID=3084
MSIBUILD_LANG_GUID=0C0C
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "fr_FR"
MSIBUILD_LANGID=1036
MSIBUILD_LANG_GUID=040C
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "gl_ES"
MSIBUILD_LANGID=1110
MSIBUILD_LANG_GUID=0456
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "hr_HR"
MSIBUILD_LANGID=1050
MSIBUILD_LANG_GUID=041A
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "hu_HU"
MSIBUILD_LANGID=1038
MSIBUILD_LANG_GUID=040E
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "is_IS"
MSIBUILD_LANGID=1039
MSIBUILD_LANG_GUID=040F
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "it_IT"
MSIBUILD_LANGID=1040
MSIBUILD_LANG_GUID=0410
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "ko_KR"
MSIBUILD_LANGID=1042
MSIBUILD_LANG_GUID=0412
MSIBUILD_CODEPAGE=949
!ELSEIF "$(LANG)" == "lt_LT"
MSIBUILD_LANGID=1063
MSIBUILD_LANG_GUID=0427
MSIBUILD_CODEPAGE=1257
!ELSEIF "$(LANG)" == "nb_NO"
MSIBUILD_LANGID=1044
MSIBUILD_LANG_GUID=0414
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "nl_NL"
MSIBUILD_LANGID=1043
MSIBUILD_LANG_GUID=0413
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "pl_PL"
MSIBUILD_LANGID=1045
MSIBUILD_LANG_GUID=0415
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "pt_PT"
MSIBUILD_LANGID=2070
MSIBUILD_LANG_GUID=0816
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "ru_RU"
MSIBUILD_LANGID=1049
MSIBUILD_LANG_GUID=0419
MSIBUILD_CODEPAGE=1251
!ELSEIF "$(LANG)" == "sk_SK"
MSIBUILD_LANGID=1051
MSIBUILD_LANG_GUID=041B
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "ro_RO"
MSIBUILD_LANGID=1048
MSIBUILD_LANG_GUID=0418
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "sl_SI"
MSIBUILD_LANGID=1060
MSIBUILD_LANG_GUID=0424
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "sr_RS"
MSIBUILD_LANGID=2074
MSIBUILD_LANG_GUID=081A
MSIBUILD_CODEPAGE=1250
!ELSEIF "$(LANG)" == "sv_SE"
MSIBUILD_LANGID=1053
MSIBUILD_LANG_GUID=041D
MSIBUILD_CODEPAGE=1252
!ELSEIF "$(LANG)" == "tr_TR"
MSIBUILD_LANGID=1055
MSIBUILD_LANG_GUID=041F
MSIBUILD_CODEPAGE=1254
!ELSEIF "$(LANG)" == "vi_VN"
MSIBUILD_LANGID=1066
MSIBUILD_LANG_GUID=042A
MSIBUILD_CODEPAGE=1258
!ELSE
LANG=en_US
MSIBUILD_LANGID=1033
MSIBUILD_LANG_GUID=0409
MSIBUILD_CODEPAGE=1252
!ENDIF


######################################################################
# Platform specific settings

!IF "$(PLAT)" == "x64"
MSIBUILD_PLAT_GUID=1
!ELSEIF "$(PLAT)" == "ARM64"
MSIBUILD_PLAT_GUID=2
!ELSE
MSIBUILD_PLAT_GUID=0
!ENDIF


######################################################################
# Project name variations for directory variables & stuff

MSIBUILD_PRODUCT_NAME_ID=GEANTLink
MSIBUILD_PRODUCT_NAME_UC=GEANTLINK
MSIBUILD_PRODUCT_NAME_8_3=GEANTL~1


######################################################################
# Path to version file
# (relative from MSIBuild\Version folder)

MSIBUILD_VERSION_FILE=..\..\..\include\Version.h


######################################################################
# GUID used to determine MSI upgrade logic

MSIBUILD_UPGRADE_GUID={B629232B-8EB3-4205-A5D$(MSIBUILD_PLAT_GUID)-BBD9ED5635ED}
MSIBUILD_REMOVE_BEFORE_INSTALL_CONDITION=OLDPRODUCTS1


######################################################################
# Minimum MSI version required to install this package

!IF "$(PLAT)" == "ARM64"
MSIBUILD_MSI_VERSION_MIN=500
!ELSE
MSIBUILD_MSI_VERSION_MIN=400
!ENDIF


######################################################################
# Length of ID and help fields in MSI tables (in characters)

MSIBUILD_LENGTH_ID=128
MSIBUILD_LENGTH_HELP=256


######################################################################
# Should MSIBuild compress files into CAB itself?

#MSIBUILD_COMPRESS=1


######################################################################
# Prevent installation of 32-bit MSI on 64-bit Windows

MSIBUILD_HAS_X64=1
MSIBUILD_NO_WOW64=1


######################################################################
# Component and registry settings (platform dependant)

!IF "$(PLAT)" == "x64" || "$(PLAT)" == "ARM64"
MSIBUILD_COMPONENT_ATTRIB_FILE=256
MSIBUILD_COMPONENT_ATTRIB_REGISTRY=260
MSIBUILD_REG32_RELOCATION=\Wow6432Node
!ELSE
MSIBUILD_COMPONENT_ATTRIB_FILE=0
MSIBUILD_COMPONENT_ATTRIB_REGISTRY=4
MSIBUILD_REG32_RELOCATION=
!ENDIF


######################################################################
# List of modules to compile and include in link
# (relative from MSI\Base folder)

MSIBUILD_MODULES=\
	"..\MSIBuild\Core\$(LANG).$(PLAT).$(CFG).msm" \
	"..\MSIBuild\Version\$(LANG).$(PLAT).$(CFG).msm" \
	"Main\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\lib\Events\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\lib\wxExtend\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\EAPMethods\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\EAPMethods\MSIBuild.EAP-TTLS\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\EventMonitor\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"..\..\WLANManager\MSIBuild\$(LANG).$(PLAT).$(CFG).msm"


######################################################################
# wxExtend Module

WXEXTEND_STATIC=1
WXEXTEND_BIN_DIR=$(MSIBUILD_PRODUCT_NAME_UC)BINDIR
WXEXTEND_LOC_DIR=$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR
