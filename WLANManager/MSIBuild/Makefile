#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

!INCLUDE "..\..\include\MSIBuildCfg.mak"

!IFNDEF MSIBUILD_PRODUCT_NAME
!ERROR Parameter MSIBUILD_PRODUCT_NAME is undefined.
!ENDIF

!IFNDEF MSIBUILD_PRODUCT_NAME_UC
!ERROR Parameter MSIBUILD_PRODUCT_NAME_UC is undefined.
!ENDIF

!IFNDEF MSIBUILD_PLAT_GUID
!ERROR Parameter MSIBUILD_PLAT_GUID is undefined.
!ENDIF

MSIBUILD_IS_LOCALIZEABLE=1
!IF "$(LANG)" != "en_US"
MSIBUILD_PO="..\locale\$(LANG).po"
!ENDIF


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	WLANManager.exe.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
WLANManager.exe.$(PLAT)	{436A4D5D-0EDD-4DC1-82F$(MSIBUILD_PLAT_GUID)-A577967BF748}	1
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
WLANManager.exe.$(PLAT)	{436A4D5D-0EDD-4DC1-82F$(MSIBUILD_PLAT_GUID)-A577967BF748}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		WLANManager.exe.$(PLAT)
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"en_US.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
Feature	Feature
featWLANManager		WLAN Manager	Helper utility to support direct shortcuts to Wireless Network Properties	111	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	8
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Feature-2.idt" : "en_US.$(PLAT).$(CFG).Feature-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSI\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# FeatureComponents

All :: "$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt"

"$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature_	Component_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
FeatureComponents	Feature_	Component_
featWLANManager	WLANManager.exe.$(PLAT)
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
WLANManager.exe.$(PLAT)	WLANManager.exe.$(PLAT)	WLANMA~1.EXE|WLANManager.exe	0		0	1536	1
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSI\MSIBuild\MSM.mak"
