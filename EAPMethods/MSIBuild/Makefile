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

MSIBUILD_IS_LOCALIZEABLE=1
!IF "$(LANG)" != "en_US"
MSIBUILD_PO="..\locale\$(LANG).po"
!ENDIF


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
EAPHostAuthor	{086E042A-6741-459D-92F0-F5CCFA4E34D4}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPHostAuthor
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"en_US.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
Feature	Feature
featEAPMethods		EAP Methods	Modules to support individual EAP methods	1	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	0
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Feature-2.idt" : "en_US.$(PLAT).$(CFG).Feature-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSI\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# Registry

All :: "$(LANG).$(PLAT).$(CFG).Registry-1.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
EAPHostAuthor	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)		$(MSIBUILD_PRODUCT_NAME)	EAPHostAuthor
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSI\MSIBuild\MSM.mak"
