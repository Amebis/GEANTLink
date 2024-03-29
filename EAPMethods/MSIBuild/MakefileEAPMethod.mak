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

!IFNDEF MSIBUILD_LANG_GUID
!ERROR Parameter MSIBUILD_LANG_GUID is undefined.
!ENDIF

!IF "$(EAPMETHOD_TYPE)" == "21"
EAPMETHOD_GUID=15
EAPMETHOD_NAME=EAP-TTLS
!ELSE
!ERROR Unknown EAP Method type.
!ENDIF

MSIBUILD_IS_LOCALIZEABLE=1
!IF "$(LANG)" != "en_US"
MSIBUILD_PO="..\locale\$(LANG).po"
!ENDIF


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)	{326E5E$(EAPMETHOD_GUID)-B6B6-4E75-BA2$(MSIBUILD_PLAT_GUID)-5BEE2A40590E}	1
EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)	{8E0766$(EAPMETHOD_GUID)-3201-45E9-BBC$(MSIBUILD_PLAT_GUID)-5D9A527012AB}	1
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)	{326E5E$(EAPMETHOD_GUID)-B6B6-4E75-BA2$(MSIBUILD_PLAT_GUID)-5BEE2A40590E}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)
EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)	{8E0766$(EAPMETHOD_GUID)-3201-45E9-BBC$(MSIBUILD_PLAT_GUID)-5D9A527012AB}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)
EAPMethod$(EAPMETHOD_TYPE)PeerDllPath	{A932B1$(EAPMETHOD_GUID)-3B65-4317-8201-03078C72A998}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerDllPath
EAPMethod$(EAPMETHOD_TYPE)PeerConfigUIPath	{D640C9$(EAPMETHOD_GUID)-45C0-4550-A323-86E8EE0FE9E9}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerConfigUIPath
EAPMethod$(EAPMETHOD_TYPE)PeerIdentityPath	{F06B12$(EAPMETHOD_GUID)-DEF8-441E-87FD-FBFFEF4BD4F7}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerIdentityPath
EAPMethod$(EAPMETHOD_TYPE)PeerInteractiveUIPath	{44B2DE$(EAPMETHOD_GUID)-C667-482C-A5E7-630F7295A43E}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerInteractiveUIPath
EAPMethod$(EAPMETHOD_TYPE)PeerFriendlyName	{7D4ABF$(EAPMETHOD_GUID)-D166-4BD2-953E-0B43C8E2C286}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerFriendlyName
EAPMethod$(EAPMETHOD_TYPE)PeerInvokePasswordDialog	{C2D911$(EAPMETHOD_GUID)-13EB-4B75-BBFF-BA557CB55A3C}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerInvokePasswordDialog
EAPMethod$(EAPMETHOD_TYPE)PeerInvokeUsernameDialog	{59194C$(EAPMETHOD_GUID)-C234-4CE8-B65E-116FE15A7FC8}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)PeerInvokeUsernameDialog
EAPMethod$(EAPMETHOD_TYPE)Properties	{75835E$(EAPMETHOD_GUID)-CAFE-4EAE-AD60-B158403035BF}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EAPMethod$(EAPMETHOD_TYPE)Properties
!IF "$(LANG)" != "en_US"
EAPMethod$(EAPMETHOD_TYPE)_UI.mo.$(LANG)	{FEEA3A$(EAPMETHOD_GUID)-28BB-40BF-$(MSIBUILD_LANG_GUID)-78181B816C06}	$(MSIBUILD_PRODUCT_NAME_UC)LOC$(MSIBUILD_LANG_GUID)DIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		EAPMethod$(EAPMETHOD_TYPE)_UI.mo.$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"en_US.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
Feature	Feature
featEAPMethod$(EAPMETHOD_TYPE)	featEAPMethods	$(EAPMETHOD_NAME)	$(EAPMETHOD_NAME) Method	1	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	8
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Feature-2.idt" : "en_US.$(PLAT).$(CFG).Feature-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSI\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# FeatureComponents

All :: "$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt"

"$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature_	Component_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
FeatureComponents	Feature_	Component_
featEAPMethod$(EAPMETHOD_TYPE)	Events.dll.$(PLAT)
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisher1
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisher2
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisher3
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisher4
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChannels
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChOperational1
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChOperational2
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChOperational3
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChAnalytic1
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChAnalytic2
featEAPMethod$(EAPMETHOD_TYPE)	EventsPublisherChAnalytic3
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational1
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational2
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational3
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational4
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational5
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational6
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational7
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational8
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelOperational9
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic1
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic2
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic3
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic4
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic5
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic6
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic7
featEAPMethod$(EAPMETHOD_TYPE)	EventsChannelAnalytic8
featEAPMethod$(EAPMETHOD_TYPE)	EAPHostAuthor
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerDllPath
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerConfigUIPath
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerIdentityPath
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerInteractiveUIPath
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerFriendlyName
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerInvokePasswordDialog
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)PeerInvokeUsernameDialog
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)Properties
featEAPMethod$(EAPMETHOD_TYPE)	LocalizationRepositoryPath
featEAPMethod$(EAPMETHOD_TYPE)	Language
!IF "$(LANG)" != "en_US"
featEAPMethod$(EAPMETHOD_TYPE)	wxstd.mo.$(LANG)
featEAPMethod$(EAPMETHOD_TYPE)	wxExtend.mo.$(LANG)
featEAPMethod$(EAPMETHOD_TYPE)	EAPMethod$(EAPMETHOD_TYPE)_UI.mo.$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)	EAPMethod$(EAPMETHOD_TYPE).dll.$(PLAT)	EAPME~$(EAPMETHOD_GUID).DLL|$(EAPMETHOD_NAME).dll	0		0	1536	1
EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)	EAPMethod$(EAPMETHOD_TYPE)_UI.dll.$(PLAT)	EAPMU~$(EAPMETHOD_GUID).DLL|$(EAPMETHOD_NAME)_UI.dll	0		0	1536	1
!IF "$(LANG)" != "en_US"
EAPMethod$(EAPMETHOD_TYPE)_UI.mo.$(LANG)	EAPMethod$(EAPMETHOD_TYPE)_UI.mo.$(LANG)	EAPMU~$(EAPMETHOD_GUID).MO|$(EAPMETHOD_NAME)_UI.mo	0		$(MSIBUILD_LANGID)	0	1
!ENDIF
<<NOKEEP


######################################################################
# Registry

All :: "$(LANG).$(PLAT).$(CFG).Registry-1.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\MSIBuild\MakefileEAPMethod.mak" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
EAPMethod$(EAPMETHOD_TYPE)PeerDllPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerDllPath	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]$(EAPMETHOD_NAME).dll	EAPMethod$(EAPMETHOD_TYPE)PeerDllPath
EAPMethod$(EAPMETHOD_TYPE)PeerConfigUIPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerConfigUIPath	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]$(EAPMETHOD_NAME)_UI.dll	EAPMethod$(EAPMETHOD_TYPE)PeerConfigUIPath
EAPMethod$(EAPMETHOD_TYPE)PeerIdentityPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerIdentityPath	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]$(EAPMETHOD_NAME)_UI.dll	EAPMethod$(EAPMETHOD_TYPE)PeerIdentityPath
EAPMethod$(EAPMETHOD_TYPE)PeerInteractiveUIPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerInteractiveUIPath	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]$(EAPMETHOD_NAME)_UI.dll	EAPMethod$(EAPMETHOD_TYPE)PeerInteractiveUIPath
EAPMethod$(EAPMETHOD_TYPE)PeerFriendlyName	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerFriendlyName	@[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]$(EAPMETHOD_NAME).dll,-1	EAPMethod$(EAPMETHOD_TYPE)PeerFriendlyName
EAPMethod$(EAPMETHOD_TYPE)PeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerInvokePasswordDialog	#0	EAPMethod$(EAPMETHOD_TYPE)PeerInvokePasswordDialog
EAPMethod$(EAPMETHOD_TYPE)PeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	PeerInvokeUsernameDialog	#0	EAPMethod$(EAPMETHOD_TYPE)PeerInvokeUsernameDialog
EAPMethod$(EAPMETHOD_TYPE)Properties	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)	Properties	#389871807	EAPMethod$(EAPMETHOD_TYPE)Properties
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSI\MSIBuild\MSM.mak"
