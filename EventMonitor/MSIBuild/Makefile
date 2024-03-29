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
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	EventMonitor.exe.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
EventMonitor.exe.$(PLAT)	{3E4DDA0E-F8B2-4210-8D8$(MSIBUILD_PLAT_GUID)-90C221670B81}	1
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
EventMonitor.exe.$(PLAT)	{3E4DDA0E-F8B2-4210-8D8$(MSIBUILD_PLAT_GUID)-90C221670B81}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		EventMonitor.exe.$(PLAT)
!IF "$(LANG)" != "en_US"
EventMonitor.mo.$(LANG)	{289D4CED-93CB-41BC-$(MSIBUILD_LANG_GUID)-49AAF92A9D34}	$(MSIBUILD_PRODUCT_NAME_UC)LOC$(MSIBUILD_LANG_GUID)DIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		EventMonitor.mo.$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"en_US.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
Feature	Feature
featEventMonitor		Event Monitor	Real-time display of internal events	101	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	8
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
featEventMonitor	Events.dll.$(PLAT)
featEventMonitor	EventsPublisher1
featEventMonitor	EventsPublisher2
featEventMonitor	EventsPublisher3
featEventMonitor	EventsPublisher4
featEventMonitor	EventsPublisherChannels
featEventMonitor	EventsPublisherChOperational1
featEventMonitor	EventsPublisherChOperational2
featEventMonitor	EventsPublisherChOperational3
featEventMonitor	EventsPublisherChAnalytic1
featEventMonitor	EventsPublisherChAnalytic2
featEventMonitor	EventsPublisherChAnalytic3
featEventMonitor	EventsChannelOperational1
featEventMonitor	EventsChannelOperational2
featEventMonitor	EventsChannelOperational3
featEventMonitor	EventsChannelOperational4
featEventMonitor	EventsChannelOperational5
featEventMonitor	EventsChannelOperational6
featEventMonitor	EventsChannelOperational7
featEventMonitor	EventsChannelOperational8
featEventMonitor	EventsChannelOperational9
featEventMonitor	EventsChannelAnalytic1
featEventMonitor	EventsChannelAnalytic2
featEventMonitor	EventsChannelAnalytic3
featEventMonitor	EventsChannelAnalytic4
featEventMonitor	EventsChannelAnalytic5
featEventMonitor	EventsChannelAnalytic6
featEventMonitor	EventsChannelAnalytic7
featEventMonitor	EventsChannelAnalytic8
featEventMonitor	EventMonitor.exe.$(PLAT)
featEventMonitor	LocalizationRepositoryPath
featEventMonitor	Language
!IF "$(LANG)" != "en_US"
featEventMonitor	wxstd.mo.$(LANG)
featEventMonitor	wxExtend.mo.$(LANG)
featEventMonitor	EventMonitor.mo.$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
EventMonitor.exe.$(PLAT)	EventMonitor.exe.$(PLAT)	EVENTM~1.EXE|EventMonitor.exe	0		0	1536	1
!IF "$(LANG)" != "en_US"
EventMonitor.mo.$(LANG)	EventMonitor.mo.$(LANG)	EVENTM~1.MO|EventMonitor.mo	0		$(MSIBUILD_LANGID)	0	1
!ENDIF
<<NOKEEP


######################################################################
# RemoveFile

All :: "$(LANG).$(PLAT).$(CFG).RemoveFile-1.idt"

"$(LANG).$(PLAT).$(CFG).RemoveFile-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
FileKey	Component_	FileName	DirProperty	InstallMode
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	L255	s$(MSIBUILD_LENGTH_ID)	i2
RemoveFile	FileKey
EventMonitor	EventMonitor.exe.$(PLAT)		$(MSIBUILD_PRODUCT_NAME_ID)ShortcutDir	2
<<NOKEEP


######################################################################
# Shortcut

All :: "$(LANG).$(PLAT).$(CFG).Shortcut-2.idt"

"en_US.$(PLAT).$(CFG).Shortcut-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Shortcut	Directory_	Name	Component_	Target	Arguments	Description	Hotkey	Icon_	IconIndex	ShowCmd	WkDir	DisplayResourceDLL	DisplayResourceId	DescriptionResourceDLL	DescriptionResourceId
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l128	s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	S255	L255	I2	S$(MSIBUILD_LENGTH_ID)	I2	I2	S$(MSIBUILD_LENGTH_ID)	S255	I2	S255	I2
Shortcut	Shortcut
EventMonitor	$(MSIBUILD_PRODUCT_NAME_ID)ShortcutDir	EVENTM~1|$(MSIBUILD_PRODUCT_NAME) Event Monitor	EventMonitor.exe.$(PLAT)	featEventMonitor		Real-time display of internal events					$(MSIBUILD_PRODUCT_NAME_UC)BINDIR				
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Shortcut-2.idt" : "en_US.$(PLAT).$(CFG).Shortcut-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSI\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSI\MSIBuild\MSM.mak"
