#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

!INCLUDE "..\..\..\include\MSIBuildCfg.mak"

!IFNDEF MSIBUILD_PRODUCT_NAME
!ERROR Parameter MSIBUILD_PRODUCT_NAME is undefined.
!ENDIF

!IFNDEF MSIBUILD_PRODUCT_NAME_UC
!ERROR Parameter MSIBUILD_PRODUCT_NAME_UC is undefined.
!ENDIF

!IFNDEF MSIBUILD_PLAT_GUID
!ERROR Parameter MSIBUILD_PLAT_GUID is undefined.
!ENDIF


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	Events.dll.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
Events.dll.$(PLAT)	{E691777F-2A7F-4E8D-9B0$(MSIBUILD_PLAT_GUID)-499075499649}	1
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
Events.dll.$(PLAT)	{E691777F-2A7F-4E8D-9B0$(MSIBUILD_PLAT_GUID)-499075499649}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		Events.dll.$(PLAT)
EventsPublisher1	{CE799218-FEF2-4584-80D1-751BEAECC4F3}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisher1
EventsPublisher2	{CE8D096D-54A9-4F6C-8B2B-BCE8253126DC}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisher2
EventsPublisher3	{68706D4D-4AD5-48E0-9C23-EE351E9A6FAA}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisher3
EventsPublisher4	{5BBBA8F8-9626-4724-8984-67FA71AB27AD}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisher4
EventsPublisherChannels	{2FAE195A-A849-4418-B204-0CFBB13A4A2F}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChannels
EventsPublisherChOperational1	{97682862-F40F-4467-B465-DF31C65066FE}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChOperational1
EventsPublisherChOperational2	{7730A832-F127-4FF1-A5D6-8477362194D7}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChOperational2
EventsPublisherChOperational3	{D45E16AF-B757-4B1A-AB4E-E4715835E494}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChOperational3
EventsPublisherChAnalytic1	{B121EA86-4ECD-42C8-B45E-30BEFC307F17}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChAnalytic1
EventsPublisherChAnalytic2	{7B9CD9CD-CB21-47A7-97AC-FD297E5BA124}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChAnalytic2
EventsPublisherChAnalytic3	{5BC46780-D624-42C4-86C5-0D482B5F7E00}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsPublisherChAnalytic3
EventsChannelOperational1	{7AC2960D-98B0-40E4-A3D9-322C0E4F1CC4}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational1
EventsChannelOperational2	{CA329351-555F-4A1A-9F6E-A358097020EE}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational2
EventsChannelOperational3	{2CA50F50-8D01-4B15-9FF4-411A3D0A8254}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational3
EventsChannelOperational4	{762EE4E5-9359-47E2-B21A-B142746A3469}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational4
EventsChannelOperational5	{4B0D9C46-AFB9-4E1F-B1FA-8061A9F9EED0}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational5
EventsChannelOperational6	{E2DC88EA-F603-4131-908E-7C303B3AA654}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational6
EventsChannelOperational7	{86641DCF-34D8-4F3B-A431-0B1365262798}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational7
EventsChannelOperational8	{09B82D13-55DD-4EAB-9E22-D8837B0B43C5}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational8
EventsChannelOperational9	{30625BDC-E125-4F7D-8E32-9F069F456180}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelOperational9
EventsChannelAnalytic1	{4E48CC21-4884-46B2-90B3-F2A4D8267D7A}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic1
EventsChannelAnalytic2	{57D027B4-24AD-4541-936A-EC7B2524DFEF}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic2
EventsChannelAnalytic3	{52493EEE-9AE8-4947-A04E-2217FB9324B4}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic3
EventsChannelAnalytic4	{D25E28CD-111B-45EB-AB92-0B7658839778}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic4
EventsChannelAnalytic5	{F617E20D-C5EC-4146-8B72-5111C8CFFB93}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic5
EventsChannelAnalytic6	{60FC49D7-D01F-474A-A77E-9A5B613F018F}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic6
EventsChannelAnalytic7	{A8FE5C92-7CB9-4AEE-962E-28DA428C91FE}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic7
EventsChannelAnalytic8	{7DD8FC55-496F-420B-983E-199FA3969539}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		EventsChannelAnalytic8
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
Events.dll.$(PLAT)	Events.dll.$(PLAT)	EAPMET~1.DLL|Events.dll	0		0	1536	1
<<NOKEEP


######################################################################
# Registry

All :: "$(LANG).$(PLAT).$(CFG).Registry-1.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
EventsPublisher1	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)		$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod	EventsPublisher1
EventsPublisher2	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)	MessageFileName	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]Events.dll	EventsPublisher2
EventsPublisher3	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)	ResourceFileName	[$(MSIBUILD_PRODUCT_NAME_UC)BINDIR]Events.dll	EventsPublisher3
EventsPublisher4	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)	Enabled	#1	EventsPublisher4
EventsPublisherChannels	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences	Count	#2	EventsPublisherChannels
EventsPublisherChOperational1	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\0		$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	EventsPublisherChOperational1
EventsPublisherChOperational2	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\0	Id	#16	EventsPublisherChOperational2
EventsPublisherChOperational3	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\0	Flags	#0	EventsPublisherChOperational3
EventsPublisherChAnalytic1	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\1		$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	EventsPublisherChAnalytic1
EventsPublisherChAnalytic2	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\1	Id	#17	EventsPublisherChAnalytic2
EventsPublisherChAnalytic3	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$(EVENT_PROVIDER_GUID)\ChannelReferences\1	Flags	#0	EventsPublisherChAnalytic3
EventsChannelOperational1	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	OwningPublisher	$(EVENT_PROVIDER_GUID)	EventsChannelOperational1
EventsChannelOperational2	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	Enabled	#1	EventsChannelOperational2
EventsChannelOperational3	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	Isolation	#0	EventsChannelOperational3
EventsChannelOperational4	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	ChannelAccess	O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)	EventsChannelOperational4
EventsChannelOperational5	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	MaxSize	#1048576	EventsChannelOperational5
EventsChannelOperational6	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	MaxSizeUpper	#0	EventsChannelOperational6
EventsChannelOperational7	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	Retention	#0	EventsChannelOperational7
EventsChannelOperational8	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	Type	#1	EventsChannelOperational8
EventsChannelOperational9	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Operational	AutoBackupLogFiles	#0	EventsChannelOperational9
EventsChannelAnalytic1	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	OwningPublisher	$(EVENT_PROVIDER_GUID)	EventsChannelAnalytic1
EventsChannelAnalytic2	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	Enabled	#0	EventsChannelAnalytic2
EventsChannelAnalytic3	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	Isolation	#0	EventsChannelAnalytic3
EventsChannelAnalytic4	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	ChannelAccess	O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)	EventsChannelAnalytic4
EventsChannelAnalytic5	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	MaxSize	#1048576	EventsChannelAnalytic5
EventsChannelAnalytic6	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	MaxSizeUpper	#0	EventsChannelAnalytic6
EventsChannelAnalytic7	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	Retention	#4294967295	EventsChannelAnalytic7
EventsChannelAnalytic8	2	SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$(MSIBUILD_VENDOR_NAME)-$(MSIBUILD_PRODUCT_NAME)-EAPMethod/Analytic	Type	#2	EventsChannelAnalytic8
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\..\MSI\MSIBuild\MSM.mak"
