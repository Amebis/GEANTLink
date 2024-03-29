#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

!INCLUDE "..\..\..\include\MSIBuildCfg.mak"

!IFNDEF MSIBUILD_PRODUCT_NAME
!ERROR Parameter MSIBUILD_PRODUCT_NAME is undefined.
!ENDIF

!IFNDEF MSIBUILD_PRODUCT_NAME_ID
!ERROR Parameter MSIBUILD_PRODUCT_NAME_ID is undefined.
!ENDIF

!IFNDEF MSIBUILD_PRODUCT_NAME_UC
!ERROR Parameter MSIBUILD_PRODUCT_NAME_UC is undefined.
!ENDIF

!IFNDEF MSIBUILD_PRODUCT_NAME_8_3
!ERROR Parameter MSIBUILD_PRODUCT_NAME_8_3 is undefined.
!ENDIF

!IFNDEF MSIBUILD_LANG_GUID
!ERROR Parameter MSIBUILD_LANG_GUID is undefined.
!ENDIF

MSIBUILD_IS_LOCALIZEABLE=1
!IF "$(LANG)" != "en_US"
MSIBUILD_PO="..\locale\$(LANG).po"
!ENDIF
!IF "$(PLAT)" == "Win32"
PROGRAMFILESFOLDER=ProgramFilesFolder
!ELSE
PROGRAMFILESFOLDER=ProgramFiles64Folder
!ENDIF


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
LANGREG	Language.Win32
!IF "$(PLAT)" == "x64" || "$(PLAT)" == "ARM64"
LANGREG	Language.$(PLAT)
!ENDIF
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
LocalizationRepositoryPath	{6551BCAB-3558-4A73-A8F2-D5A17E85481B}	$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		LocalizationRepositoryPath
Language	{187A7FE1-A380-4281-9FB6-456B161CDF36}	$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		Language
!IF "$(LANG)" != "en_US"
wxstd.mo.$(LANG)	{5BFC819A-8A84-42D8-$(MSIBUILD_LANG_GUID)-3733450235E4}	$(MSIBUILD_PRODUCT_NAME_UC)LOC$(MSIBUILD_LANG_GUID)DIR	$(MSIBUILD_COMPONENT_ATTRIB_FILE)		wxstd.mo.$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# CustomAction

All :: "$(LANG).$(PLAT).$(CFG).CustomAction-1.idt"

"$(LANG).$(PLAT).$(CFG).CustomAction-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Action	Type	Source	Target
s$(MSIBUILD_LENGTH_ID)	i2	S$(MSIBUILD_LENGTH_ID)	S255
CustomAction	Action
Set$(MSIBUILD_PRODUCT_NAME_UC)DIR1	35	$(MSIBUILD_PRODUCT_NAME_UC)DIR	[OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR]
Set$(MSIBUILD_PRODUCT_NAME_UC)DIR2	35	$(MSIBUILD_PRODUCT_NAME_UC)DIR	[INSTALLDIR]
SetLANGUAGE1	307	LANGUAGE	[LANGREG]
SetLANGUAGE2	307	LANGUAGE	[LANG]
<<NOKEEP


######################################################################
# Directory

All :: "$(LANG).$(PLAT).$(CFG).Directory-1.idt"

"$(LANG).$(PLAT).$(CFG).Directory-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Directory	Directory_Parent	DefaultDir
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	l255
Directory	Directory
TARGETDIR		SourceDir
ProgramMenuFolder	TARGETDIR	.
$(MSIBUILD_PRODUCT_NAME_ID)ShortcutDir	ProgramMenuFolder	$(MSIBUILD_PRODUCT_NAME_8_3)|$(MSIBUILD_PRODUCT_NAME):.
$(PROGRAMFILESFOLDER)	TARGETDIR	.
$(MSIBUILD_PRODUCT_NAME_UC)DIR	$(PROGRAMFILESFOLDER)	$(MSIBUILD_PRODUCT_NAME_8_3)|$(MSIBUILD_PRODUCT_NAME):.
!IF     "$(PLAT)" == "Win32" && "$(CFG)" == "Debug"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:WIN32~1.DEB|Win32.Debug
!ELSEIF "$(PLAT)" == "Win32" && "$(CFG)" == "Release"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:WIN32~1.REL|Win32.Release
!ELSEIF "$(PLAT)" == "x64"   && "$(CFG)" == "Debug"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:X64~1.DEB|x64.Debug
!ELSEIF "$(PLAT)" == "x64"   && "$(CFG)" == "Release"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:X64~1.REL|x64.Release
!ELSEIF "$(PLAT)" == "ARM64"   && "$(CFG)" == "Debug"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:ARM64~1.DEB|ARM64.Debug
!ELSEIF "$(PLAT)" == "ARM64"   && "$(CFG)" == "Release"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:ARM64~1.REL|ARM64.Release
!ENDIF
$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	locale
!IF "$(LANG)" != "en_US"
$(MSIBUILD_PRODUCT_NAME_UC)LOC$(MSIBUILD_LANG_GUID)DIR	$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR	$(LANG)
!ENDIF
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
!IF "$(LANG)" != "en_US"
wxstd.mo.$(LANG)	wxstd.mo.$(LANG)	wxstd.mo	0		$(MSIBUILD_LANGID)	0	1
!ENDIF
<<NOKEEP


######################################################################
# Icon

All :: \
	"$(LANG).$(PLAT).$(CFG).Icon-1.idt" \
	"$(LANG).$(PLAT).$(CFG).Icon-1\product.ico"

"$(LANG).$(PLAT).$(CFG).Icon-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak" "$(LANG).$(PLAT).$(CFG).Icon-1"
	move /y << $@ > NUL
Name	Data
s$(MSIBUILD_LENGTH_ID)	v0
Icon	Name
product.ico	product.ico
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Icon-1\product.ico" : "..\..\..\include\icon_full.ico"
	copy /y $** $@ > NUL


######################################################################
# InstallExecuteSequence

All :: "$(LANG).$(PLAT).$(CFG).InstallExecuteSequence-1.idt"

"$(LANG).$(PLAT).$(CFG).InstallExecuteSequence-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Action	Condition	Sequence
s$(MSIBUILD_LENGTH_ID)	S255	I2
InstallExecuteSequence	Action	Condition
SetLANGUAGE1	LANGREG	653
SetLANGUAGE2	LANG	654
Set$(MSIBUILD_PRODUCT_NAME_UC)DIR1	OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR AND UILevel < 4	1001
Set$(MSIBUILD_PRODUCT_NAME_UC)DIR2	INSTALLDIR AND UILevel < 4	1002
<<NOKEEP


######################################################################
# LaunchCondition

All :: "$(LANG).$(PLAT).$(CFG).LaunchCondition-2.idt"

"en_US.$(PLAT).$(CFG).LaunchCondition-2.idtx" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Condition	Description
s255	l255
LaunchCondition	Condition
VersionNT >= "600"	[ProductName] requires Windows Vista or later version of Windows.
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).LaunchCondition-2.idt" : "en_US.$(PLAT).$(CFG).LaunchCondition-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# Media

All :: "$(LANG).$(PLAT).$(CFG).Media-1.idt"

"$(LANG).$(PLAT).$(CFG).Media-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
DiskId	LastSequence	DiskPrompt	Cabinet	VolumeLabel	Source
i2	i2	L64	S255	S32	S$(MSIBUILD_LENGTH_ID)
Media	DiskId
1	1	[ProductName]		$(MSIBUILD_PRODUCT_NAME_UC)	
<<NOKEEP


######################################################################
# Property

All :: \
	"$(LANG).$(PLAT).$(CFG).Property-1.idt" \
	"$(LANG).$(PLAT).$(CFG).Property-2.idt"

"$(LANG).$(PLAT).$(CFG).Property-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Value
s$(MSIBUILD_LENGTH_ID)	l0
Property	Property
ARPPRODUCTICON	product.ico
ALLUSERS	1
DISABLEADVTSHORTCUTS	1
INSTALLLEVEL	3
InstallMode	Typical
SecureCustomProperties	OLDPRODUCTS;NEWPRODUCTS;OLDPRODUCTS1;LANG
LANGUAGE	$(LANG)
<<NOKEEP

"en_US.$(PLAT).$(CFG).Property-2.idtx" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Property	Value
s$(MSIBUILD_LENGTH_ID)	l0
Property	Property
ARPURLINFOABOUT	http://www.geant.org/
ARPHELPLINK	http://www.geant.org/
ARPURLUPDATEINFO	https://github.com/Amebis/GEANTLink/releases
<<NOKEEP

"$(LANG).$(PLAT).$(CFG).Property-2.idt" : "en_US.$(PLAT).$(CFG).Property-2.idtx" $(MSIBUILD_PO)
	cscript.exe "..\..\MSIBuild\MSI.wsf" //Job:IDTTranslate //Nologo $@ $** /CP:$(MSIBUILD_CODEPAGE)


######################################################################
# Registry

All :: "$(LANG).$(PLAT).$(CFG).Registry-1.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
LocalizationRepositoryPath	2	SOFTWARE\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)	LocalizationRepositoryPath	[$(MSIBUILD_PRODUCT_NAME_UC)LOCDIR]	LocalizationRepositoryPath
Language	2	SOFTWARE\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)	Language	[LANGUAGE]	Language
<<NOKEEP


######################################################################
# RegLocator

All :: "$(LANG).$(PLAT).$(CFG).RegLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).RegLocator-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
Signature_	Root	Key	Name	Type
s$(MSIBUILD_LENGTH_ID)	i2	s255	S255	I2
RegLocator	Signature_
Language.Win32	2	SOFTWARE\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)	Language	2
!IF "$(PLAT)" == "x64" || "$(PLAT)" == "ARM64"
Language.$(PLAT)	2	SOFTWARE\$(MSIBUILD_VENDOR_NAME)\$(MSIBUILD_PRODUCT_NAME)	Language	18
!ENDIF
<<NOKEEP


######################################################################
# Upgrade

All :: "$(LANG).$(PLAT).$(CFG).Upgrade-1.idt"

"$(LANG).$(PLAT).$(CFG).Upgrade-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	move /y << $@ > NUL
UpgradeCode	VersionMin	VersionMax	Language	Attributes	Remove	ActionProperty
s38	S20	S20	S255	i4	S255	s$(MSIBUILD_LENGTH_ID)
Upgrade	UpgradeCode	VersionMin	VersionMax	Language	Attributes
!IF "$(PLAT)" == "x64"
{3B90FD10-2DB4-4729-8081-C5668BA0BD2F}	0			257		OLDPRODUCTS1
!ELSEIF "$(PLAT)" == "ARM64"
{094B1885-C53C-4A1C-842F-D66994D60BB5}	0			257		OLDPRODUCTS1
!ELSE
{41546260-2E34-40C3-9890-1FF733E71C6D}	0			257		OLDPRODUCTS1
!ENDIF
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSIBuild\MSM.mak"
