#
#    Copyright 1991-2016 Amebis
#    Copyright 2016 GÉANT
#
#    This file is part of GEANTLink.
#
#    GEANTLink is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    GEANTLink is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with GEANTLink. If not, see <http://www.gnu.org/licenses/>.
#

!INCLUDE "..\..\..\include\MSIBuildCfg.mak"


######################################################################
# CustomAction

All :: "$(LANG).$(PLAT).$(CFG).CustomAction-1.idt"

"$(LANG).$(PLAT).$(CFG).CustomAction-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Action	Type	Source	Target
s$(MSIBUILD_LENGTH_ID)	i2	S$(MSIBUILD_LENGTH_ID)	S255
CustomAction	Action
caSet$(MSIBUILD_PRODUCT_NAME_UC)DIR1	35	$(MSIBUILD_PRODUCT_NAME_UC)DIR	[OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR]
caSet$(MSIBUILD_PRODUCT_NAME_UC)DIR2	35	$(MSIBUILD_PRODUCT_NAME_UC)DIR	[INSTALLDIR]
<<NOKEEP


######################################################################
# Directory

All :: "$(LANG).$(PLAT).$(CFG).Directory-1.idt"

"$(LANG).$(PLAT).$(CFG).Directory-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Directory	Directory_Parent	DefaultDir
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	l255
Directory	Directory
TARGETDIR		SourceDir
ProgramFilesFolder	TARGETDIR	.
!IF "$(PLAT)" == "x64"
ProgramFiles64Folder	TARGETDIR	.
PROGRAMFILESDIR	ProgramFiles64Folder	.
!ELSE
PROGRAMFILESDIR	ProgramFilesFolder	.
!ENDIF
ProgramMenuFolder	TARGETDIR	.
$(MSIBUILD_PRODUCT_NAME)ShortcutDir	ProgramMenuFolder	$(MSIBUILD_PRODUCT_NAME_8_3)|$(MSIBUILD_PRODUCT_NAME):.
$(MSIBUILD_PRODUCT_NAME_UC)DIR	PROGRAMFILESDIR	$(MSIBUILD_PRODUCT_NAME_8_3)|$(MSIBUILD_PRODUCT_NAME):.
!IF     "$(PLAT)" == "Win32" && "$(CFG)" == "Debug"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:WIN32~1.DEB|Win32.Debug
!ELSEIF "$(PLAT)" == "Win32" && "$(CFG)" == "Release"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:WIN32~1.REL|Win32.Release
!ELSEIF "$(PLAT)" == "x64"   && "$(CFG)" == "Debug"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:X64~1.DEB|x64.Debug
!ELSEIF "$(PLAT)" == "x64"   && "$(CFG)" == "Release"
$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_PRODUCT_NAME_UC)DIR	.:X64~1.REL|x64.Release
!ENDIF
<<NOKEEP


######################################################################
# InstallExecuteSequence

All :: "$(LANG).$(PLAT).$(CFG).InstallExecuteSequence-1.idt"

"$(LANG).$(PLAT).$(CFG).InstallExecuteSequence-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Action	Condition	Sequence
s$(MSIBUILD_LENGTH_ID)	S255	I2
InstallExecuteSequence	Action
caSet$(MSIBUILD_PRODUCT_NAME_UC)DIR1	OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR AND UILevel < 4	1001
caSet$(MSIBUILD_PRODUCT_NAME_UC)DIR2	INSTALLDIR AND UILevel < 4	1002
<<NOKEEP


######################################################################
# Media

All :: "$(LANG).$(PLAT).$(CFG).Media-1.idt"

"$(LANG).$(PLAT).$(CFG).Media-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
DiskId	LastSequence	DiskPrompt	Cabinet	VolumeLabel	Source
i2	i2	L64	S255	S32	S$(MSIBUILD_LENGTH_ID)
Media	DiskId
1	1	[ProductName]		$(MSIBUILD_PRODUCT_NAME_UC)	
<<NOKEEP


######################################################################
# Property

All :: "$(LANG).$(PLAT).$(CFG).Property-1.idt"

"$(LANG).$(PLAT).$(CFG).Property-1.idt" : "Makefile" "..\..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Property	Value
s$(MSIBUILD_LENGTH_ID)	l0
Property	Property
ALLUSERS	1
DISABLEADVTSHORTCUTS	1
INSTALLLEVEL	3
InstallMode	Typical
SecureCustomProperties	OLDPRODUCTFOUND;NEWPRODUCTFOUND
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSIBuild\MSM.mak"
