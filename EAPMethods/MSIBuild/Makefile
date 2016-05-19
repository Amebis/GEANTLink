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

!INCLUDE "..\..\include\MSIBuildCfg.mak"

MSIBUILD_IS_LOCALIZEABLE=1


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	clEAPTTLS.dll.$(PLAT)
OLD$(MSIBUILD_PRODUCT_NAME_UC)DIR	clEAPMethodEvents.dll.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
!IF "$(PLAT)" == "Win32"
clEAPMethodEvents.dll.Win32	{E0A1F106-D904-4BAF-9324-94FE6DD12089}	1
!ENDIF
!IF "$(PLAT)" == "x64"
clEAPMethodEvents.dll.x64	{594109D7-8FA0-43DF-8CA6-FE1562AAC1C1}	1
!ENDIF
!IF "$(PLAT)" == "Win32"
clEAPTTLS.dll.Win32	{A4A62D2F-DA90-4765-BD8C-D59EA2C01DFE}	1
!ENDIF
!IF "$(PLAT)" == "x64"
clEAPTTLS.dll.x64	{A1F62401-03F1-4D4E-A1FA-0FD4858D90B6}	1
!ENDIF
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
!IF "$(PLAT)" == "Win32"
compEAPMethodEvents.dll.Win32	{E0A1F106-D904-4BAF-9324-94FE6DD12089}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	0		fileEAPMethodEvents.dll.Win32
!ENDIF
!IF "$(PLAT)" == "x64"
compEAPMethodEvents.dll.x64	{594109D7-8FA0-43DF-8CA6-FE1562AAC1C1}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	256		fileEAPMethodEvents.dll.x64
!ENDIF
compEAPHostAuthor	{086E042A-6741-459D-92F0-F5CCFA4E34D4}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostAuthor
!IF "$(PLAT)" == "Win32"
compEAPTTLS.dll.Win32	{A4A62D2F-DA90-4765-BD8C-D59EA2C01DFE}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	0		fileEAPTTLS.dll.Win32
!ENDIF
!IF "$(PLAT)" == "x64"
compEAPTTLS.dll.x64	{A1F62401-03F1-4D4E-A1FA-0FD4858D90B6}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	256		fileEAPTTLS.dll.x64
!ENDIF
compEAPTTLSPeerDllPath	{29FD2FDC-9289-47F0-96A3-C21AEE587B5B}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPTTLSPeerDllPath
compEAPTTLSPeerFriendlyName	{E3250ECE-E59F-4693-B290-925B80929EAE}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPTTLSPeerFriendlyName
compEAPTTLSPeerInvokePasswordDialog	{9A426E96-6E79-4BA9-83DD-7A205CA43810}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPTTLSPeerInvokePasswordDialog
compEAPTTLSPeerInvokeUsernameDialog	{92E9B700-3D91-4C6F-BBD8-99888D7A2387}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPTTLSPeerInvokeUsernameDialog
compEAPTTLSProperties	{266DE96B-8115-407A-B69C-1D2FDC8FEF42}	$(MSIBUILD_PRODUCT_NAME_UC)BINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPTTLSProperties
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"En.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
1252	Feature	Feature
featEAPMethods		EAP Peer Methods	Modules to support individual EAP methods	1	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	0
featEAPTTLS	featEAPMethods	TTLS	Tunneled Transport Layer Security	1	3	$(MSIBUILD_PRODUCT_NAME_UC)DIR	8
<<NOKEEP

"En.$(PLAT).$(CFG).Feature-2.idt" : "En.$(PLAT).$(CFG).Feature-2.idtx"
	copy /y $** $@ > NUL


######################################################################
# FeatureComponents

All :: "$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt"

"$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Feature_	Component_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
FeatureComponents	Feature_	Component_
featEAPTTLS	compEAPMethodEvents.dll.$(PLAT)
featEAPTTLS	compEAPHostAuthor
featEAPTTLS	compEAPTTLS.dll.$(PLAT)
featEAPTTLS	compEAPTTLSPeerDllPath
featEAPTTLS	compEAPTTLSPeerFriendlyName
featEAPTTLS	compEAPTTLSPeerInvokePasswordDialog
featEAPTTLS	compEAPTTLSPeerInvokeUsernameDialog
featEAPTTLS	compEAPTTLSProperties
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
fileEAPMethodEvents.dll.$(PLAT)	compEAPMethodEvents.dll.$(PLAT)	EAPMET~1.DLL|EAPMethodEvents.dll	0		0	1536	1
fileEAPTTLS.dll.$(PLAT)	compEAPTTLS.dll.$(PLAT)	EAPTTLS.dll	0		0	1536	1
<<NOKEEP


######################################################################
# Registry

All :: "$(LANG).$(PLAT).$(CFG).Registry-1.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
regEAPHostAuthor	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532		$(MSIBUILD_PRODUCT_NAME)	compEAPHostAuthor
regEAPTTLSPeerDllPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21	PeerDllPath	[#fileEAPTTLS.dll.$(PLAT)]	compEAPTTLSPeerDllPath
regEAPTTLSPeerFriendlyName	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21	PeerFriendlyName	@[#fileEAPTTLS.dll.$(PLAT)],-1	compEAPTTLSPeerFriendlyName
regEAPTTLSPeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21	PeerInvokePasswordDialog	#0	compEAPTTLSPeerInvokePasswordDialog
regEAPTTLSPeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21	PeerInvokeUsernameDialog	#0	compEAPTTLSPeerInvokeUsernameDialog
regEAPTTLSProperties	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\67532\21	Properties	#389871807	compEAPTTLSProperties
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSI\MSIBuild\MSM.mak"
