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

RegisterDLLs ::
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerDllPath"              /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(EAPMETHOD_NAME).dll"     /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerConfigUIPath"         /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(EAPMETHOD_NAME)_UI.dll"  /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerIdentityPath"         /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(EAPMETHOD_NAME)_UI.dll"  /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerInteractiveUIPath"    /t REG_SZ    /d "$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(EAPMETHOD_NAME)_UI.dll"  /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerFriendlyName"         /t REG_SZ    /d "@$(MAKEDIR)\$(OUTPUT_DIR)\$(PLAT).Debug\$(EAPMETHOD_NAME).dll,-1" /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerInvokePasswordDialog" /t REG_DWORD /d 0                                                                  /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "PeerInvokeUsernameDialog" /t REG_DWORD /d 0                                                                  /f > NUL
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\EapHost\Methods\$(EAPMETHOD_AUTHOR_ID)\$(EAPMETHOD_TYPE)" /v "Properties"               /t REG_DWORD /d 389871807                                                          /f > NUL
