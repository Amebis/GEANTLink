#    SPDX-License-Identifier: GPL-3.0-or-later
#    Copyright © 1991-2022 Amebis
#    Copyright © 2016 GÉANT

RegisterDLLs ::
	regsvr32.exe /s "$(MAKEDIR)\output\$(PLAT).Debug\$(EAPMETHOD_NAME).dll"
	regsvr32.exe /s "$(MAKEDIR)\output\$(PLAT).Debug\$(EAPMETHOD_NAME)_UI.dll"
