/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

// Prevent warnings from wxWidgets headers
#define _CRT_SECURE_NO_WARNINGS

#if EAPMETHOD_TYPE == 21
#include "../lib/TTLS_UI/include/Module.h"
#define EAPMETHOD_PEER_UI eap::peer_ttls_ui
#else
#error Unknown EAP Method type.
#endif

extern EAPMETHOD_PEER_UI g_peer;
