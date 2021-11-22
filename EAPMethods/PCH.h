/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#if EAPMETHOD_TYPE == 21
#include "../lib/TTLS/include/Method.h"
#include "../lib/TTLS/include/Module.h"
#define EAPMETHOD_PEER eap::peer_ttls
#else
#error Unknown EAP Method type.
#endif

extern EAPMETHOD_PEER g_peer;
