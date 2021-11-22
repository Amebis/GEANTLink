/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#include "../include/TTLS.h"

#include "../include/Config.h"
#include "../include/Credentials.h"
#include "../include/Method.h"
#include "../include/Module.h"

#include "../../TLS/include/Method.h"

#include "../../PAP/include/Config.h"
#include "../../PAP/include/Method.h"

#include "../../MSCHAPv2/include/Config.h"
#include "../../MSCHAPv2/include/Method.h"
#include "../../MSCHAPv2/include/MSCHAPv2.h"

#include "../../GTC/include/Config.h"
#include "../../GTC/include/Method.h"

#include "../../EapHost/include/Config.h"
#include "../../EapHost/include/Method.h"

#include "../../EAPBase/include/EAPXML.h"

#include <WinStd/EAP.h>

#include <EapHostError.h>
#include <EapHostPeerTypes.h>
#include <eappapis.h>
#include <schannel.h>
