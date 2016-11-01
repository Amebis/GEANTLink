/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GÉANTLink.

    GÉANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GÉANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"
#include "../include/Method.h"
#include "../include/Module.h"

#include "../../PAP/include/Config.h"
#include "../../PAP/include/Method.h"

#include "../../MSCHAPv2/include/Config.h"
#include "../../MSCHAPv2/include/Method.h"
#include "../../MSCHAPv2/include/MSCHAPv2.h"

#include "../../EapHost/include/Config.h"
#include "../../EapHost/include/Method.h"

#include "../../EAPBase/include/EAPXML.h"

#include <WinStd/EAP.h>

#include <EapHostError.h>
#include <EapHostPeerTypes.h>
#include <eappapis.h>
#include <schannel.h>
