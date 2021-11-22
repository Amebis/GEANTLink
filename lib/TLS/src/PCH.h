/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"
#include "../include/Method.h"
#include "../include/Module.h"

#include "../../MSCHAPv2/include/Method.h"

#include "../../EAPBase/include/EAPXML.h"
#include "../../EAPBase/include/UIContext.h"

#include <WinStd/Cred.h>
#include <WinStd/EAP.h>

#include <EapHostError.h>
#include <schnlsp.h>
#include <time.h>

#include <algorithm>
