/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#include "../lib/EAPBase/include/Config.h"
#include "../lib/EAPBase/include/Credentials.h"
#include "../lib/EAPBase/include/Module.h"

#include <WinStd/Common.h>
#include <WinStd/Win.h>
#include <stdex/base64>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <shellapi.h>
#include <tchar.h>

#include <memory>
