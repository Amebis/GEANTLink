/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"
#include "../include/Method.h"

#include "../../EAPBase/include/Module.h"

#include <stdex/memory.hpp>
#include <WinStd/Cred.h>
#include <WinStd/Win.h>

#include <Windows.h>
#include <EapHostError.h> // include after Windows.h
#include <EapHostPeerTypes.h>
#include <eappapis.h>
