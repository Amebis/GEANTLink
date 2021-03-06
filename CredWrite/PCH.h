/*
    Copyright 2015-2020 Amebis
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

#include "../lib/EAPBase/include/Config.h"
#include "../lib/EAPBase/include/Credentials.h"
#include "../lib/EAPBase/include/Module.h"

#include <WinStd/Common.h>
#include <WinStd/Base64.h>
#include <WinStd/Win.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <shellapi.h>
#include <tchar.h>

#include <memory>
