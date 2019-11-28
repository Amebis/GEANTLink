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

#include "App.h"
#include "ETWLog.h"
#include "Frame.h"
#include "LogPanel.h"

#include "../lib/EAPBase_UI/include/EAP_UI.h"

#include "../include/Version.h"

#include <wxex/common.h>
#include <wxex/object.h>
#include <wxex/persist/auimanager.h>

#include <WinStd/COM.h>
#include <WinStd/ETW.h>
#include <WinStd/Win.h>

#include <Windows.h>
#include <Msi.h>
#include <tchar.h>

#include <in6addr.h>
#include <MSTcpIP.h>
#include <Sddl.h>
#include <tchar.h>

#include <utility>
#include <vector>
#include <set>

#include <EventsETW.h> // Must include after <Windows.h>
