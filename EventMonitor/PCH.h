/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
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
