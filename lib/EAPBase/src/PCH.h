/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"
#include "../include/Method.h"
#include "../include/Module.h"
#include "../include/UIContext.h"

#include "../include/EAP.h"
#include "../include/EAPXML.h"

#include <WinStd/Cred.h>
#include <WinStd/ETW.h>
#include <WinStd/Sec.h>

#include <Windows.h>
#include <EapHostError.h> // include after Windows.h
#include <EventsETW.h>
