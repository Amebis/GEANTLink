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

#define _CRT_SECURE_NO_WARNINGS // Prevent warnings from wxWidgets headers

#include "../include/Module.h"
#include "../include/TTLS_UI.h"

#include "../../EAPMsg_UI/include/EAPMsg_UI.h"
#include "../../PAP_UI/include/PAP_UI.h"
#include "../../MSCHAPv2_UI/include/MSCHAPv2_UI.h"

#include <wxex/common.h>

#include <wx/app.h>
#include <wx/thread.h>
