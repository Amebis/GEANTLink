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

class wxEventMonitorApp;

#pragma once

#include "Frame.h"

#include <wx/app.h>
#include <wx/config.h>
#include <wx/intl.h>


///
/// EventMonitor application
///
class wxEventMonitorApp : public wxApp
{
public:
    wxEventMonitorApp();

    ///
    /// Called when application initializes.
    ///
    /// \returns
    /// - \c true if initialization succeeded
    /// - \c false otherwise
    ///
    virtual bool OnInit();

    ///
    /// Called when application uninitializes.
    ///
    /// \returns Result code to return to OS
    ///
    //virtual int OnExit();

public:
    wxLocale             m_locale;  ///< Current locale
};

wxDECLARE_APP(wxEventMonitorApp);
