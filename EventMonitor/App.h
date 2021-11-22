/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

///
/// \defgroup EventMonitor  Event Monitor
/// Real-time log of application events
///

class wxEventMonitorApp;

#pragma once

#include "Frame.h"

#include <wx/app.h>
#include <wx/config.h>
#include <wx/intl.h>


/// \addtogroup EventMonitor
/// @{

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

/// @}

wxDECLARE_APP(wxEventMonitorApp);
