/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

class wxEventMonitorLogPanel;
class wxPersistentEventMonitorLogPanel;

#pragma once

#include "res/wxEventMonitor_UI.h"
#include <wx/persist/window.h>


/// \addtogroup EventMonitor
/// @{

///
/// EventMonitor trace log panel
///
class wxEventMonitorLogPanel : public wxEventMonitorLogPanelBase
{
public:
    ///
    /// Constructs EventMonitor log panel
    ///
    /// \param[in] parent  Parent window. Must not be \c NULL.
    ///
    wxEventMonitorLogPanel(wxWindow* parent);

    friend class wxPersistentEventMonitorLogPanel;   // Allow saving/restoring window state.
};


///
/// Supports saving/restoring `wxEventMonitorLogPanel` state
///
class wxPersistentEventMonitorLogPanel : public wxPersistentWindow<wxEventMonitorLogPanel>
{
public:
    ///
    /// Constructor for a persistent window object
    ///
    /// \param[in] wnd  Window this object will save/restore
    ///
    wxPersistentEventMonitorLogPanel(wxEventMonitorLogPanel *wnd);

    ///
    /// Returns the string uniquely identifying the objects supported by this adapter.
    ///
    /// \returns This implementation always returns `wxT(wxPERSIST_TLW_KIND)`
    ///
    virtual wxString GetKind() const;

    ///
    /// Saves the object properties
    ///
    virtual void Save() const;

    ///
    /// Restores the object properties
    ///
    /// \returns
    /// - \c true if the properties were successfully restored;
    /// - \c false otherwise.
    ///
    virtual bool Restore();
};


///
/// Creates persistent window object for `wxEventMonitorLogPanel` class window
///
inline wxPersistentObject *wxCreatePersistentObject(wxEventMonitorLogPanel *wnd)
{
    return new wxPersistentEventMonitorLogPanel(wnd);
}

/// @}
