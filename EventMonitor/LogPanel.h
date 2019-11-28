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
