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

///
/// EventMonitor trace log panel
///
class wxEventMonitorLogPanel;

///
/// Supports saving/restoring wxEventMonitorLogPanel state
///
class wxPersistentEventMonitorLogPanel;

#pragma once

#include "res/wxEventMonitor_UI.h"
#include <wx/persist/window.h>


class wxEventMonitorLogPanel : public wxEventMonitorLogPanelBase
{
public:
    wxEventMonitorLogPanel(wxWindow* parent);

    friend class wxPersistentEventMonitorLogPanel;   // Allow saving/restoring window state.
};


class wxPersistentEventMonitorLogPanel : public wxPersistentWindow<wxEventMonitorLogPanel>
{
public:
    wxPersistentEventMonitorLogPanel(wxEventMonitorLogPanel *wnd);

    virtual wxString GetKind() const;
    virtual void Save() const;
    virtual bool Restore();
};


inline wxPersistentObject *wxCreatePersistentObject(wxEventMonitorLogPanel *wnd)
{
    return new wxPersistentEventMonitorLogPanel(wnd);
}
