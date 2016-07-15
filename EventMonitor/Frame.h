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
/// EventMonitor main frame
///
class wxEventMonitorFrame;

///
/// Supports saving/restoring wxEventMonitorFrame GUI state
///
class wxPersistentEventMonitorFrame;

#pragma once;

#include "wxEventMonitor_UI.h"
#include <wx/persist/toplevel.h>


class wxEventMonitorFrame : public wxEventMonitorFrameBase
{
public:
    wxEventMonitorFrame();

    friend class wxPersistentEventMonitorFrame;

protected:
    void OnExit(wxCommandEvent& event);
    wxDECLARE_EVENT_TABLE();
};


class wxPersistentEventMonitorFrame : public wxPersistentTLW
{
public:
    wxPersistentEventMonitorFrame(wxEventMonitorFrame *wnd);

    virtual void Save() const;
    virtual bool Restore();
};


inline wxPersistentObject *wxCreatePersistentObject(wxEventMonitorFrame *wnd)
{
    return new wxPersistentEventMonitorFrame(wnd);
}
