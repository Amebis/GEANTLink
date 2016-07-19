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

#include "StdAfx.h"


//////////////////////////////////////////////////////////////////////////
// wxEventMonitorFrame
//////////////////////////////////////////////////////////////////////////

wxBEGIN_EVENT_TABLE(wxEventMonitorFrame, wxEventMonitorFrameBase)
    EVT_MENU(wxID_EXIT, wxEventMonitorFrame::OnExit)
wxEND_EVENT_TABLE()


wxEventMonitorFrame::wxEventMonitorFrame() : wxEventMonitorFrameBase(NULL)
{
    // Load main window icons.
#ifdef __WINDOWS__
    wxIcon icon_small(wxT("00_EventMonitor.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
    wxIconBundle icons;
    icons.AddIcon(icon_small);
    icons.AddIcon(wxIcon(wxT("00_EventMonitor.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON)));
    SetIcons(icons);
#else
    wxIcon icon_small(wxICON(00_EventMonitor.ico));
    SetIcon(icon_small);
#endif

    // Restore persistent state of wxAuiManager manually, since m_mgr is not on the heap.
    wxPersistentAuiManager(&m_mgr).Restore();
}


void wxEventMonitorFrame::OnExit(wxCommandEvent& /*event*/)
{
    Close();
}


//////////////////////////////////////////////////////////////////////////
// wxPersistentEventMonitorFrame
//////////////////////////////////////////////////////////////////////////

wxPersistentEventMonitorFrame::wxPersistentEventMonitorFrame(wxEventMonitorFrame *wnd) : wxPersistentTLW(wnd)
{
}


void wxPersistentEventMonitorFrame::Save() const
{
    const wxEventMonitorFrame * const wnd = static_cast<const wxEventMonitorFrame*>(GetWindow());

    wxPersistentEventMonitorLogPanel(wnd->m_panel).Save();

    wxPersistentTLW::Save();
}


bool wxPersistentEventMonitorFrame::Restore()
{
    const bool r = wxPersistentTLW::Restore();

    wxEventMonitorFrame * const wnd = static_cast<wxEventMonitorFrame*>(GetWindow());

    wxPersistentEventMonitorLogPanel(wnd->m_panel).Restore();

    return r;
}
