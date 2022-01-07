/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"


//////////////////////////////////////////////////////////////////////////
// wxEventMonitorLogPanel
//////////////////////////////////////////////////////////////////////////

wxEventMonitorLogPanel::wxEventMonitorLogPanel(wxWindow* parent) : wxEventMonitorLogPanelBase(parent)
{
    // Set focus.
    m_log->SetFocus();
}


//////////////////////////////////////////////////////////////////////////
// wxPersistentEventMonitorLogPanel
//////////////////////////////////////////////////////////////////////////

wxPersistentEventMonitorLogPanel::wxPersistentEventMonitorLogPanel(wxEventMonitorLogPanel *wnd) : wxPersistentWindow<wxEventMonitorLogPanel>(wnd)
{
}


wxString wxPersistentEventMonitorLogPanel::GetKind() const
{
    return wxT(wxPERSIST_TLW_KIND);
}


void wxPersistentEventMonitorLogPanel::Save() const
{
    const wxEventMonitorLogPanel * const wnd = static_cast<const wxEventMonitorLogPanel*>(GetWindow());

    wxPersistentETWListCtrl(wnd->m_log).Save();
}


bool wxPersistentEventMonitorLogPanel::Restore()
{
    wxEventMonitorLogPanel * const wnd = static_cast<wxEventMonitorLogPanel*>(GetWindow());

    wxPersistentETWListCtrl(wnd->m_log).Restore();

    return true;
}
