/*
    Copyright 2015-2016 Amebis
    Copyright 2016 G�ANT

    This file is part of G�ANTLink.

    G�ANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    G�ANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with G�ANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include "StdAfx.h"


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

    // Save log's column widths.
    wxListItem col;
    col.SetMask(wxLIST_MASK_TEXT | wxLIST_MASK_WIDTH);
    for (int i = 0, n = wnd->m_log->GetColumnCount(); i < n; i++) {
        wnd->m_log->GetColumn(i, col);
        SaveValue(wxString::Format(wxT("Column%sWidth"), col.GetText().c_str()), col.GetWidth());
    }
}


bool wxPersistentEventMonitorLogPanel::Restore()
{
    wxEventMonitorLogPanel * const wnd = static_cast<wxEventMonitorLogPanel*>(GetWindow());

    // Restore log's column widths.
    wxListItem col;
    col.SetMask(wxLIST_MASK_TEXT);
    for (int i = 0, n = wnd->m_log->GetColumnCount(); i < n; i++) {
        wnd->m_log->GetColumn(i, col);

        int width;
        if (RestoreValue(wxString::Format(wxT("Column%sWidth"), col.GetText().c_str()), &width))
            wnd->m_log->SetColumnWidth(i, width);
    }

    return true;
}
