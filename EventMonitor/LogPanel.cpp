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
// wxEventMonitorLogPanel
//////////////////////////////////////////////////////////////////////////

wxEventMonitorLogPanel::wxEventMonitorLogPanel(wxWindow* parent) : wxEventMonitorLogPanelBase(parent)
{
    m_log->AppendColumn(_("Time"));
    m_log->AppendColumn(_("Source"));

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
    //const wxEventMonitorLogPanel * const wnd = static_cast<const wxEventMonitorLogPanel*>(GetWindow());

    //SaveValue(wxT("splitDecomposed"), wnd->m_splitterDecomposed->GetSashPosition());
    //SaveValue(wxT("splitComposed"  ), wnd->m_splitterComposed  ->GetSashPosition());
}


bool wxPersistentEventMonitorLogPanel::Restore()
{
    //wxEventMonitorLogPanel * const wnd = static_cast<wxEventMonitorLogPanel*>(GetWindow());

    //int sashVal;

    //if (RestoreValue(wxT("splitDecomposed"), &sashVal)) {
    //    // wxFormBuilder sets initial splitter stash in idle event handler after GUI settles. Overriding our loaded value. Disconnect it's idle event handler.
    //    wnd->m_splitterDecomposed->Disconnect( wxEVT_IDLE, wxIdleEventHandler( wxEventMonitorLogPanelBase::m_splitterDecomposedOnIdle ), NULL, wnd );
    //    wnd->m_splitterDecomposed->SetSashPosition(sashVal);
    //}

    //if (RestoreValue(wxT("splitComposed"), &sashVal)) {
    //    // wxFormBuilder sets initial splitter stash in idle event handler after GUI settles. Overriding our loaded value. Disconnect it's idle event handler.
    //    wnd->m_splitterComposed->Disconnect( wxEVT_IDLE, wxIdleEventHandler( wxEventMonitorLogPanelBase::m_splitterComposedOnIdle ), NULL, wnd );
    //    wnd->m_splitterComposed->SetSashPosition(sashVal);
    //}

    return true;
}
