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

#include "LogPanel.h"

#include "wxEventMonitor_UI.h"

#include <wx/frame.h>
#include <wx/menu.h>
#include <wx/statusbr.h>
#include <wx/aui/auibar.h>
#include <wx/aui/framemanager.h>
#include <wx/persist/toplevel.h>

#include <WinStd/Win.h>


class wxEventMonitorFrame : public wxFrame
{
protected:
    enum {
        wxID_COPY_ALL = 1000,
        wxID_SELECT_ALL,
        wxID_SELECT_NONE,
        wxID_VIEW_SCROLL_AUTO,
        wxID_VIEW_SOURCE_EAPHOST,
        wxID_VIEW_SOURCE_SCHANNEL,
        wxID_VIEW_SOURCE_PRODUCT,
        wxID_VIEW_LEVEL_VERBOSE,
        wxID_VIEW_LEVEL_INFORMATION,
        wxID_VIEW_LEVEL_WARNING,
        wxID_VIEW_LEVEL_ERROR
    };

public:
    wxEventMonitorFrame(wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Event Monitor"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize(600,400), long style = wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL, const wxString& name = wxT("EventMonitor"));
    ~wxEventMonitorFrame();

    friend class wxPersistentEventMonitorFrame;

protected:
    void OnExit(wxCommandEvent& event);
    void OnEditCopyUpdate(wxUpdateUIEvent& event);
    void OnEditCopy(wxCommandEvent& event);
    void OnEditCopyAllUpdate(wxUpdateUIEvent& event);
    void OnEditCopyAll(wxCommandEvent& event);
    void OnEditClearUpdate(wxUpdateUIEvent& event);
    void OnEditClear(wxCommandEvent& event);
    void OnEditSelectAllUpdate(wxUpdateUIEvent& event);
    void OnEditSelectAll(wxCommandEvent& event);
    void OnEditSelectNoneUpdate(wxUpdateUIEvent& event);
    void OnEditSelectNone(wxCommandEvent& event);
    void OnViewScrollUpdate(wxUpdateUIEvent& event);
    void OnViewScroll(wxCommandEvent& event);
    void OnViewSourceEapHostUpdate(wxUpdateUIEvent& event);
    void OnViewSourceEapHost(wxCommandEvent& event);
    void OnViewSourceSchannelUpdate(wxUpdateUIEvent& event);
    void OnViewSourceSchannel(wxCommandEvent& event);
    void OnViewSourceProductUpdate(wxUpdateUIEvent& event);
    void OnViewSourceProduct(wxCommandEvent& event);
    void OnViewLevelUpdate(wxUpdateUIEvent& event);
    void OnViewLevel(wxCommandEvent& event);

protected:
    wxMenuBar* m_menubar;
    wxMenu* m_menuProgram;
    wxMenu* m_menuEdit;
    wxMenu* m_menuView;
    wxMenuItem* m_menuViewSourceProduct;
    wxMenuItem* m_menuViewLevelVerbose;
    wxMenuItem* m_menuViewLevelInformation;
    wxMenuItem* m_menuViewLevelWarning;
    wxMenuItem* m_menuViewLevelError;
    wxAuiToolBar* m_toolbarEdit;
    wxAuiToolBarItem* m_toolEditCopy;
    wxAuiToolBarItem* m_toolEditCopyAll;
    wxAuiToolBarItem* m_toolEditClear;
    wxAuiToolBar* m_toolbarView;
    wxAuiToolBarItem* m_toolViewScrollAuto;
    wxAuiToolBarItem* m_toolViewSourceEapHost;
    wxAuiToolBarItem* m_toolViewSourceSchannel;
    wxAuiToolBarItem* m_toolViewSourceProduct;
    wxAuiToolBarItem* m_toolViewLevelVerbose;
    wxAuiToolBarItem* m_toolViewLevelInformation;
    wxAuiToolBarItem* m_toolViewLevelWarning;
    wxAuiToolBarItem* m_toolViewLevelError;
    wxStatusBar* m_statusBar;
    wxEventMonitorLogPanel* m_panel;
    wxAuiManager m_mgr;
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
