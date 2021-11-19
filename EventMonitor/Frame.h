/*
    Copyright 2015-2020 Amebis
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

class wxEventMonitorFrame;
class wxPersistentEventMonitorFrame;

#pragma once

#include "LogPanel.h"

#include <wx/frame.h>
#include <wx/menu.h>
#include <wx/statusbr.h>
#include <wx/aui/auibar.h>
#include <wx/aui/framemanager.h>
#include <wx/persist/toplevel.h>

#include <WinStd/Win.h>

#pragma warning(push)
#pragma warning(disable: 26444)


/// \addtogroup EventMonitor
/// @{

///
/// EventMonitor main frame
///
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
        wxID_VIEW_LEVEL_ERROR,
        wxID_VIEW_TOOLBAR_EDIT,
        wxID_VIEW_TOOLBAR_VIEW,
    };

public:
    ///
    /// Creates an EventMonitor frame window
    ///
    /// \param[in] parent  The window parent. This may be \c NULL. If it is non-NULL, the frame will always be displayed on top of the parent window on Windows.
    /// \param[in] id      The window identifier. It may take a value of \c wxID_ANY to indicate a default value.
    /// \param[in] title   The caption to be displayed on the frame's title bar.
    /// \param[in] pos     The window position. The value \c wxDefaultPosition indicates a default position, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] size    The window size. The value \c wxDefaultSize indicates a default size, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] style   The window style. See `wxFrame` class description.
    /// \param[in] name    The name of the window. This parameter is used to associate a name with the item, allowing the application user to set Motif resource values for individual windows.
    ///
    wxEventMonitorFrame(wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Event Monitor"), const wxPoint& pos = wxDefaultPosition, long style = wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL, const wxString& name = wxT("EventMonitor"));

    ///
    /// Destructor
    ///
    ~wxEventMonitorFrame();

    friend class wxPersistentEventMonitorFrame;

protected:
    /// \cond internal
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
    void OnViewSourceUpdate(wxUpdateUIEvent& event);
    void OnViewSource(wxCommandEvent& event);
    void OnViewLevelUpdate(wxUpdateUIEvent& event);
    void OnViewLevel(wxCommandEvent& event);
    void OnViewToolbarUpdate(wxUpdateUIEvent& event);
    void OnViewToolbar(wxCommandEvent& event);
    /// \endcond

protected:
    /// \cond internal
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
    /// \endcond
};


///
/// Supports saving/restoring `wxEventMonitorFrame` GUI state
///
class wxPersistentEventMonitorFrame : public wxPersistentTLW
{
public:
    ///
    /// Constructor for a persistent window object
    ///
    /// \param[in] wnd  Window this object will save/restore
    ///
    wxPersistentEventMonitorFrame(wxEventMonitorFrame *wnd);

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
/// Creates persistent window object for `wxETWListCtrl` class window
///
inline wxPersistentObject *wxCreatePersistentObject(wxEventMonitorFrame *wnd)
{
    return new wxPersistentEventMonitorFrame(wnd);
}

/// @}

#pragma warning(pop)
