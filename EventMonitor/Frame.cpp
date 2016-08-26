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


wxEventMonitorFrame::wxEventMonitorFrame(wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style, const wxString& name) :
    wxFrame(parent, id, title, pos, size, style, name)
{
    this->SetSizeHints(wxSize(150,150), wxDefaultSize);
    m_mgr.SetManagedWindow(this);
    m_mgr.SetFlags(wxAUI_MGR_DEFAULT);

    // Load main window icons.
#ifdef __WINDOWS__
    wxIconBundle icons;
    icons.AddIcon(wxIcon(wxT("00_EventMonitor.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON)));
    icons.AddIcon(wxIcon(wxT("00_EventMonitor.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXICON  ), ::GetSystemMetrics(SM_CYICON  )));
    this->SetIcons(icons);
#else
    this->SetIcon(wxIcon(wxICON(00_EventMonitor.ico)));
#endif

    wxString prod_name(wxT(PRODUCT_NAME_STR));
    wxString prod_status_bar;
    prod_status_bar.Printf(_("Toggles %s rows"), wxT(PRODUCT_NAME_STR));

    winstd::library lib_comres;
    lib_comres.load(_T("comres.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    winstd::library lib_ieframe;
    lib_ieframe.load(_T("ieframe.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    winstd::library lib_shell32;
    lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    wxSize size_menu(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
    wxSize size_tool(size_menu);

    m_menubar = new wxMenuBar(0);
    m_menuProgram = new wxMenu();
    wxMenuItem* m_menuItemExit;
    m_menuItemExit = new wxMenuItem(m_menuProgram, wxID_EXIT, wxString(_("E&xit")) + wxT('\t') + wxT("Alt+F4"), _("Quit this program"), wxITEM_NORMAL);
    m_menuItemExit->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(240), size_menu));
    m_menuProgram->Append(m_menuItemExit);

    m_menubar->Append(m_menuProgram, _("&Program"));

    m_menuEdit = new wxMenu();
    wxMenuItem* m_menuEditCopy;
    m_menuEditCopy = new wxMenuItem(m_menuEdit, wxID_COPY, wxString(wxEmptyString) , wxEmptyString, wxITEM_NORMAL);
    m_menuEditCopy->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(243), size_menu));
    m_menuEdit->Append(m_menuEditCopy);

    wxMenuItem* m_menuEditCopyAll;
    m_menuEditCopyAll = new wxMenuItem(m_menuEdit, wxID_COPY_ALL, wxString(_("Copy All")) + wxT('\t') + wxT("Ctrl+Shift+C"), _("Copies all rows to clipboard"), wxITEM_NORMAL);
    m_menuEditCopyAll->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(133), size_menu));
    m_menuEdit->Append(m_menuEditCopyAll);

    wxMenuItem* m_menuEditClear;
    m_menuEditClear = new wxMenuItem(m_menuEdit, wxID_CLEAR, wxString(_("Clear")) , _("Clears all rows from log"), wxITEM_NORMAL);
    m_menuEditClear->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(200), size_menu));
    m_menuEdit->Append(m_menuEditClear);

    m_menuEdit->AppendSeparator();

    wxMenuItem* m_menuEditSelectAll;
    m_menuEditSelectAll = new wxMenuItem(m_menuEdit, wxID_SELECT_ALL, wxString(_("Select &All")) + wxT('\t') + wxT("Ctrl+A"), _("Selects all rows"), wxITEM_NORMAL);
    m_menuEdit->Append(m_menuEditSelectAll);

    wxMenuItem* m_menuEditSelectNone;
    m_menuEditSelectNone = new wxMenuItem(m_menuEdit, wxID_SELECT_NONE, wxString(_("Select &None")) , _("Clears row selection"), wxITEM_NORMAL);
    m_menuEdit->Append(m_menuEditSelectNone);

    m_menubar->Append(m_menuEdit, _("&Edit"));

    m_menuView = new wxMenu();
    wxMenuItem* m_menuViewScrollAuto;
    m_menuViewScrollAuto = new wxMenuItem(m_menuView, wxID_VIEW_SCROLL_AUTO, wxString(_("Auto Scroll")) + wxT('\t') + wxT("Ctrl+S"), _("Automatically scrolls to the recent rows as they come-in."), wxITEM_CHECK);
    //m_menuViewScrollAuto->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(231), size_menu));
    m_menuView->Append(m_menuViewScrollAuto);

    m_menuView->AppendSeparator();

    wxMenuItem* m_menuViewSourceEapHost;
    m_menuViewSourceEapHost = new wxMenuItem(m_menuView, wxID_VIEW_SOURCE_EAPHOST, wxString("EapHost") , _("Toggles EapHost rows"), wxITEM_CHECK);
    //m_menuViewSourceEapHost->SetBitmaps(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(273), size_menu));
    m_menuView->Append(m_menuViewSourceEapHost);

    wxMenuItem* m_menuViewSourceSchannel;
    m_menuViewSourceSchannel = new wxMenuItem(m_menuView, wxID_VIEW_SOURCE_SCHANNEL, wxString("Schannel") , _("Toggles Schannel rows"), wxITEM_CHECK);
    //m_menuViewSourceSchannel->SetBitmaps(wxLoadIconFromResource(lib_ieframe, MAKEINTRESOURCE(36870), size_menu));
    m_menuView->Append(m_menuViewSourceSchannel);

    m_menuViewSourceProduct = new wxMenuItem(m_menuView, wxID_VIEW_SOURCE_PRODUCT, prod_name , prod_status_bar, wxITEM_CHECK);
    //m_menuViewSourceProduct->SetBitmaps(wxIcon(wxT("product.ico"), wxBITMAP_TYPE_ICO_RESOURCE, size_menu.GetWidth(), size_menu.GetHeight()));
    m_menuView->Append(m_menuViewSourceProduct);

    m_menuView->AppendSeparator();

    m_menuViewLevelVerbose = new wxMenuItem(m_menuView, wxID_VIEW_LEVEL_VERBOSE, wxString(_("Verbose")) + wxT('\t') + wxT("Ctrl+1"), _("Shows all rows up to verbose level"), wxITEM_RADIO);
    //m_menuViewLevelVerbose->SetBitmaps(wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2863), size_menu));
    m_menuView->Append(m_menuViewLevelVerbose);

    m_menuViewLevelInformation = new wxMenuItem(m_menuView, wxID_VIEW_LEVEL_INFORMATION, wxString(_("Informational")) + wxT('\t') + wxT("Ctrl+2"), _("Shows all rows up to informational level"), wxITEM_RADIO);
    //m_menuViewLevelInformation->SetBitmaps(wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2859), size_menu));
    m_menuView->Append(m_menuViewLevelInformation);

    m_menuViewLevelWarning = new wxMenuItem(m_menuView, wxID_VIEW_LEVEL_WARNING, wxString(_("Warning")) + wxT('\t') + wxT("Ctrl+3"), _("Shows all rows up to warning level"), wxITEM_RADIO);
    //m_menuViewLevelWarning->SetBitmaps(wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2865), size_menu));
    m_menuView->Append(m_menuViewLevelWarning);

    m_menuViewLevelError = new wxMenuItem(m_menuView, wxID_VIEW_LEVEL_ERROR, wxString(_("Error")) + wxT('\t') + wxT("Ctrl+4"), _("Shows all rows up to error level"), wxITEM_RADIO);
    //m_menuViewLevelError->SetBitmaps(wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2861), size_menu));
    m_menuView->Append(m_menuViewLevelError);

    m_menubar->Append(m_menuView, _("&View"));

    this->SetMenuBar(m_menubar);

    m_toolbarEdit = new wxAuiToolBar(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxAUI_TB_HORZ_LAYOUT);
    m_toolEditCopy = m_toolbarEdit->AddTool(wxID_COPY, _("Copy"), wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(243), size_tool), wxNullBitmap, wxITEM_NORMAL, _("Copy"), _("Copies selected rows to clipboard"), NULL);

    m_toolEditCopyAll = m_toolbarEdit->AddTool(wxID_COPY_ALL, _("Copy All"), wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(133), size_tool), wxNullBitmap, wxITEM_NORMAL, _("Copy All"), _("Copies all rows to clipboard"), NULL);

    m_toolEditClear = m_toolbarEdit->AddTool(wxID_CLEAR, _("Clear"), wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(200), size_tool), wxNullBitmap, wxITEM_NORMAL, _("Clear All"), _("Clears all rows from the log"), NULL);

    m_toolbarEdit->Realize();
    m_mgr.AddPane(m_toolbarEdit, wxAuiPaneInfo().Name(wxT("ToolbarEdit")).Top().Caption(_("Edit")).PinButton(true).Dock().Resizable().FloatingSize(wxDefaultSize).LeftDockable(false).RightDockable(false).Layer(1).ToolbarPane());

    m_toolbarView = new wxAuiToolBar(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxAUI_TB_HORZ_LAYOUT);
    m_toolViewScrollAuto = m_toolbarView->AddTool(wxID_VIEW_SCROLL_AUTO, _("Auto Scroll"), wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(231), size_tool), wxNullBitmap, wxITEM_CHECK, _("Automatically scroll"), _("Automatically scrolls to the recent rows as they come-in."), NULL);

    m_toolbarView->AddSeparator();

    m_toolViewSourceEapHost = m_toolbarView->AddTool(wxID_VIEW_SOURCE_EAPHOST, "EapHost", wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(273), size_tool), wxNullBitmap, wxITEM_CHECK, _("Toggles EapHost rows"), _("Toggles EapHost rows"), NULL);

    m_toolViewSourceSchannel = m_toolbarView->AddTool(wxID_VIEW_SOURCE_SCHANNEL, "Schannel", wxLoadIconFromResource(lib_ieframe, MAKEINTRESOURCE(36870), size_tool), wxNullBitmap, wxITEM_CHECK, _("Toggles Schannel rows"), _("Toggles Schannel rows"), NULL);

    m_toolViewSourceProduct = m_toolbarView->AddTool(wxID_VIEW_SOURCE_PRODUCT, prod_name, wxIcon(wxT("product.ico"), wxBITMAP_TYPE_ICO_RESOURCE, size_tool.GetWidth(), size_tool.GetHeight()), wxNullBitmap, wxITEM_CHECK, prod_status_bar, prod_status_bar, NULL);

    m_toolbarView->AddSeparator();

    m_toolViewLevelVerbose = m_toolbarView->AddTool(wxID_VIEW_LEVEL_VERBOSE, _("Verbose"), wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2863), size_tool), wxNullBitmap, wxITEM_RADIO, _("Shows verbose rows"), _("Shows all rows up to verbose level"), NULL);

    m_toolViewLevelInformation = m_toolbarView->AddTool(wxID_VIEW_LEVEL_INFORMATION, _("Informational"), wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2859), size_tool), wxNullBitmap, wxITEM_RADIO, _("Shows informational rows"), _("Shows all rows up to informational level"), NULL);

    m_toolViewLevelWarning = m_toolbarView->AddTool(wxID_VIEW_LEVEL_WARNING, _("Warning"), wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2865), size_tool), wxNullBitmap, wxITEM_RADIO, _("Shows warning rows"), _("Shows all rows up to warning level"), NULL);

    m_toolViewLevelError = m_toolbarView->AddTool(wxID_VIEW_LEVEL_ERROR, _("Error"), wxLoadIconFromResource(lib_comres, MAKEINTRESOURCE(2861), size_tool), wxNullBitmap, wxITEM_RADIO, _("Shows Error rows"), _("Shows all rows up to error level"), NULL);

    m_toolbarView->Realize();
    m_mgr.AddPane(m_toolbarView, wxAuiPaneInfo().Name(wxT("ToolbarView")).Top().Caption(_("View")).PinButton(true).Dock().Resizable().FloatingSize(wxDefaultSize).LeftDockable(false).RightDockable(false).Layer(1).ToolbarPane());

    m_panel = new wxEventMonitorLogPanel(this);

    m_mgr.AddPane(m_panel, wxAuiPaneInfo() .Name(wxT("LogPanel")).Center() .Caption(_("Log Trace")).CaptionVisible(false).CloseButton(false).PaneBorder(false).Dock().Resizable().FloatingSize(wxDefaultSize).Floatable(false));

    m_statusBar = this->CreateStatusBar(1, wxST_SIZEGRIP, wxID_ANY);

    m_mgr.Update();
    this->Centre(wxBOTH);

    // Restore persistent state of wxAuiManager manually, since m_mgr is not on the heap.
    wxPersistentAuiManager(&m_mgr).Restore();

    // Connect Events
    this->Connect(wxID_EXIT                ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnExit                    ));
    this->Connect(wxID_COPY                ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditCopyUpdate          ));
    this->Connect(wxID_COPY                ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditCopy                ));
    this->Connect(wxID_COPY_ALL            ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditCopyAllUpdate       ));
    this->Connect(wxID_COPY_ALL            ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditCopyAll             ));
    this->Connect(wxID_CLEAR               ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditClearUpdate         ));
    this->Connect(wxID_CLEAR               ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditClear               ));
    this->Connect(wxID_SELECT_ALL          ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditSelectAllUpdate     ));
    this->Connect(wxID_SELECT_ALL          ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditSelectAll           ));
    this->Connect(wxID_SELECT_NONE         ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditSelectNoneUpdate    ));
    this->Connect(wxID_SELECT_NONE         ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditSelectNone          ));
    this->Connect(wxID_VIEW_SCROLL_AUTO    ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewScrollUpdate        ));
    this->Connect(wxID_VIEW_SCROLL_AUTO    ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewScroll              ));
    this->Connect(wxID_VIEW_SOURCE_EAPHOST ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceEapHostUpdate ));
    this->Connect(wxID_VIEW_SOURCE_EAPHOST ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceEapHost       ));
    this->Connect(wxID_VIEW_SOURCE_SCHANNEL,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceSchannelUpdate));
    this->Connect(wxID_VIEW_SOURCE_SCHANNEL,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceSchannel      ));
    this->Connect(wxID_VIEW_SOURCE_PRODUCT ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceProductUpdate ));
    this->Connect(wxID_VIEW_SOURCE_PRODUCT ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceProduct       ));
    this->Connect(wxID_VIEW_LEVEL_VERBOSE  , wxID_VIEW_LEVEL_ERROR, wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewLevelUpdate         ));
    this->Connect(wxID_VIEW_LEVEL_VERBOSE  , wxID_VIEW_LEVEL_ERROR, wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewLevel               ));
}


wxEventMonitorFrame::~wxEventMonitorFrame()
{
    // Disconnect Events
    this->Disconnect(wxID_EXIT               ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnExit                   ));
    this->Disconnect(wxID_COPY               ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditCopyUpdate         ));
    this->Disconnect(wxID_COPY               ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditCopy               ));
    this->Disconnect(wxID_COPY_ALL           ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditCopyAllUpdate      ));
    this->Disconnect(wxID_COPY_ALL           ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditCopyAll            ));
    this->Disconnect(wxID_CLEAR              ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditClearUpdate        ));
    this->Disconnect(wxID_CLEAR              ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditClear              ));
    this->Disconnect(wxID_SELECT_ALL         ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditSelectAllUpdate    ));
    this->Disconnect(wxID_SELECT_ALL         ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditSelectAll          ));
    this->Disconnect(wxID_SELECT_NONE        ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnEditSelectNoneUpdate   ));
    this->Disconnect(wxID_SELECT_NONE        ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnEditSelectNone         ));
    this->Disconnect(wxID_VIEW_SCROLL_AUTO   ,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewScrollUpdate       ));
    this->Disconnect(wxID_VIEW_SCROLL_AUTO   ,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewScroll             ));
    this->Disconnect(wxID_VIEW_SOURCE_EAPHOST,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceEapHostUpdate));
    this->Disconnect(wxID_VIEW_SOURCE_EAPHOST,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceEapHost      ));
    this->Disconnect(wxID_VIEW_SOURCE_SCHANNEL,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceSchannelUpdate));
    this->Disconnect(wxID_VIEW_SOURCE_SCHANNEL,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceSchannel      ));
    this->Disconnect(wxID_VIEW_SOURCE_PRODUCT,                        wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewSourceProductUpdate));
    this->Disconnect(wxID_VIEW_SOURCE_PRODUCT,                        wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewSourceProduct      ));
    this->Disconnect(wxID_VIEW_LEVEL_VERBOSE , wxID_VIEW_LEVEL_ERROR, wxEVT_UPDATE_UI, wxUpdateUIEventHandler(wxEventMonitorFrame::OnViewLevelUpdate        ));
    this->Disconnect(wxID_VIEW_LEVEL_VERBOSE , wxID_VIEW_LEVEL_ERROR, wxEVT_MENU     , wxCommandEventHandler (wxEventMonitorFrame::OnViewLevel              ));

    m_mgr.UnInit();

}


void wxEventMonitorFrame::OnExit(wxCommandEvent& /*event*/)
{
    Close();
}


void wxEventMonitorFrame::OnEditCopyUpdate(wxUpdateUIEvent& event)
{
    event.Enable(m_panel->m_log->GetSelectedItemCount() != 0);
}


void wxEventMonitorFrame::OnEditCopy(wxCommandEvent& /*event*/)
{
    m_panel->m_log->CopySelected();
}


void wxEventMonitorFrame::OnEditCopyAllUpdate(wxUpdateUIEvent& event)
{
    event.Enable(!m_panel->m_log->IsEmpty());
}


void wxEventMonitorFrame::OnEditCopyAll(wxCommandEvent& /*event*/)
{
    m_panel->m_log->CopyAll();
}


void wxEventMonitorFrame::OnEditClearUpdate(wxUpdateUIEvent& event)
{
    event.Enable(!m_panel->m_log->IsEmpty());
}


void wxEventMonitorFrame::OnEditClear(wxCommandEvent& /*event*/)
{
    m_panel->m_log->ClearAll();
}


void wxEventMonitorFrame::OnEditSelectAllUpdate(wxUpdateUIEvent& event)
{
    event.Enable(m_panel->m_log->GetSelectedItemCount() != m_panel->m_log->GetItemCount());
}


void wxEventMonitorFrame::OnEditSelectAll(wxCommandEvent& /*event*/)
{
    m_panel->m_log->SelectAll();
}


void wxEventMonitorFrame::OnEditSelectNoneUpdate(wxUpdateUIEvent& event)
{
    event.Enable(m_panel->m_log->GetSelectedItemCount() != 0);
}


void wxEventMonitorFrame::OnEditSelectNone(wxCommandEvent& /*event*/)
{
    m_panel->m_log->SelectNone();
}


void wxEventMonitorFrame::OnViewScrollUpdate(wxUpdateUIEvent& event)
{
    event.Check(m_panel->m_log->m_scroll_auto);
}


void wxEventMonitorFrame::OnViewScroll(wxCommandEvent& event)
{
    m_panel->m_log->m_scroll_auto = event.IsChecked();
    if (m_panel->m_log->m_scroll_auto) {
        long count = m_panel->m_log->GetItemCount();
        if (count)
            m_panel->m_log->EnsureVisible(count - 1);
    }
}


void wxEventMonitorFrame::OnViewSourceEapHostUpdate(wxUpdateUIEvent& event)
{
    event.Check(m_panel->m_log->m_source_eaphost);
}


void wxEventMonitorFrame::OnViewSourceEapHost(wxCommandEvent& event)
{
    bool state_new = event.IsChecked();
    if (m_panel->m_log->m_source_eaphost != state_new) {
        m_panel->m_log->m_source_eaphost = state_new;
        m_panel->m_log->RebuildItems();
    }
}


void wxEventMonitorFrame::OnViewSourceSchannelUpdate(wxUpdateUIEvent& event)
{
    event.Check(m_panel->m_log->m_source_schannel);
}


void wxEventMonitorFrame::OnViewSourceSchannel(wxCommandEvent& event)
{
    bool state_new = event.IsChecked();
    if (m_panel->m_log->m_source_schannel != state_new) {
        m_panel->m_log->m_source_schannel = state_new;
        m_panel->m_log->RebuildItems();
    }
}


void wxEventMonitorFrame::OnViewSourceProductUpdate(wxUpdateUIEvent& event)
{
    event.Check(m_panel->m_log->m_source_product);
}


void wxEventMonitorFrame::OnViewSourceProduct(wxCommandEvent& event)
{
    bool state_new = event.IsChecked();
    if (m_panel->m_log->m_source_product != state_new) {
        m_panel->m_log->m_source_product = state_new;
        m_panel->m_log->RebuildItems();
    }
}


void wxEventMonitorFrame::OnViewLevelUpdate(wxUpdateUIEvent& event)
{
    event.Check(TRACE_LEVEL_ERROR + wxID_VIEW_LEVEL_ERROR - event.GetId() == m_panel->m_log->m_level);
}


void wxEventMonitorFrame::OnViewLevel(wxCommandEvent& event)
{
    UCHAR state_new = TRACE_LEVEL_ERROR + wxID_VIEW_LEVEL_ERROR - event.GetId();
    if (m_panel->m_log->m_level != state_new) {
        m_panel->m_log->m_level = state_new;
        m_panel->m_log->RebuildItems();
    }
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
