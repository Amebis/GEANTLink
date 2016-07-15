///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "StdAfx.h"

#include "wxEventMonitor_UI.h"

///////////////////////////////////////////////////////////////////////////

wxEventMonitorFrameBase::wxEventMonitorFrameBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : wxFrame( parent, id, title, pos, size, style, name )
{
	this->SetSizeHints( wxSize( 150,150 ), wxDefaultSize );
	m_mgr.SetManagedWindow(this);
	m_mgr.SetFlags(wxAUI_MGR_DEFAULT);
	
	m_menubar = new wxMenuBar( 0 );
	m_menuProgram = new wxMenu();
	wxMenuItem* m_menuItemExit;
	m_menuItemExit = new wxMenuItem( m_menuProgram, wxID_EXIT, wxString( _("E&xit") ) + wxT('\t') + wxT("Alt+F4"), _("Quit this program"), wxITEM_NORMAL );
	m_menuProgram->Append( m_menuItemExit );
	
	m_menubar->Append( m_menuProgram, _("&Program") ); 
	
	this->SetMenuBar( m_menubar );
	
	m_panel = new wxEventMonitorLogPanel( this );
	
	m_mgr.AddPane( m_panel, wxAuiPaneInfo() .Name( wxT("LogPanel") ).Center() .Caption( _("Log Trace") ).CaptionVisible( false ).CloseButton( false ).PaneBorder( false ).Dock().Resizable().FloatingSize( wxDefaultSize ).Floatable( false ) );
	
	m_statusBar = this->CreateStatusBar( 1, wxST_SIZEGRIP, wxID_ANY );
	
	m_mgr.Update();
	this->Centre( wxBOTH );
	
	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( wxEventMonitorFrameBase::OnClose ) );
	this->Connect( wxEVT_ICONIZE, wxIconizeEventHandler( wxEventMonitorFrameBase::OnIconize ) );
	this->Connect( wxEVT_IDLE, wxIdleEventHandler( wxEventMonitorFrameBase::OnIdle ) );
}

wxEventMonitorFrameBase::~wxEventMonitorFrameBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( wxEventMonitorFrameBase::OnClose ) );
	this->Disconnect( wxEVT_ICONIZE, wxIconizeEventHandler( wxEventMonitorFrameBase::OnIconize ) );
	this->Disconnect( wxEVT_IDLE, wxIdleEventHandler( wxEventMonitorFrameBase::OnIdle ) );
	
	m_mgr.UnInit();
	
}

wxEventMonitorLogPanelBase::wxEventMonitorLogPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : wxPanel( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizerMain;
	bSizerMain = new wxBoxSizer( wxVERTICAL );
	
	m_log = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_ALIGN_TOP|wxLC_AUTOARRANGE|wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_SINGLE_SEL|wxNO_BORDER );
	bSizerMain->Add( m_log, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( bSizerMain );
	this->Layout();
	bSizerMain->Fit( this );
}

wxEventMonitorLogPanelBase::~wxEventMonitorLogPanelBase()
{
}
