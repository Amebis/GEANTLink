///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxEAP_UI.h"

///////////////////////////////////////////////////////////////////////////

wxEAPConfigDialogBase::wxEAPConfigDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	
	sb_content->Add( m_providers, 1, wxEXPAND|wxALL, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_content->Add( m_buttons, 0, wxEXPAND|wxALL, 5 );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
}

wxEAPConfigDialogBase::~wxEAPConfigDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
	
}

wxEAPCredentialsDialogBase::wxEAPCredentialsDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_panels = new wxBoxSizer( wxVERTICAL );
	
	
	sb_content->Add( m_panels, 1, wxEXPAND|wxALL, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_content->Add( m_buttons, 0, wxEXPAND|wxALL, 5 );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPCredentialsDialogBase::OnInitDialog ) );
}

wxEAPCredentialsDialogBase::~wxEAPCredentialsDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPCredentialsDialogBase::OnInitDialog ) );
	
}

wxEAPBannerPanelBase::wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHT ) );
	this->SetMinSize( wxSize( -1,48 ) );
	
	wxBoxSizer* sc_content;
	sc_content = new wxBoxSizer( wxVERTICAL );
	
	m_title = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_title->Wrap( -1 );
	m_title->SetFont( wxFont( 18, 70, 90, 90, false, wxEmptyString ) );
	m_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHTTEXT ) );
	
	sc_content->Add( m_title, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( sc_content );
	this->Layout();
	sc_content->Fit( this );
}

wxEAPBannerPanelBase::~wxEAPBannerPanelBase()
{
}

wxEAPCredentialsConfigPanelBase::wxEAPCredentialsConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_credentials;
	sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Client Credentials") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Manage your credentials stored in Windows Credential Manager."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	wxFlexGridSizer* sb_credentials_tbl;
	sb_credentials_tbl = new wxFlexGridSizer( 0, 2, 5, 5 );
	sb_credentials_tbl->AddGrowableCol( 1 );
	sb_credentials_tbl->SetFlexibleDirection( wxBOTH );
	sb_credentials_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_identity_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Identity:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_identity_label, 0, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	m_identity = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_identity->SetToolTip( _("Enter your user name here (user@domain.org, DOMAINUser, etc.)") );
	
	sb_credentials_tbl->Add( m_identity, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	sb_credentials_vert->Add( sb_credentials_tbl, 0, wxEXPAND|wxALL, 5 );
	
	wxBoxSizer* sb_buttons;
	sb_buttons = new wxBoxSizer( wxHORIZONTAL );
	
	m_set = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_set->SetToolTip( _("Click here to set or modify your credentials") );
	
	sb_buttons->Add( m_set, 0, wxRIGHT, 5 );
	
	m_clear = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Clear Credentials"), wxDefaultPosition, wxDefaultSize, 0 );
	m_clear->SetToolTip( _("Click to clear your credentials from Credential Manager.\nNote: You will be prompted to enter credentials when connecting.") );
	
	sb_buttons->Add( m_clear, 0, wxLEFT, 5 );
	
	
	sb_credentials_vert->Add( sb_buttons, 0, wxALIGN_RIGHT|wxALL, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSet ), NULL, this );
	m_clear->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClear ), NULL, this );
}

wxEAPCredentialsConfigPanelBase::~wxEAPCredentialsConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSet ), NULL, this );
	m_clear->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClear ), NULL, this );
	
}

wxPasswordCredentialsPanelBase::wxPasswordCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_credentials;
	sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Client Credentials") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Please provide your user ID and password."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	wxFlexGridSizer* sb_credentials_tbl;
	sb_credentials_tbl = new wxFlexGridSizer( 0, 2, 5, 5 );
	sb_credentials_tbl->AddGrowableCol( 1 );
	sb_credentials_tbl->SetFlexibleDirection( wxBOTH );
	sb_credentials_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_identity_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("User ID:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_identity_label, 0, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	m_identity = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_identity->SetToolTip( _("Enter your user name here (user@domain.org, DOMAIN\\User, etc.)") );
	
	sb_credentials_tbl->Add( m_identity, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	m_password_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Password:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_password_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_password_label, 0, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	m_password = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_password->SetToolTip( _("Enter your password here") );
	
	sb_credentials_tbl->Add( m_password, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	sb_credentials_vert->Add( sb_credentials_tbl, 0, wxEXPAND|wxALL, 5 );
	
	m_remember = new wxCheckBox( sb_credentials->GetStaticBox(), wxID_ANY, _("&Remember"), wxDefaultPosition, wxDefaultSize, 0 );
	m_remember->SetHelpText( _("Check if you would like to save username and password") );
	
	sb_credentials_vert->Add( m_remember, 0, wxALL|wxEXPAND, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
}

wxPasswordCredentialsPanelBase::~wxPasswordCredentialsPanelBase()
{
}
