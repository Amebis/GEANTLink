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
	m_providers->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	
	sb_content->Add( m_providers, 1, wxEXPAND|wxALL, 10 );
	
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

wxEAPNotePanelBase::wxEAPNotePanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INFOBK ) );
	
	wxBoxSizer* sb_note_horiz;
	sb_note_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_note_icon = new wxStaticBitmap( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_note_horiz->Add( m_note_icon, 0, wxALL, 5 );
	
	m_note_vert = new wxBoxSizer( wxVERTICAL );
	
	m_note_label = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_note_label->Wrap( 449 );
	m_note_vert->Add( m_note_label, 0, wxALL|wxEXPAND, 5 );
	
	
	sb_note_horiz->Add( m_note_vert, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_note_horiz );
	this->Layout();
}

wxEAPNotePanelBase::~wxEAPNotePanelBase()
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
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Manage credentials used to connect."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_cred_radio;
	sb_cred_radio = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* sz_own;
	sz_own = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* sz_own_inner;
	sz_own_inner = new wxBoxSizer( wxHORIZONTAL );
	
	m_own = new wxRadioButton( sb_credentials->GetStaticBox(), wxID_ANY, _("Use &own credentials:"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP );
	m_own->SetToolTip( _("Select this option if you have your unique credentials to connect") );
	
	sz_own_inner->Add( m_own, 2, wxEXPAND, 5 );
	
	m_own_identity = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_own_identity->SetToolTip( _("Your credentials loaded from Windows Credential Manager") );
	
	sz_own_inner->Add( m_own_identity, 3, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	sz_own->Add( sz_own_inner, 1, wxEXPAND|wxBOTTOM, 5 );
	
	wxBoxSizer* sb_buttons_own;
	sb_buttons_own = new wxBoxSizer( wxHORIZONTAL );
	
	m_own_clear = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Clear Credentials"), wxDefaultPosition, wxDefaultSize, 0 );
	m_own_clear->SetToolTip( _("Click to clear your credentials from Credential Manager.\nNote: You will be prompted to enter credentials when connecting.") );
	
	sb_buttons_own->Add( m_own_clear, 0, wxRIGHT, 5 );
	
	m_own_set = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_own_set->SetToolTip( _("Click here to set or modify your credentials") );
	
	sb_buttons_own->Add( m_own_set, 0, wxLEFT, 5 );
	
	
	sz_own->Add( sb_buttons_own, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_cred_radio->Add( sz_own, 0, wxEXPAND|wxBOTTOM, 5 );
	
	wxBoxSizer* sz_preshared;
	sz_preshared = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* sz_preshared_inner;
	sz_preshared_inner = new wxBoxSizer( wxHORIZONTAL );
	
	m_preshared = new wxRadioButton( sb_credentials->GetStaticBox(), wxID_ANY, _("Use &pre-shared credentials:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_preshared->SetToolTip( _("Select this options if all clients connect using the same credentials") );
	
	sz_preshared_inner->Add( m_preshared, 2, wxEXPAND, 5 );
	
	m_preshared_identity = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_preshared_identity->SetToolTip( _("Common (pre-shared) credentials") );
	
	sz_preshared_inner->Add( m_preshared_identity, 3, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	sz_preshared->Add( sz_preshared_inner, 1, wxEXPAND|wxBOTTOM, 5 );
	
	wxBoxSizer* sb_buttons_preshared;
	sb_buttons_preshared = new wxBoxSizer( wxHORIZONTAL );
	
	m_preshared_set = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_preshared_set->SetToolTip( _("Click here to set or modify your credentials") );
	
	sb_buttons_preshared->Add( m_preshared_set, 0, 0, 5 );
	
	
	sz_preshared->Add( sb_buttons_preshared, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_cred_radio->Add( sz_preshared, 0, wxEXPAND|wxTOP, 5 );
	
	
	sb_credentials_vert->Add( sb_cred_radio, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_own_clear->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClearOwn ), NULL, this );
	m_own_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetOwn ), NULL, this );
	m_preshared_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetPreshared ), NULL, this );
}

wxEAPCredentialsConfigPanelBase::~wxEAPCredentialsConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_own_clear->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClearOwn ), NULL, this );
	m_own_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetOwn ), NULL, this );
	m_preshared_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetPreshared ), NULL, this );
	
}

wxEAPCredentialsPanelPassBase::wxEAPCredentialsPanelPassBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
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

wxEAPCredentialsPanelPassBase::~wxEAPCredentialsPanelPassBase()
{
}
