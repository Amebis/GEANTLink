///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxEAP_UI.h"

///////////////////////////////////////////////////////////////////////////

wxEAPConfigBase::wxEAPConfigBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sz_content;
	sz_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sz_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	
	sz_content->Add( m_providers, 1, wxEXPAND|wxALL, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sz_content->Add( m_buttons, 0, wxEXPAND|wxALL, 5 );
	
	
	this->SetSizer( sz_content );
	this->Layout();
	sz_content->Fit( this );
}

wxEAPConfigBase::~wxEAPConfigBase()
{
}

wxEAPBannerPanelBase::wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHT ) );
	this->SetMinSize( wxSize( -1,48 ) );
	
	wxBoxSizer* sc_content;
	sc_content = new wxBoxSizer( wxVERTICAL );
	
	m_product_name = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_product_name->Wrap( -1 );
	m_product_name->SetFont( wxFont( 14, 70, 90, 90, false, wxEmptyString ) );
	m_product_name->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHTTEXT ) );
	
	sc_content->Add( m_product_name, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( sc_content );
	this->Layout();
	sc_content->Fit( this );
}

wxEAPBannerPanelBase::~wxEAPBannerPanelBase()
{
}

wxCredentialsConfigPanelBase::wxCredentialsConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_credentials;
	sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Client Credentials") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Manage your credentials to identify you during the connection attempt."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	m_allow_save = new wxCheckBox( sb_credentials->GetStaticBox(), wxID_ANY, _("Allow credentials to be &remembered in Credential Manager"), wxDefaultPosition, wxDefaultSize, 0 );
	m_allow_save->SetHelpText( _("Check if you would like to allow saving credentials to Windows Credential Manager") );
	
	sb_credentials_vert->Add( m_allow_save, 0, wxALL, 5 );
	
	wxBoxSizer* sb_cred_store_btn;
	sb_cred_store_btn = new wxBoxSizer( wxHORIZONTAL );
	
	m_cred_store_set = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_cred_store_set->SetToolTip( _("Adds a new certificate authority from the file to the list") );
	
	sb_cred_store_btn->Add( m_cred_store_set, 0, wxRIGHT|wxLEFT, 5 );
	
	m_cred_store_clear = new wxButton( sb_credentials->GetStaticBox(), wxID_ANY, _("&Clear Credentials"), wxDefaultPosition, wxDefaultSize, 0 );
	m_cred_store_clear->SetToolTip( _("Removes selected certificate authorities from the list") );
	
	sb_cred_store_btn->Add( m_cred_store_clear, 0, wxLEFT, 5 );
	
	
	sb_credentials_vert->Add( sb_cred_store_btn, 0, wxALIGN_RIGHT|wxALL, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
	
	// Connect Events
	m_allow_save->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnAllowSave ), NULL, this );
	m_cred_store_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnCredentialsSet ), NULL, this );
	m_cred_store_clear->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnCredentialsClear ), NULL, this );
}

wxCredentialsConfigPanelBase::~wxCredentialsConfigPanelBase()
{
	// Disconnect Events
	m_allow_save->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnAllowSave ), NULL, this );
	m_cred_store_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnCredentialsSet ), NULL, this );
	m_cred_store_clear->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxCredentialsConfigPanelBase::OnCredentialsClear ), NULL, this );
	
}

wxPasswordCredentialsPanelBase::wxPasswordCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_credentials;
	sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Session Credentials") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Please provide your user ID and password."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	wxGridSizer* sb_credentials_tbl;
	sb_credentials_tbl = new wxGridSizer( 0, 2, 0, 0 );
	
	m_identity_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("User ID:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_identity_label, 1, wxEXPAND, 5 );
	
	m_identity = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_identity->SetToolTip( _("Enter your user name here (user@domain.org, DOMAINUser, etc.)") );
	
	sb_credentials_tbl->Add( m_identity, 2, wxEXPAND, 5 );
	
	m_password_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Password:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_password_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_password_label, 1, wxEXPAND, 5 );
	
	m_password = new wxTextCtrl( sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_password->SetToolTip( _("Enter your password here") );
	
	sb_credentials_tbl->Add( m_password, 2, wxEXPAND, 5 );
	
	
	sb_credentials_vert->Add( sb_credentials_tbl, 0, wxEXPAND|wxALL, 5 );
	
	m_remember = new wxCheckBox( sb_credentials->GetStaticBox(), wxID_ANY, _("&Remember my credentials"), wxDefaultPosition, wxDefaultSize, 0 );
	m_remember->SetHelpText( _("Check if you would like to save the credentials to Windows Credential Manager") );
	
	sb_credentials_vert->Add( m_remember, 0, wxALL|wxEXPAND, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
}

wxPasswordCredentialsPanelBase::~wxPasswordCredentialsPanelBase()
{
}
