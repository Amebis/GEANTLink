///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Aug  8 2018)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
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
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	m_providers->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	
	sb_content->Add( m_providers, 1, wxEXPAND|wxALL, FromDIP(10) );
	
	wxBoxSizer* sb_bottom_horiz;
	sb_bottom_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	wxBoxSizer* sb_bottom_horiz_inner;
	sb_bottom_horiz_inner = new wxBoxSizer( wxHORIZONTAL );
	
	m_prov_add = new wxButton( this, wxID_ANY, _("+"), wxDefaultPosition, FromDIP(wxSize( 30,-1 )), 0 );
	m_prov_add->SetToolTip( _("Adds new provider") );
	
	sb_bottom_horiz_inner->Add( m_prov_add, 0, wxALL, FromDIP(5) );
	
	m_prov_remove = new wxButton( this, wxID_ANY, _("-"), wxDefaultPosition, FromDIP(wxSize( 30,-1 )), 0 );
	m_prov_remove->SetToolTip( _("Removes selected provider") );
	
	sb_bottom_horiz_inner->Add( m_prov_remove, 0, wxALL, FromDIP(5) );
	
	m_prov_advanced = new wxButton( this, wxID_ANY, _("Advanced..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_prov_advanced->SetToolTip( _("Opens dialog with provider settings") );
	
	sb_bottom_horiz_inner->Add( m_prov_advanced, 0, wxALL, FromDIP(5) );
	
	
	sb_bottom_horiz->Add( sb_bottom_horiz_inner, 1, wxEXPAND, FromDIP(5) );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_bottom_horiz->Add( m_buttons, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_content->Add( sb_bottom_horiz, 0, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPConfigDialogBase::OnUpdateUI ) );
	m_prov_add->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvAdd ), NULL, this );
	m_prov_remove->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvRemove ), NULL, this );
	m_prov_advanced->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvAdvanced ), NULL, this );
}

wxEAPConfigDialogBase::~wxEAPConfigDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPConfigDialogBase::OnUpdateUI ) );
	m_prov_add->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvAdd ), NULL, this );
	m_prov_remove->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvRemove ), NULL, this );
	m_prov_advanced->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnProvAdvanced ), NULL, this );
	
}

wxEAPGeneralDialogBase::wxEAPGeneralDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_panels = new wxBoxSizer( wxVERTICAL );
	
	
	sb_content->Add( m_panels, 1, wxEXPAND|wxALL, FromDIP(5) );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_content->Add( m_buttons, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPGeneralDialogBase::OnInitDialog ) );
}

wxEAPGeneralDialogBase::~wxEAPGeneralDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPGeneralDialogBase::OnInitDialog ) );
	
}

wxEAPCredentialsConnectionDialogBase::wxEAPCredentialsConnectionDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	m_providers->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	
	sb_content->Add( m_providers, 1, wxEXPAND | wxALL, FromDIP(5) );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_content->Add( m_buttons, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPCredentialsConnectionDialogBase::OnInitDialog ) );
}

wxEAPCredentialsConnectionDialogBase::~wxEAPCredentialsConnectionDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPCredentialsConnectionDialogBase::OnInitDialog ) );
	
}

wxEAPBannerPanelBase::wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : wxPanel( parent, id, pos, size, style, name )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHT ) );
	this->SetMinSize( FromDIP(wxSize( -1,48 )) );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_title = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_title->Wrap( -1 );
	m_title->SetFont( wxFont( 18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxEmptyString ) );
	m_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHTTEXT ) );
	
	sb_content->Add( m_title, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
}

wxEAPBannerPanelBase::~wxEAPBannerPanelBase()
{
}

wxEAPNotePanelBase::wxEAPNotePanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_INFOBK ) );
	
	wxBoxSizer* sb_note_horiz;
	sb_note_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_note_icon = new wxStaticBitmap( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_note_horiz->Add( m_note_icon, 0, wxALL, FromDIP(5) );
	
	m_note_vert = new wxBoxSizer( wxVERTICAL );
	
	m_note_label = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_note_label->Wrap( FromDIP(449) );
	m_note_vert->Add( m_note_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	
	sb_note_horiz->Add( m_note_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_note_horiz );
	this->Layout();
}

wxEAPNotePanelBase::~wxEAPNotePanelBase()
{
}

wxEAPCredentialsConfigPanelBase::wxEAPCredentialsConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	m_sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("%s User Credentials") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( m_sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Select the source where your credentials used to connect are stored."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( FromDIP(440) );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	m_storage = new wxRadioButton( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Use credentials from Credential &Manager"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP );
	m_storage->SetToolTip( _("Select this option if you would like to use credentials stored in Windows Credential Manager") );
	
	sb_credentials_vert->Add( m_storage, 0, wxEXPAND|wxTOP|wxRIGHT|wxLEFT, FromDIP(5) );
	
	wxBoxSizer* sb_storage;
	sb_storage = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* sb_storage_identity;
	sb_storage_identity = new wxBoxSizer( wxHORIZONTAL );
	
	m_storage_identity_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Identity:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_storage_identity_label->Wrap( -1 );
	sb_storage_identity->Add( m_storage_identity_label, 0, 0, FromDIP(5) );
	
	m_storage_identity = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_storage_identity->Wrap( -1 );
	m_storage_identity->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxEmptyString ) );
	m_storage_identity->SetToolTip( _("Your present credentials stored in Windows Credential Manager") );
	
	sb_storage_identity->Add( m_storage_identity, 1, wxEXPAND|wxLEFT, FromDIP(5) );
	
	
	sb_storage->Add( sb_storage_identity, 1, wxEXPAND, FromDIP(5) );
	
	wxBoxSizer* sb_buttons_storage;
	sb_buttons_storage = new wxBoxSizer( wxHORIZONTAL );
	
	m_storage_clear = new wxButton( m_sb_credentials->GetStaticBox(), wxID_ANY, _("&Clear Credentials"), wxDefaultPosition, wxDefaultSize, 0 );
	m_storage_clear->SetToolTip( _("Click to clear your credentials from Credential Manager.\nNote: You will be prompted to enter credentials when connecting.") );
	
	sb_buttons_storage->Add( m_storage_clear, 0, wxRIGHT, FromDIP(5) );
	
	m_storage_set = new wxButton( m_sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_storage_set->SetToolTip( _("Click here to set or modify your credentials") );
	
	sb_buttons_storage->Add( m_storage_set, 0, wxLEFT, FromDIP(5) );
	
	
	sb_storage->Add( sb_buttons_storage, 0, wxALIGN_RIGHT|wxTOP, FromDIP(5) );
	
	
	sb_credentials_vert->Add( sb_storage, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	m_config = new wxRadioButton( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Use credentials from &profile configuration"), wxDefaultPosition, wxDefaultSize, 0 );
	m_config->SetToolTip( _("Select this option if you would like to store credentials as a part of  profile configuration") );
	
	sb_credentials_vert->Add( m_config, 0, wxEXPAND|wxTOP|wxRIGHT|wxLEFT, FromDIP(5) );
	
	wxBoxSizer* sb_config;
	sb_config = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* sb_config_identity;
	sb_config_identity = new wxBoxSizer( wxHORIZONTAL );
	
	m_config_identity_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Identity:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_config_identity_label->Wrap( -1 );
	sb_config_identity->Add( m_config_identity_label, 0, 0, FromDIP(5) );
	
	m_config_identity = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_config_identity->Wrap( -1 );
	m_config_identity->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxEmptyString ) );
	m_config_identity->SetToolTip( _("Profile configuration credentials") );
	
	sb_config_identity->Add( m_config_identity, 1, wxEXPAND|wxLEFT, FromDIP(5) );
	
	
	sb_config->Add( sb_config_identity, 1, wxEXPAND, FromDIP(5) );
	
	wxBoxSizer* sb_buttons_config;
	sb_buttons_config = new wxBoxSizer( wxHORIZONTAL );
	
	m_config_set = new wxButton( m_sb_credentials->GetStaticBox(), wxID_ANY, _("&Set Credentials..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_config_set->SetToolTip( _("Click here to set or modify your credentials") );
	
	sb_buttons_config->Add( m_config_set, 0, 0, FromDIP(5) );
	
	
	sb_config->Add( sb_buttons_config, 0, wxALIGN_RIGHT|wxTOP, FromDIP(5) );
	
	
	sb_credentials_vert->Add( sb_config, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	m_sb_credentials->Add( sb_credentials_horiz, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( m_sb_credentials );
	this->Layout();
	m_timer_storage.SetOwner( this, wxID_ANY );
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_storage_clear->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClearStorage ), NULL, this );
	m_storage_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetStorage ), NULL, this );
	m_config_set->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetConfig ), NULL, this );
	this->Connect( wxID_ANY, wxEVT_TIMER, wxTimerEventHandler( wxEAPCredentialsConfigPanelBase::OnTimerStorage ) );
}

wxEAPCredentialsConfigPanelBase::~wxEAPCredentialsConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPCredentialsConfigPanelBase::OnUpdateUI ) );
	m_storage_clear->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnClearStorage ), NULL, this );
	m_storage_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetStorage ), NULL, this );
	m_config_set->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPCredentialsConfigPanelBase::OnSetConfig ), NULL, this );
	this->Disconnect( wxID_ANY, wxEVT_TIMER, wxTimerEventHandler( wxEAPCredentialsConfigPanelBase::OnTimerStorage ) );
	
}

wxPasswordCredentialsPanelBase::wxPasswordCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxEAPCredentialsPanelBase( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	m_sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("User ID and Password") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( m_sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, FromDIP(5) );
	
	m_sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Please provide your user ID and password."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( FromDIP(440) );
	m_sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxFlexGridSizer* sb_credentials_tbl;
	sb_credentials_tbl = new wxFlexGridSizer( 0, 2, FromDIP(5), FromDIP(5) );
	sb_credentials_tbl->AddGrowableCol( 1 );
	sb_credentials_tbl->SetFlexibleDirection( wxBOTH );
	sb_credentials_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_identity_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("User ID:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_identity_label, 0, wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	m_identity = new wxTextCtrl( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_identity->SetToolTip( _("Enter your user name here (user@domain.org, DOMAIN\\User, etc.)") );
	
	sb_credentials_tbl->Add( m_identity, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	m_password_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Password:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_password_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_password_label, 0, wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	m_password = new wxTextCtrl( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_password->SetToolTip( _("Enter your password here") );
	
	sb_credentials_tbl->Add( m_password, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	
	m_sb_credentials_vert->Add( sb_credentials_tbl, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_credentials_horiz->Add( m_sb_credentials_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	m_sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( m_sb_credentials );
	this->Layout();
	
	// Connect Events
	m_password->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( wxPasswordCredentialsPanelBase::OnPasswordText ), NULL, this );
}

wxPasswordCredentialsPanelBase::~wxPasswordCredentialsPanelBase()
{
	// Disconnect Events
	m_password->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( wxPasswordCredentialsPanelBase::OnPasswordText ), NULL, this );
	
}

wxIdentityCredentialsPanelBase::wxIdentityCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxEAPCredentialsPanelBase( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	m_sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("User ID") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( m_sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, FromDIP(5) );
	
	m_sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Please provide your user ID."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( FromDIP(440) );
	m_sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxFlexGridSizer* sb_credentials_tbl;
	sb_credentials_tbl = new wxFlexGridSizer( 0, 2, FromDIP(5), FromDIP(5) );
	sb_credentials_tbl->AddGrowableCol( 1 );
	sb_credentials_tbl->SetFlexibleDirection( wxBOTH );
	sb_credentials_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_identity_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("User ID:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_credentials_tbl->Add( m_identity_label, 0, wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	m_identity = new wxTextCtrl( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_identity->SetToolTip( _("Enter your user name here (user@domain.org, DOMAIN\\User, etc.)") );
	
	sb_credentials_tbl->Add( m_identity, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	
	m_sb_credentials_vert->Add( sb_credentials_tbl, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_credentials_horiz->Add( m_sb_credentials_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	m_sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( m_sb_credentials );
	this->Layout();
}

wxIdentityCredentialsPanelBase::~wxIdentityCredentialsPanelBase()
{
}

wxEAPProviderContactInfoPanelBase::wxEAPProviderContactInfoPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	wxStaticBoxSizer* sb_provider_contact;
	sb_provider_contact = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Your Organization") ), wxVERTICAL );
	
	wxBoxSizer* sb_provider_contact_horiz;
	sb_provider_contact_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_provider_contact_icon = new wxStaticBitmap( sb_provider_contact->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_contact_horiz->Add( m_provider_contact_icon, 0, wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_provider_contact_vert;
	sb_provider_contact_vert = new wxBoxSizer( wxVERTICAL );
	
	m_provider_contact_label = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("Describe your organization to customize user prompts.  When organization is introduced, end-users find program messages easier to understand and act."), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_contact_label->Wrap( FromDIP(440) );
	sb_provider_contact_vert->Add( m_provider_contact_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxBoxSizer* sb_provider_name;
	sb_provider_name = new wxBoxSizer( wxVERTICAL );
	
	m_provider_name_label = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("Your organization &name:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name_label->Wrap( -1 );
	sb_provider_name->Add( m_provider_name_label, 0, wxBOTTOM, FromDIP(5) );
	
	m_provider_name = new wxTextCtrl( sb_provider_contact->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name->SetToolTip( _("Your organization name as it will appear on helpdesk contact notifications") );
	
	sb_provider_name->Add( m_provider_name, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_provider_name_note = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("(Keep it short, please)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name_note->Wrap( -1 );
	sb_provider_name->Add( m_provider_name_note, 0, wxALIGN_RIGHT, FromDIP(5) );
	
	
	sb_provider_contact_vert->Add( sb_provider_name, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_provider_helpdesk;
	sb_provider_helpdesk = new wxBoxSizer( wxVERTICAL );
	
	m_provider_helpdesk_label = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("Helpdesk contact &information:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_helpdesk_label->Wrap( -1 );
	sb_provider_helpdesk->Add( m_provider_helpdesk_label, 0, wxBOTTOM, FromDIP(5) );
	
	wxFlexGridSizer* sb_provider_helpdesk_inner;
	sb_provider_helpdesk_inner = new wxFlexGridSizer( 0, 2, 0, 0 );
	sb_provider_helpdesk_inner->AddGrowableCol( 1 );
	sb_provider_helpdesk_inner->SetFlexibleDirection( wxBOTH );
	sb_provider_helpdesk_inner->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_provider_web_icon = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("¶"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_web_icon->Wrap( -1 );
	m_provider_web_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_web_icon, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT, FromDIP(5) );
	
	m_provider_web = new wxTextCtrl( sb_provider_contact->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_web->SetToolTip( _("Your helpdesk website address") );
	
	sb_provider_helpdesk_inner->Add( m_provider_web, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL|wxBOTTOM, FromDIP(5) );
	
	m_provider_email_icon = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _("*"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_email_icon->Wrap( -1 );
	m_provider_email_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_email_icon, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT, FromDIP(5) );
	
	m_provider_email = new wxTextCtrl( sb_provider_contact->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_email->SetToolTip( _("Your helpdesk e-mail address") );
	
	sb_provider_helpdesk_inner->Add( m_provider_email, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL|wxBOTTOM, FromDIP(5) );
	
	m_provider_phone_icon = new wxStaticText( sb_provider_contact->GetStaticBox(), wxID_ANY, _(")"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_phone_icon->Wrap( -1 );
	m_provider_phone_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_phone_icon, 0, wxALIGN_CENTER_VERTICAL|wxRIGHT, FromDIP(5) );
	
	m_provider_phone = new wxTextCtrl( sb_provider_contact->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_phone->SetToolTip( _("Your helpdesk phone number") );
	
	sb_provider_helpdesk_inner->Add( m_provider_phone, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	
	sb_provider_helpdesk->Add( sb_provider_helpdesk_inner, 0, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_contact_vert->Add( sb_provider_helpdesk, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_provider_contact_horiz->Add( sb_provider_contact_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_contact->Add( sb_provider_contact_horiz, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_provider_contact );
	this->Layout();
}

wxEAPProviderContactInfoPanelBase::~wxEAPProviderContactInfoPanelBase()
{
}

wxEAPProviderIDPanelBase::wxEAPProviderIDPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	wxStaticBoxSizer* sb_provider_id;
	sb_provider_id = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Provider Unique Identifier") ), wxVERTICAL );
	
	wxBoxSizer* sb_provider_id_horiz;
	sb_provider_id_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_provider_id_icon = new wxStaticBitmap( sb_provider_id->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_id_horiz->Add( m_provider_id_icon, 0, wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_provider_id_vert;
	sb_provider_id_vert = new wxBoxSizer( wxVERTICAL );
	
	m_provider_id_label_outer = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("Assign your organization a unique ID to allow sharing the same credential set across different network profiles."), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_id_label_outer->Wrap( FromDIP(440) );
	sb_provider_id_vert->Add( m_provider_id_label_outer, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxBoxSizer* sb_provider_namespace;
	sb_provider_namespace = new wxBoxSizer( wxVERTICAL );
	
	m_provider_namespace_label = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("&Namespace:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_namespace_label->Wrap( -1 );
	sb_provider_namespace->Add( m_provider_namespace_label, 0, wxBOTTOM, FromDIP(5) );
	
	wxString m_provider_namespaceChoices[] = { _("urn:RFC4282:realm"), _("urn:uuid") };
	int m_provider_namespaceNChoices = sizeof( m_provider_namespaceChoices ) / sizeof( wxString );
	m_provider_namespace = new wxChoice( sb_provider_id->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, m_provider_namespaceNChoices, m_provider_namespaceChoices, 0 );
	m_provider_namespace->SetSelection( 0 );
	sb_provider_namespace->Add( m_provider_namespace, 0, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_id_vert->Add( sb_provider_namespace, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_provider_id_inner;
	sb_provider_id_inner = new wxBoxSizer( wxVERTICAL );
	
	m_provider_id_label = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("Provider unique &identifier:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_id_label->Wrap( -1 );
	sb_provider_id_inner->Add( m_provider_id_label, 0, wxBOTTOM, FromDIP(5) );
	
	m_provider_id = new wxTextCtrl( sb_provider_id->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_id->SetToolTip( _("Your organization ID to assign same credentials from other profiles") );
	
	sb_provider_id_inner->Add( m_provider_id, 0, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_id_vert->Add( sb_provider_id_inner, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_provider_id_horiz->Add( sb_provider_id_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_id->Add( sb_provider_id_horiz, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_provider_id );
	this->Layout();
}

wxEAPProviderIDPanelBase::~wxEAPProviderIDPanelBase()
{
}

wxEAPProviderLockPanelBase::wxEAPProviderLockPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style, const wxString& name ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style, name )
{
	wxStaticBoxSizer* sb_provider_lock;
	sb_provider_lock = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Configuration Lock") ), wxVERTICAL );
	
	wxBoxSizer* sb_provider_lock_horiz;
	sb_provider_lock_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_provider_lock_icon = new wxStaticBitmap( sb_provider_lock->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_lock_horiz->Add( m_provider_lock_icon, 0, wxALL, FromDIP(5) );
	
	wxBoxSizer* sb_provider_lock_vert;
	sb_provider_lock_vert = new wxBoxSizer( wxVERTICAL );
	
	m_provider_lock_label = new wxStaticText( sb_provider_lock->GetStaticBox(), wxID_ANY, _("Your configuration can be locked to prevent accidental modification by end-users. Users will only be allowed to enter credentials."), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_lock_label->Wrap( FromDIP(440) );
	sb_provider_lock_vert->Add( m_provider_lock_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxBoxSizer* sb_provider_lock_inner;
	sb_provider_lock_inner = new wxBoxSizer( wxVERTICAL );
	
	m_provider_lock = new wxCheckBox( sb_provider_lock->GetStaticBox(), wxID_ANY, _("&Lock this configuration and prevent any further modification via user interface."), wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_lock_inner->Add( m_provider_lock, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_provider_lock_note = new wxStaticText( sb_provider_lock->GetStaticBox(), wxID_ANY, _("(Warning: Once locked, you can not revert using this dialog!)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_lock_note->Wrap( -1 );
	sb_provider_lock_inner->Add( m_provider_lock_note, 0, wxALIGN_RIGHT, FromDIP(5) );
	
	
	sb_provider_lock_vert->Add( sb_provider_lock_inner, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_provider_lock_horiz->Add( sb_provider_lock_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	sb_provider_lock->Add( sb_provider_lock_horiz, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_provider_lock );
	this->Layout();
}

wxEAPProviderLockPanelBase::~wxEAPProviderLockPanelBase()
{
}

wxEAPProviderSelectDialogBase::wxEAPProviderSelectDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxEAPBannerPanel( this );
	
	sb_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, FromDIP(5) );
	
	m_providers = new wxBoxSizer( wxVERTICAL );
	
	m_providers->SetMinSize( FromDIP(wxSize( 350,-1 )) ); 
	
	sb_content->Add( m_providers, 1, wxEXPAND|wxALL, FromDIP(5) );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_content->Add( m_buttons, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPProviderSelectDialogBase::OnInitDialog ) );
}

wxEAPProviderSelectDialogBase::~wxEAPProviderSelectDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPProviderSelectDialogBase::OnInitDialog ) );
	
}
