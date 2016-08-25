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
	
	wxBoxSizer* sb_bottom_horiz;
	sb_bottom_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	wxBoxSizer* sb_bottom_horiz_inner;
	sb_bottom_horiz_inner = new wxBoxSizer( wxHORIZONTAL );
	
	m_advanced = new wxButton( this, wxID_ANY, _("Advanced..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_advanced->SetToolTip( _("Opens dialog with provider settings") );
	
	sb_bottom_horiz_inner->Add( m_advanced, 0, wxALL, 5 );
	
	
	sb_bottom_horiz->Add( sb_bottom_horiz_inner, 1, wxEXPAND, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sb_bottom_horiz->Add( m_buttons, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_content->Add( sb_bottom_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
	
	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPConfigDialogBase::OnUpdateUI ) );
	m_advanced->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnAdvanced ), NULL, this );
}

wxEAPConfigDialogBase::~wxEAPConfigDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPConfigDialogBase::OnInitDialog ) );
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPConfigDialogBase::OnUpdateUI ) );
	m_advanced->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPConfigDialogBase::OnAdvanced ), NULL, this );
	
}

wxEAPGeneralDialogBase::wxEAPGeneralDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
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
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPGeneralDialogBase::OnInitDialog ) );
}

wxEAPGeneralDialogBase::~wxEAPGeneralDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( wxEAPGeneralDialogBase::OnInitDialog ) );
	
}

wxEAPBannerPanelBase::wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHT ) );
	this->SetMinSize( wxSize( -1,48 ) );
	
	wxBoxSizer* sb_content;
	sb_content = new wxBoxSizer( wxVERTICAL );
	
	m_title = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_title->Wrap( -1 );
	m_title->SetFont( wxFont( 18, 70, 90, 90, false, wxEmptyString ) );
	m_title->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_HIGHLIGHTTEXT ) );
	
	sb_content->Add( m_title, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( sb_content );
	this->Layout();
	sb_content->Fit( this );
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

wxEAPCredentialsPassPanelBase::wxEAPCredentialsPassPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
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

wxEAPCredentialsPassPanelBase::~wxEAPCredentialsPassPanelBase()
{
}

wxEAPProviderIdentityPanelBase::wxEAPProviderIdentityPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_provider_id;
	sb_provider_id = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Your Organization") ), wxVERTICAL );
	
	wxBoxSizer* sb_provider_id_horiz;
	sb_provider_id_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_provider_id_icon = new wxStaticBitmap( sb_provider_id->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_id_horiz->Add( m_provider_id_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_provider_id_vert;
	sb_provider_id_vert = new wxBoxSizer( wxVERTICAL );
	
	m_provider_id_label = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("Describe your organization to customize user prompts.  When organization is introduced, end-users find program messages easier to understand and act."), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_id_label->Wrap( 446 );
	sb_provider_id_vert->Add( m_provider_id_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_provider_name;
	sb_provider_name = new wxBoxSizer( wxVERTICAL );
	
	m_provider_name_label = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("Your organization &name:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name_label->Wrap( -1 );
	sb_provider_name->Add( m_provider_name_label, 0, wxBOTTOM, 5 );
	
	m_provider_name = new wxTextCtrl( sb_provider_id->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name->SetToolTip( _("Your organization name as it will appear on helpdesk contact notifications") );
	
	sb_provider_name->Add( m_provider_name, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_provider_name_note = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("(Keep it short, please)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_name_note->Wrap( -1 );
	sb_provider_name->Add( m_provider_name_note, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_provider_id_vert->Add( sb_provider_name, 0, wxEXPAND|wxALL, 5 );
	
	wxBoxSizer* sb_provider_helpdesk;
	sb_provider_helpdesk = new wxBoxSizer( wxVERTICAL );
	
	m_provider_helpdesk_label = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("Helpdesk contact &information:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_helpdesk_label->Wrap( -1 );
	sb_provider_helpdesk->Add( m_provider_helpdesk_label, 0, wxBOTTOM, 5 );
	
	wxFlexGridSizer* sb_provider_helpdesk_inner;
	sb_provider_helpdesk_inner = new wxFlexGridSizer( 0, 2, 0, 0 );
	sb_provider_helpdesk_inner->AddGrowableCol( 1 );
	sb_provider_helpdesk_inner->SetFlexibleDirection( wxBOTH );
	sb_provider_helpdesk_inner->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_provider_web_icon = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("¶"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_web_icon->Wrap( -1 );
	m_provider_web_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), 70, 90, 90, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_web_icon, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT, 5 );
	
	m_provider_web = new wxTextCtrl( sb_provider_id->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_web->SetToolTip( _("Your helpdesk website address") );
	
	sb_provider_helpdesk_inner->Add( m_provider_web, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL|wxBOTTOM, 5 );
	
	m_provider_email_icon = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _("*"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_email_icon->Wrap( -1 );
	m_provider_email_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), 70, 90, 90, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_email_icon, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT, 5 );
	
	m_provider_email = new wxTextCtrl( sb_provider_id->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_email->SetToolTip( _("Your helpdesk e-mail address") );
	
	sb_provider_helpdesk_inner->Add( m_provider_email, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL|wxBOTTOM, 5 );
	
	m_provider_phone_icon = new wxStaticText( sb_provider_id->GetStaticBox(), wxID_ANY, _(")"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_phone_icon->Wrap( -1 );
	m_provider_phone_icon->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), 70, 90, 90, false, wxT("Wingdings") ) );
	
	sb_provider_helpdesk_inner->Add( m_provider_phone_icon, 0, wxALIGN_CENTER_VERTICAL|wxRIGHT, 5 );
	
	m_provider_phone = new wxTextCtrl( sb_provider_id->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_phone->SetToolTip( _("Your helpdesk phone number") );
	
	sb_provider_helpdesk_inner->Add( m_provider_phone, 1, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	sb_provider_helpdesk->Add( sb_provider_helpdesk_inner, 1, wxEXPAND, 5 );
	
	
	sb_provider_id_vert->Add( sb_provider_helpdesk, 1, wxEXPAND, 5 );
	
	
	sb_provider_id_horiz->Add( sb_provider_id_vert, 1, wxEXPAND, 5 );
	
	
	sb_provider_id->Add( sb_provider_id_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_provider_id );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPProviderIdentityPanelBase::OnUpdateUI ) );
}

wxEAPProviderIdentityPanelBase::~wxEAPProviderIdentityPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPProviderIdentityPanelBase::OnUpdateUI ) );
	
}

wxEAPProviderLockPanelBase::wxEAPProviderLockPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_provider_lock;
	sb_provider_lock = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Configuration Lock") ), wxVERTICAL );
	
	wxBoxSizer* sb_provider_lock_horiz;
	sb_provider_lock_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_provider_lock_icon = new wxStaticBitmap( sb_provider_lock->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_lock_horiz->Add( m_provider_lock_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_provider_lock_vert;
	sb_provider_lock_vert = new wxBoxSizer( wxVERTICAL );
	
	m_provider_lock_label = new wxStaticText( sb_provider_lock->GetStaticBox(), wxID_ANY, _("Your configuration can be locked to prevent accidental modification by end-users. Users will only be allowed to enter credentials."), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_lock_label->Wrap( 446 );
	sb_provider_lock_vert->Add( m_provider_lock_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_provider_name;
	sb_provider_name = new wxBoxSizer( wxVERTICAL );
	
	m_provider_lock = new wxCheckBox( sb_provider_lock->GetStaticBox(), wxID_ANY, _("&Lock this configuration and prevent any further modification via user interface."), wxDefaultPosition, wxDefaultSize, 0 );
	sb_provider_name->Add( m_provider_lock, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_provider_lock_note = new wxStaticText( sb_provider_lock->GetStaticBox(), wxID_ANY, _("(Warning: Once locked, you can not revert using this dialog!)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_provider_lock_note->Wrap( -1 );
	sb_provider_name->Add( m_provider_lock_note, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_provider_lock_vert->Add( sb_provider_name, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_provider_lock_horiz->Add( sb_provider_lock_vert, 1, wxEXPAND, 5 );
	
	
	sb_provider_lock->Add( sb_provider_lock_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_provider_lock );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPProviderLockPanelBase::OnUpdateUI ) );
}

wxEAPProviderLockPanelBase::~wxEAPProviderLockPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPProviderLockPanelBase::OnUpdateUI ) );
	
}
