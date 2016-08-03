///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxTLS_UI.h"

///////////////////////////////////////////////////////////////////////////

wxEAPTLSServerTrustConfigPanelBase::wxEAPTLSServerTrustConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_server_trust;
	sb_server_trust = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Server Trust") ), wxVERTICAL );
	
	wxBoxSizer* sb_server_trust_horiz;
	sb_server_trust_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_server_trust_icon = new wxStaticBitmap( sb_server_trust->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_server_trust_horiz->Add( m_server_trust_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_server_trust_vert;
	sb_server_trust_vert = new wxBoxSizer( wxVERTICAL );
	
	m_server_trust_label = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("Describe the servers you trust to prevent credential interception in case of man-in-the-middle attacks."), wxDefaultPosition, wxDefaultSize, 0 );
	m_server_trust_label->Wrap( 446 );
	sb_server_trust_vert->Add( m_server_trust_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_root_ca;
	sb_root_ca = new wxBoxSizer( wxVERTICAL );
	
	m_root_ca_lbl = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("Acceptable Certificate Authorities:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_lbl->Wrap( -1 );
	sb_root_ca->Add( m_root_ca_lbl, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_root_ca = new wxListBox( sb_server_trust->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_SORT ); 
	m_root_ca->SetToolTip( _("List of certificate authorities server's certificate must be issued by") );
	
	sb_root_ca->Add( m_root_ca, 1, wxEXPAND|wxBOTTOM, 5 );
	
	wxBoxSizer* sb_root_ca_btn;
	sb_root_ca_btn = new wxBoxSizer( wxHORIZONTAL );
	
	m_root_ca_add_store = new wxButton( sb_server_trust->GetStaticBox(), wxID_ANY, _("Add CA from Store..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_add_store->SetToolTip( _("Adds a new certificate authority from the certificate store to the list") );
	
	sb_root_ca_btn->Add( m_root_ca_add_store, 0, wxRIGHT, 5 );
	
	m_root_ca_add_file = new wxButton( sb_server_trust->GetStaticBox(), wxID_ANY, _("Add CA from File..."), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_add_file->SetToolTip( _("Adds a new certificate authority from the file to the list") );
	
	sb_root_ca_btn->Add( m_root_ca_add_file, 0, wxRIGHT|wxLEFT, 5 );
	
	m_root_ca_remove = new wxButton( sb_server_trust->GetStaticBox(), wxID_ANY, _("&Remove CA"), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_remove->Enable( false );
	m_root_ca_remove->SetToolTip( _("Removes selected certificate authorities from the list") );
	
	sb_root_ca_btn->Add( m_root_ca_remove, 0, wxLEFT, 5 );
	
	
	sb_root_ca->Add( sb_root_ca_btn, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_server_trust_vert->Add( sb_root_ca, 1, wxEXPAND|wxALL, 5 );
	
	wxBoxSizer* sb_server_names;
	sb_server_names = new wxBoxSizer( wxVERTICAL );
	
	m_server_names_label = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("Acceptable server &names:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_server_names_label->Wrap( -1 );
	sb_server_names->Add( m_server_names_label, 0, wxBOTTOM, 5 );
	
	m_server_names = new wxTextCtrl( sb_server_trust->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_server_names->SetToolTip( _("A semicolon delimited list of acceptable server FQDN names; blank to skip name check; \"*\" wildchar allowed") );
	
	sb_server_names->Add( m_server_names, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_server_names_note = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("(Example: foo.bar.com;*.domain.org)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_server_names_note->Wrap( -1 );
	sb_server_names->Add( m_server_names_note, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_server_trust_vert->Add( sb_server_names, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_server_trust_horiz->Add( sb_server_trust_vert, 1, wxEXPAND, 5 );
	
	
	sb_server_trust->Add( sb_server_trust_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_server_trust );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnUpdateUI ) );
	m_root_ca->Connect( wxEVT_COMMAND_LISTBOX_DOUBLECLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCADClick ), NULL, this );
	m_root_ca_add_store->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCAAddStore ), NULL, this );
	m_root_ca_add_file->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCAAddFile ), NULL, this );
	m_root_ca_remove->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCARemove ), NULL, this );
}

wxEAPTLSServerTrustConfigPanelBase::~wxEAPTLSServerTrustConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnUpdateUI ) );
	m_root_ca->Disconnect( wxEVT_COMMAND_LISTBOX_DOUBLECLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCADClick ), NULL, this );
	m_root_ca_add_store->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCAAddStore ), NULL, this );
	m_root_ca_add_file->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCAAddFile ), NULL, this );
	m_root_ca_remove->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPTLSServerTrustConfigPanelBase::OnRootCARemove ), NULL, this );
	
}

wxTLSCredentialsPanelBase::wxTLSCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_credentials;
	sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("TLS Client Certificate") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_credentials_vert;
	sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_credentials_label = new wxStaticText( sb_credentials->GetStaticBox(), wxID_ANY, _("Please select your client certificate to use for authentication."), wxDefaultPosition, wxDefaultSize, 0 );
	m_credentials_label->Wrap( 446 );
	sb_credentials_vert->Add( m_credentials_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_cert_radio;
	sb_cert_radio = new wxBoxSizer( wxVERTICAL );
	
	m_cert_none = new wxRadioButton( sb_credentials->GetStaticBox(), wxID_ANY, _("Co&nnect without providing a client certificate"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP );
	m_cert_none->SetToolTip( _("Select if your server does not require you to provide a client certificate") );
	
	sb_cert_radio->Add( m_cert_none, 1, wxEXPAND, 5 );
	
	wxBoxSizer* sb_cert_select;
	sb_cert_select = new wxBoxSizer( wxHORIZONTAL );
	
	m_cert_select = new wxRadioButton( sb_credentials->GetStaticBox(), wxID_ANY, _("Use the following &certificate:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_cert_select->SetToolTip( _("Select if you need to provide a client certificate when connecting") );
	
	sb_cert_select->Add( m_cert_select, 0, wxEXPAND, 5 );
	
	wxArrayString m_cert_select_valChoices;
	m_cert_select_val = new wxChoice( sb_credentials->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, m_cert_select_valChoices, wxCB_SORT );
	m_cert_select_val->SetSelection( 0 );
	m_cert_select_val->SetToolTip( _("Client certificate to use for authentication") );
	
	sb_cert_select->Add( m_cert_select_val, 1, wxEXPAND, 5 );
	
	
	sb_cert_radio->Add( sb_cert_select, 1, wxEXPAND, 5 );
	
	
	sb_credentials_vert->Add( sb_cert_radio, 0, wxEXPAND|wxALL, 5 );
	
	m_remember = new wxCheckBox( sb_credentials->GetStaticBox(), wxID_ANY, _("&Remember"), wxDefaultPosition, wxDefaultSize, 0 );
	m_remember->SetHelpText( _("Check if you would like to save certificate selection") );
	
	sb_credentials_vert->Add( m_remember, 0, wxALL|wxEXPAND, 5 );
	
	
	sb_credentials_horiz->Add( sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_credentials );
	this->Layout();
}

wxTLSCredentialsPanelBase::~wxTLSCredentialsPanelBase()
{
}
