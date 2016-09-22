///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxTLS_UI.h"

///////////////////////////////////////////////////////////////////////////

wxTLSServerTrustPanelBase::wxTLSServerTrustPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
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
	m_server_trust_label->Wrap( 440 );
	sb_server_trust_vert->Add( m_server_trust_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_root_ca;
	sb_root_ca = new wxBoxSizer( wxVERTICAL );
	
	m_root_ca_lbl = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("Acceptable Certificate Authorities:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_lbl->Wrap( -1 );
	sb_root_ca->Add( m_root_ca_lbl, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_root_ca = new wxListBox( sb_server_trust->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_SORT ); 
	m_root_ca->SetToolTip( _("Server's certificate must be issued by one of certificate authorities listed here") );
	
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
	m_server_names->SetToolTip( _("A semicolon delimited list of acceptable server FQDN names; blank to skip name check; Unicode characters allowed") );
	
	sb_server_names->Add( m_server_names, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_server_names_note = new wxStaticText( sb_server_trust->GetStaticBox(), wxID_ANY, _("(Example: foo.bar.com;server2.bar.com)"), wxDefaultPosition, wxDefaultSize, 0 );
	m_server_names_note->Wrap( -1 );
	sb_server_names->Add( m_server_names_note, 0, wxALIGN_RIGHT, 5 );
	
	
	sb_server_trust_vert->Add( sb_server_names, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_server_trust_horiz->Add( sb_server_trust_vert, 1, wxEXPAND, 5 );
	
	
	sb_server_trust->Add( sb_server_trust_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_server_trust );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTLSServerTrustPanelBase::OnUpdateUI ) );
	m_root_ca->Connect( wxEVT_COMMAND_LISTBOX_DOUBLECLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCADClick ), NULL, this );
	m_root_ca_add_store->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCAAddStore ), NULL, this );
	m_root_ca_add_file->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCAAddFile ), NULL, this );
	m_root_ca_remove->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCARemove ), NULL, this );
}

wxTLSServerTrustPanelBase::~wxTLSServerTrustPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTLSServerTrustPanelBase::OnUpdateUI ) );
	m_root_ca->Disconnect( wxEVT_COMMAND_LISTBOX_DOUBLECLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCADClick ), NULL, this );
	m_root_ca_add_store->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCAAddStore ), NULL, this );
	m_root_ca_add_file->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCAAddFile ), NULL, this );
	m_root_ca_remove->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxTLSServerTrustPanelBase::OnRootCARemove ), NULL, this );
	
}

wxTLSCredentialsPanelBase::wxTLSCredentialsPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxEAPCredentialsPanelBase( parent, id, pos, size, style )
{
	m_sb_credentials = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("TLS Client Certificate") ), wxVERTICAL );
	
	wxBoxSizer* sb_credentials_horiz;
	sb_credentials_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_credentials_icon = new wxStaticBitmap( m_sb_credentials->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_credentials_horiz->Add( m_credentials_icon, 0, wxALL, 5 );
	
	m_sb_credentials_vert = new wxBoxSizer( wxVERTICAL );
	
	m_certificate_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Please select your client &certificate to use for authentication."), wxDefaultPosition, wxDefaultSize, 0 );
	m_certificate_label->Wrap( 440 );
	m_sb_credentials_vert->Add( m_certificate_label, 0, wxEXPAND|wxTOP|wxRIGHT|wxLEFT, 5 );
	
	wxArrayString m_certificateChoices;
	m_certificate = new wxChoice( m_sb_credentials->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, m_certificateChoices, wxCB_SORT );
	m_certificate->SetSelection( 0 );
	m_certificate->SetToolTip( _("Client certificate to use for authentication") );
	
	m_sb_credentials_vert->Add( m_certificate, 0, wxEXPAND|wxALL, 5 );
	
	wxBoxSizer* sb_identity;
	sb_identity = new wxBoxSizer( wxVERTICAL );
	
	m_identity_label = new wxStaticText( m_sb_credentials->GetStaticBox(), wxID_ANY, _("Custom &identity:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_identity_label->Wrap( -1 );
	sb_identity->Add( m_identity_label, 0, wxBOTTOM, 5 );
	
	m_identity = new wxTextCtrl( m_sb_credentials->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_identity->SetToolTip( _("Your identity (username@domain) to override one from certificate; or blank to use one provided in certificate") );
	
	sb_identity->Add( m_identity, 0, wxEXPAND, 5 );
	
	
	m_sb_credentials_vert->Add( sb_identity, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_credentials_horiz->Add( m_sb_credentials_vert, 1, wxEXPAND, 5 );
	
	
	m_sb_credentials->Add( sb_credentials_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( m_sb_credentials );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTLSCredentialsPanelBase::OnUpdateUI ) );
}

wxTLSCredentialsPanelBase::~wxTLSCredentialsPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTLSCredentialsPanelBase::OnUpdateUI ) );
	
}
