///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxEAPTLS.h"

///////////////////////////////////////////////////////////////////////////

BEGIN_EVENT_TABLE( wxEAPTLSConfigPanelBase, wxPanel )
	EVT_LISTBOX_DCLICK( wxID_ANY, wxEAPTLSConfigPanelBase::_wxFB_OnRootCADClick )
	EVT_BUTTON( wxID_ANY, wxEAPTLSConfigPanelBase::_wxFB_OnRootCAAdd )
	EVT_BUTTON( wxID_ANY, wxEAPTLSConfigPanelBase::_wxFB_OnRootCARemove )
END_EVENT_TABLE()

wxEAPTLSConfigPanelBase::wxEAPTLSConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
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
	
	m_root_ca = new wxListBox( sb_server_trust->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_MULTIPLE|wxLB_SORT ); 
	m_root_ca->SetToolTip( _("List of certificate authorities server's certificate must be issued by") );
	
	sb_root_ca->Add( m_root_ca, 1, wxEXPAND|wxBOTTOM, 5 );
	
	wxBoxSizer* sb_root_ca_btn;
	sb_root_ca_btn = new wxBoxSizer( wxHORIZONTAL );
	
	m_root_ca_add = new wxButton( sb_server_trust->GetStaticBox(), wxID_ANY, _("Add CA"), wxDefaultPosition, wxDefaultSize, 0 );
	m_root_ca_add->SetToolTip( _("Adds a new certificate authority to the list") );
	
	sb_root_ca_btn->Add( m_root_ca_add, 0, wxRIGHT, 5 );
	
	m_root_ca_remove = new wxButton( sb_server_trust->GetStaticBox(), wxID_ANY, _("&Remove CA"), wxDefaultPosition, wxDefaultSize, 0 );
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
}

wxEAPTLSConfigPanelBase::~wxEAPTLSConfigPanelBase()
{
}
