///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxpass.h"

///////////////////////////////////////////////////////////////////////////

wxPasswordCredentialsBase::wxPasswordCredentialsBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
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

wxPasswordCredentialsBase::~wxPasswordCredentialsBase()
{
}
