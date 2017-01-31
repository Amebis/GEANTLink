///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxTTLS_UI.h"

///////////////////////////////////////////////////////////////////////////

wxTTLSConfigPanelBase::wxTTLSConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_outer_identity;
	sb_outer_identity = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Outer Identity") ), wxVERTICAL );
	
	wxBoxSizer* sb_outer_identity_horiz;
	sb_outer_identity_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_outer_identity_icon = new wxStaticBitmap( sb_outer_identity->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_outer_identity_horiz->Add( m_outer_identity_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_outer_identity_vert;
	sb_outer_identity_vert = new wxBoxSizer( wxVERTICAL );
	
	m_outer_identity_label = new wxStaticText( sb_outer_identity->GetStaticBox(), wxID_ANY, _("Select the user ID supplicant introduces itself as to authenticator:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_outer_identity_label->Wrap( 440 );
	sb_outer_identity_vert->Add( m_outer_identity_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_outer_identity_radio;
	sb_outer_identity_radio = new wxBoxSizer( wxVERTICAL );
	
	m_outer_identity_same = new wxRadioButton( sb_outer_identity->GetStaticBox(), wxID_ANY, _("&True identity"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP );
	m_outer_identity_same->SetToolTip( _("Use my true user name") );
	
	sb_outer_identity_radio->Add( m_outer_identity_same, 1, wxEXPAND, 5 );
	
	m_outer_identity_empty = new wxRadioButton( sb_outer_identity->GetStaticBox(), wxID_ANY, _("Use &empty outer identity"), wxDefaultPosition, wxDefaultSize, 0 );
	m_outer_identity_empty->SetToolTip( _("Ommit my user name and use @mydomain.org only") );
	
	sb_outer_identity_radio->Add( m_outer_identity_empty, 1, wxEXPAND, 5 );
	
	wxBoxSizer* sb_outer_identity_custom;
	sb_outer_identity_custom = new wxBoxSizer( wxHORIZONTAL );
	
	m_outer_identity_custom = new wxRadioButton( sb_outer_identity->GetStaticBox(), wxID_ANY, _("&Custom outer identity:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_outer_identity_custom->SetToolTip( _("Specify custom outer identity") );
	
	sb_outer_identity_custom->Add( m_outer_identity_custom, 0, wxEXPAND, 5 );
	
	m_outer_identity_custom_val = new wxTextCtrl( sb_outer_identity->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_outer_identity_custom_val->SetToolTip( _("Custom outer identity to use") );
	
	sb_outer_identity_custom->Add( m_outer_identity_custom_val, 1, wxEXPAND, 5 );
	
	
	sb_outer_identity_radio->Add( sb_outer_identity_custom, 1, wxEXPAND, 5 );
	
	
	sb_outer_identity_vert->Add( sb_outer_identity_radio, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_outer_identity_horiz->Add( sb_outer_identity_vert, 1, wxEXPAND, 5 );
	
	
	sb_outer_identity->Add( sb_outer_identity_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_outer_identity );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTTLSConfigPanelBase::OnUpdateUI ) );
}

wxTTLSConfigPanelBase::~wxTTLSConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxTTLSConfigPanelBase::OnUpdateUI ) );
	
}
