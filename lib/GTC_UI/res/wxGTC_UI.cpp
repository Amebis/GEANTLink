///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxGTC_UI.h"

///////////////////////////////////////////////////////////////////////////

wxGTCResponsePanelBase::wxGTCResponsePanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style )
{
	m_sb_response = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("GTC Challenge") ), wxVERTICAL );
	
	wxBoxSizer* sb_response_horiz;
	sb_response_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_response_icon = new wxStaticBitmap( m_sb_response->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_response_horiz->Add( m_response_icon, 0, wxALL, FromDIP(5) );
	
	m_sb_response_vert = new wxBoxSizer( wxVERTICAL );
	
	m_response_label = new wxStaticText( m_sb_response->GetStaticBox(), wxID_ANY, _("Please provide your response."), wxDefaultPosition, wxDefaultSize, 0 );
	m_response_label->Wrap( FromDIP(440) );
	m_sb_response_vert->Add( m_response_label, 0, wxALL|wxEXPAND, FromDIP(5) );
	
	wxFlexGridSizer* sb_response_tbl;
	sb_response_tbl = new wxFlexGridSizer( 0, 2, FromDIP(5), FromDIP(5) );
	sb_response_tbl->AddGrowableCol( 1 );
	sb_response_tbl->SetFlexibleDirection( wxBOTH );
	sb_response_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_challenge = new wxStaticText( m_sb_response->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, FromDIP(0) );
	m_challenge->Wrap( -1 );
	m_challenge->SetToolTip( _("Server challenge") );
	
	sb_response_tbl->Add( m_challenge, 0, wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	m_response = new wxTextCtrl( m_sb_response->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_response->SetToolTip( _("Enter your response here") );
	
	sb_response_tbl->Add( m_response, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, FromDIP(5) );
	
	
	m_sb_response_vert->Add( sb_response_tbl, 0, wxEXPAND|wxALL, FromDIP(5) );
	
	
	sb_response_horiz->Add( m_sb_response_vert, 1, wxEXPAND, FromDIP(5) );
	
	
	m_sb_response->Add( sb_response_horiz, 0, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( m_sb_response );
	this->Layout();
}

wxGTCResponsePanelBase::~wxGTCResponsePanelBase()
{
}

wxGTCConfigPanelBase::wxGTCConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, long style ) : wxPanel( parent, id, pos, parent->FromDIP(wxSize( 500,-1 )), style )
{
	wxBoxSizer* sb_vertical;
	sb_vertical = new wxBoxSizer( wxVERTICAL );
	
	m_auth_mode_label = new wxStaticText( this, wxID_ANY, _("EAP-GTC authentication &mode:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_auth_mode_label->Wrap( -1 );
	sb_vertical->Add( m_auth_mode_label, 0, wxBOTTOM, FromDIP(5) );
	
	m_auth_mode = new wxChoicebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxCHB_DEFAULT );
	m_auth_mode->SetToolTip( _("Select EAP-GTC authentication mode from the list") );
	
	sb_vertical->Add( m_auth_mode, 1, wxEXPAND, FromDIP(5) );
	
	
	this->SetSizer( sb_vertical );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxGTCConfigPanelBase::OnUpdateUI ) );
}

wxGTCConfigPanelBase::~wxGTCConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxGTCConfigPanelBase::OnUpdateUI ) );
	
}
