///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxGTC_UI.h"

///////////////////////////////////////////////////////////////////////////

wxGTCResponsePanelBase::wxGTCResponsePanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	m_sb_response = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("GTC Challenge") ), wxVERTICAL );
	
	wxBoxSizer* sb_response_horiz;
	sb_response_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_response_icon = new wxStaticBitmap( m_sb_response->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_response_horiz->Add( m_response_icon, 0, wxALL, 5 );
	
	m_sb_response_vert = new wxBoxSizer( wxVERTICAL );
	
	m_response_label = new wxStaticText( m_sb_response->GetStaticBox(), wxID_ANY, _("Please provide your response."), wxDefaultPosition, wxDefaultSize, 0 );
	m_response_label->Wrap( 440 );
	m_sb_response_vert->Add( m_response_label, 0, wxALL|wxEXPAND, 5 );
	
	wxFlexGridSizer* sb_response_tbl;
	sb_response_tbl = new wxFlexGridSizer( 0, 2, 5, 5 );
	sb_response_tbl->AddGrowableCol( 1 );
	sb_response_tbl->SetFlexibleDirection( wxBOTH );
	sb_response_tbl->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_challenge = new wxStaticText( m_sb_response->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_challenge->Wrap( -1 );
	m_challenge->SetToolTip( _("Server challenge") );
	
	sb_response_tbl->Add( m_challenge, 0, wxALIGN_CENTER_VERTICAL, 5 );
	
	m_response = new wxTextCtrl( m_sb_response->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_response->SetToolTip( _("Enter your response here") );
	
	sb_response_tbl->Add( m_response, 2, wxEXPAND|wxALIGN_CENTER_VERTICAL, 5 );
	
	
	m_sb_response_vert->Add( sb_response_tbl, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_response_horiz->Add( m_sb_response_vert, 1, wxEXPAND, 5 );
	
	
	m_sb_response->Add( sb_response_horiz, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( m_sb_response );
	this->Layout();
}

wxGTCResponsePanelBase::~wxGTCResponsePanelBase()
{
}
