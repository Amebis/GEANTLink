///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxEAPMsg_UI.h"

///////////////////////////////////////////////////////////////////////////

wxEAPMsgMethodConfigPanelBase::wxEAPMsgMethodConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_method;
	sb_method = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("Inner EAP Method") ), wxVERTICAL );
	
	wxBoxSizer* sb_method_horiz;
	sb_method_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_method_icon = new wxStaticBitmap( sb_method->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_method_horiz->Add( m_method_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_method_vert;
	sb_method_vert = new wxBoxSizer( wxVERTICAL );
	
	m_method_label = new wxStaticText( sb_method->GetStaticBox(), wxID_ANY, _("Select and configure inner EAP method"), wxDefaultPosition, wxDefaultSize, 0 );
	m_method_label->Wrap( 440 );
	sb_method_vert->Add( m_method_label, 0, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* sb_method_inner;
	sb_method_inner = new wxBoxSizer( wxHORIZONTAL );
	
	wxArrayString m_methodChoices;
	m_method = new wxChoice( sb_method->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, m_methodChoices, 0 );
	m_method->SetSelection( 0 );
	sb_method_inner->Add( m_method, 1, wxRIGHT|wxEXPAND, 5 );
	
	m_settings = new wxButton( sb_method->GetStaticBox(), wxID_ANY, _("&Settings"), wxDefaultPosition, wxDefaultSize, 0 );
	sb_method_inner->Add( m_settings, 0, 0, 5 );
	
	
	sb_method_vert->Add( sb_method_inner, 0, wxEXPAND|wxALL, 5 );
	
	
	sb_method_horiz->Add( sb_method_vert, 1, wxEXPAND, 5 );
	
	
	sb_method->Add( sb_method_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_method );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPMsgMethodConfigPanelBase::OnUpdateUI ) );
	m_settings->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPMsgMethodConfigPanelBase::OnSettings ), NULL, this );
}

wxEAPMsgMethodConfigPanelBase::~wxEAPMsgMethodConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxEAPMsgMethodConfigPanelBase::OnUpdateUI ) );
	m_settings->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( wxEAPMsgMethodConfigPanelBase::OnSettings ), NULL, this );
	
}
