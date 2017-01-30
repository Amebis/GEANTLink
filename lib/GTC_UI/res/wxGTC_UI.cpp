///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxGTC_UI.h"

///////////////////////////////////////////////////////////////////////////

wxGTCMethodConfigPanelBase::wxGTCMethodConfigPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	wxStaticBoxSizer* sb_method;
	sb_method = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("GTC Settings") ), wxVERTICAL );
	
	wxBoxSizer* sb_method_horiz;
	sb_method_horiz = new wxBoxSizer( wxHORIZONTAL );
	
	m_method_icon = new wxStaticBitmap( sb_method->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sb_method_horiz->Add( m_method_icon, 0, wxALL, 5 );
	
	wxBoxSizer* sb_method_vert;
	sb_method_vert = new wxBoxSizer( wxVERTICAL );
	
	m_method_label = new wxStaticText( sb_method->GetStaticBox(), wxID_ANY, _("This method requires no additional configuration."), wxDefaultPosition, wxDefaultSize, 0 );
	m_method_label->Wrap( 440 );
	sb_method_vert->Add( m_method_label, 0, wxALL|wxEXPAND, 5 );
	
	
	sb_method_horiz->Add( sb_method_vert, 1, wxEXPAND, 5 );
	
	
	sb_method->Add( sb_method_horiz, 1, wxEXPAND, 5 );
	
	
	this->SetSizer( sb_method );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxGTCMethodConfigPanelBase::OnUpdateUI ) );
}

wxGTCMethodConfigPanelBase::~wxGTCMethodConfigPanelBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_UPDATE_UI, wxUpdateUIEventHandler( wxGTCMethodConfigPanelBase::OnUpdateUI ) );
	
}
