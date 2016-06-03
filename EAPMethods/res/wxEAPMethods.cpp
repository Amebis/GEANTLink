///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include <StdAfx.h>

#include "wxEAPMethods.h"

///////////////////////////////////////////////////////////////////////////

wxEAPConfigBase::wxEAPConfigBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* sz_content;
	sz_content = new wxBoxSizer( wxVERTICAL );
	
	m_banner = new wxStaticBitmap( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sz_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	
	sz_content->Add( m_providers, 0, wxEXPAND|wxALL, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sz_content->Add( m_buttons, 0, wxEXPAND, 5 );
	
	
	this->SetSizer( sz_content );
	this->Layout();
	sz_content->Fit( this );
	
	this->Centre( wxBOTH );
}

wxEAPConfigBase::~wxEAPConfigBase()
{
}
