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
	
	m_banner = new wxEAPBannerPanel( this );
	
	sz_content->Add( m_banner, 0, wxEXPAND|wxBOTTOM, 5 );
	
	m_providers = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	
	sz_content->Add( m_providers, 1, wxEXPAND|wxALL, 5 );
	
	m_buttons = new wxStdDialogButtonSizer();
	m_buttonsOK = new wxButton( this, wxID_OK );
	m_buttons->AddButton( m_buttonsOK );
	m_buttonsCancel = new wxButton( this, wxID_CANCEL );
	m_buttons->AddButton( m_buttonsCancel );
	m_buttons->Realize();
	
	sz_content->Add( m_buttons, 0, wxEXPAND|wxALL, 5 );
	
	
	this->SetSizer( sz_content );
	this->Layout();
	sz_content->Fit( this );
	
	this->Centre( wxBOTH );
}

wxEAPConfigBase::~wxEAPConfigBase()
{
}

wxEAPBannerPanelBase::wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style ) : wxPanel( parent, id, pos, size, style )
{
	this->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
	this->SetMinSize( wxSize( -1,48 ) );
	
	wxBoxSizer* sc_content;
	sc_content = new wxBoxSizer( wxVERTICAL );
	
	m_product_name = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_product_name->Wrap( -1 );
	m_product_name->SetFont( wxFont( 14, 70, 90, 90, false, wxEmptyString ) );
	
	sc_content->Add( m_product_name, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( sc_content );
	this->Layout();
	sc_content->Fit( this );
}

wxEAPBannerPanelBase::~wxEAPBannerPanelBase()
{
}
