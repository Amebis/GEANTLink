///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Oct 26 2018)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#pragma once

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/statbmp.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/panel.h>
#include <wx/choicebk.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxGTCResponsePanelBase
///////////////////////////////////////////////////////////////////////////////
class wxGTCResponsePanelBase : public wxPanel
{
	private:

	protected:
		wxStaticBoxSizer* m_sb_response;
		wxStaticBitmap* m_response_icon;
		wxBoxSizer* m_sb_response_vert;
		wxStaticText* m_response_label;
		wxStaticText* m_challenge;
		wxTextCtrl* m_response;

	public:

		wxGTCResponsePanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, long style = wxTAB_TRAVERSAL ); 
		~wxGTCResponsePanelBase();

};

///////////////////////////////////////////////////////////////////////////////
/// Class wxGTCConfigPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxGTCConfigPanelBase : public wxPanel
{
	private:

	protected:
		wxStaticText* m_auth_mode_label;
		wxChoicebook* m_auth_mode;

		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }


	public:

		wxGTCConfigPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, long style = wxTAB_TRAVERSAL ); 
		~wxGTCConfigPanelBase();

};

