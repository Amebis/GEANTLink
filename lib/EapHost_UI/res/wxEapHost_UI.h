///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEAPHOST_UI_H__
#define __WXEAPHOST_UI_H__

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
#include <wx/choice.h>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEapHostMethodConfigPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEapHostMethodConfigPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_method_icon;
		wxStaticText* m_method_label;
		wxChoice* m_method;
		wxButton* m_settings;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		virtual void OnSettings( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEapHostMethodConfigPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, long style = wxTAB_TRAVERSAL ); 
		~wxEapHostMethodConfigPanelBase();
	
};

#endif //__WXEAPHOST_UI_H__
