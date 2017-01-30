///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXGTC_UI_H__
#define __WXGTC_UI_H__

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
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxGTCMethodConfigPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxGTCMethodConfigPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_method_icon;
		wxStaticText* m_method_label;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxGTCMethodConfigPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL ); 
		~wxGTCMethodConfigPanelBase();
	
};

#endif //__WXGTC_UI_H__
