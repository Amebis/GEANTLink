///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEAPMETHODS_H__
#define __WXEAPMETHODS_H__

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
class wxEAPBannerPanel;
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/notebook.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <wx/dialog.h>
#include <wx/stattext.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPConfigBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPConfigBase : public wxDialog 
{
	private:
	
	protected:
		wxEAPBannerPanel *m_banner;
		wxNotebook* m_providers;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsOK;
		wxButton* m_buttonsCancel;
	
	public:
		
		wxEAPConfigBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Method Configuration"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPConfigBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPBannerPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPBannerPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticText* m_product_name;
	
	public:
		
		wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = 0 ); 
		~wxEAPBannerPanelBase();
	
};

#endif //__WXEAPMETHODS_H__
