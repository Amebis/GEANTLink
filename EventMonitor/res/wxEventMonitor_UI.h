///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEVENTMONITOR_UI_H__
#define __WXEVENTMONITOR_UI_H__

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
class wxETWListCtrl;

#include <wx/listctrl.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/sizer.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEventMonitorLogPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEventMonitorLogPanelBase : public wxPanel 
{
	private:
	
	protected:
	
	public:
		wxETWListCtrl* m_log;
		
		wxEventMonitorLogPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxT("EventMonitorLogPanel") ); 
		~wxEventMonitorLogPanelBase();
	
};

#endif //__WXEVENTMONITOR_UI_H__
