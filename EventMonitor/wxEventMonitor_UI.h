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

#include <wx/string.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/menu.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
class wxEventMonitorLogPanel;
#include <wx/statusbr.h>
#include <wx/frame.h>
#include <wx/aui/aui.h>
#include <wx/listctrl.h>
#include <wx/sizer.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEventMonitorFrameBase
///////////////////////////////////////////////////////////////////////////////
class wxEventMonitorFrameBase : public wxFrame 
{
	private:
	
	protected:
		wxMenuBar* m_menubar;
		wxMenu* m_menuProgram;
		wxStatusBar* m_statusBar;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnClose( wxCloseEvent& event ) { event.Skip(); }
		virtual void OnIconize( wxIconizeEvent& event ) { event.Skip(); }
		virtual void OnIdle( wxIdleEvent& event ) { event.Skip(); }
		
	
	public:
		wxEventMonitorLogPanel* m_panel;
		
		wxEventMonitorFrameBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Event Monitor"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 600,400 ), long style = wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL, const wxString& name = wxT("EventMonitor") );
		wxAuiManager m_mgr;
		
		~wxEventMonitorFrameBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEventMonitorLogPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEventMonitorLogPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxETWListCtrl* m_log;
	
	public:
		
		wxEventMonitorLogPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxT("EventMonitorLogPanel") ); 
		~wxEventMonitorLogPanelBase();
	
};

#endif //__WXEVENTMONITOR_UI_H__
