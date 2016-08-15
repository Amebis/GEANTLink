///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEAP_UI_H__
#define __WXEAP_UI_H__

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
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/statbmp.h>
#include <wx/radiobut.h>
#include <wx/textctrl.h>
#include <wx/statbox.h>
#include <wx/checkbox.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPConfigDialogBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPConfigDialogBase : public wxDialog 
{
	private:
	
	protected:
		wxEAPBannerPanel *m_banner;
		wxNotebook* m_providers;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsOK;
		wxButton* m_buttonsCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnInitDialog( wxInitDialogEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPConfigDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Method Configuration"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPConfigDialogBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPCredentialsDialogBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPCredentialsDialogBase : public wxDialog 
{
	private:
	
	protected:
		wxEAPBannerPanel *m_banner;
		wxBoxSizer* m_panels;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsOK;
		wxButton* m_buttonsCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnInitDialog( wxInitDialogEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPCredentialsDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Credentials"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPCredentialsDialogBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPBannerPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPBannerPanelBase : public wxPanel 
{
	private:
	
	protected:
	
	public:
		wxStaticText* m_title;
		
		wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = 0 ); 
		~wxEAPBannerPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPNotePanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPNotePanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_note_icon;
		wxBoxSizer* m_note_vert;
		wxStaticText* m_note_label;
	
	public:
		
		wxEAPNotePanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxSIMPLE_BORDER|wxTAB_TRAVERSAL ); 
		~wxEAPNotePanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPCredentialsConfigPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPCredentialsConfigPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_credentials_icon;
		wxStaticText* m_credentials_label;
		wxRadioButton* m_own;
		wxTextCtrl* m_own_identity;
		wxButton* m_own_clear;
		wxButton* m_own_set;
		wxRadioButton* m_preshared;
		wxTextCtrl* m_preshared_identity;
		wxButton* m_preshared_set;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		virtual void OnClearOwn( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnSetOwn( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnSetPreshared( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPCredentialsConfigPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL ); 
		~wxEAPCredentialsConfigPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPCredentialsPanelPassBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPCredentialsPanelPassBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_credentials_icon;
		wxStaticText* m_credentials_label;
		wxStaticText* m_identity_label;
		wxTextCtrl* m_identity;
		wxStaticText* m_password_label;
		wxTextCtrl* m_password;
		wxCheckBox* m_remember;
	
	public:
		
		wxEAPCredentialsPanelPassBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL ); 
		~wxEAPCredentialsPanelPassBase();
	
};

#endif //__WXEAP_UI_H__
