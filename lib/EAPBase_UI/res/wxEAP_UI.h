///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Aug  8 2018)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEAP_UI_H__
#define __WXEAP_UI_H__

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
#include "../include/wxEAP_UIBase.h"
class wxEAPBannerPanel;
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/notebook.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/dialog.h>
#include <wx/stattext.h>
#include <wx/panel.h>
#include <wx/statbmp.h>
#include <wx/radiobut.h>
#include <wx/statbox.h>
#include <wx/timer.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
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
		wxButton* m_prov_add;
		wxButton* m_prov_remove;
		wxButton* m_prov_advanced;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsOK;
		wxButton* m_buttonsCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnInitDialog( wxInitDialogEvent& event ) { event.Skip(); }
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		virtual void OnProvAdd( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnProvRemove( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnProvAdvanced( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPConfigDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Connection Configuration"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPConfigDialogBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPGeneralDialogBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPGeneralDialogBase : public wxDialog 
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
		
		wxEAPGeneralDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPGeneralDialogBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPCredentialsConnectionDialogBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPCredentialsConnectionDialogBase : public wxDialog 
{
	private:
	
	protected:
		wxEAPBannerPanel *m_banner;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsOK;
		wxButton* m_buttonsCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnInitDialog( wxInitDialogEvent& event ) { event.Skip(); }
		
	
	public:
		wxNotebook* m_providers;
		
		wxEAPCredentialsConnectionDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Credentials"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPCredentialsConnectionDialogBase();
	
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
		
		wxEAPBannerPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = 0, const wxString& name = wxEmptyString ); 
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
		
		wxEAPNotePanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL|wxBORDER_SIMPLE, const wxString& name = wxEmptyString ); 
		~wxEAPNotePanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPCredentialsConfigPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPCredentialsConfigPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBoxSizer* m_sb_credentials;
		wxStaticBitmap* m_credentials_icon;
		wxStaticText* m_credentials_label;
		wxRadioButton* m_storage;
		wxStaticText* m_storage_identity_label;
		wxStaticText* m_storage_identity;
		wxButton* m_storage_clear;
		wxButton* m_storage_set;
		wxRadioButton* m_config;
		wxStaticText* m_config_identity_label;
		wxStaticText* m_config_identity;
		wxButton* m_config_set;
		wxTimer m_timer_storage;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		virtual void OnClearStorage( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnSetStorage( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnSetConfig( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnTimerStorage( wxTimerEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPCredentialsConfigPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxEAPCredentialsConfigPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxPasswordCredentialsPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxPasswordCredentialsPanelBase : public wxEAPCredentialsPanelBase
{
	private:
	
	protected:
		wxStaticBoxSizer* m_sb_credentials;
		wxStaticBitmap* m_credentials_icon;
		wxBoxSizer* m_sb_credentials_vert;
		wxStaticText* m_credentials_label;
		wxStaticText* m_identity_label;
		wxTextCtrl* m_identity;
		wxStaticText* m_password_label;
		wxTextCtrl* m_password;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnPasswordText( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxPasswordCredentialsPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxPasswordCredentialsPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxIdentityCredentialsPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxIdentityCredentialsPanelBase : public wxEAPCredentialsPanelBase
{
	private:
	
	protected:
		wxStaticBoxSizer* m_sb_credentials;
		wxStaticBitmap* m_credentials_icon;
		wxBoxSizer* m_sb_credentials_vert;
		wxStaticText* m_credentials_label;
		wxStaticText* m_identity_label;
		wxTextCtrl* m_identity;
	
	public:
		
		wxIdentityCredentialsPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxIdentityCredentialsPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPProviderContactInfoPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPProviderContactInfoPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_provider_contact_icon;
		wxStaticText* m_provider_contact_label;
		wxStaticText* m_provider_name_label;
		wxTextCtrl* m_provider_name;
		wxStaticText* m_provider_name_note;
		wxStaticText* m_provider_helpdesk_label;
		wxStaticText* m_provider_web_icon;
		wxTextCtrl* m_provider_web;
		wxStaticText* m_provider_email_icon;
		wxTextCtrl* m_provider_email;
		wxStaticText* m_provider_phone_icon;
		wxTextCtrl* m_provider_phone;
	
	public:
		
		wxEAPProviderContactInfoPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxEAPProviderContactInfoPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPProviderIDPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPProviderIDPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_provider_id_icon;
		wxStaticText* m_provider_id_label_outer;
		wxStaticText* m_provider_namespace_label;
		wxChoice* m_provider_namespace;
		wxStaticText* m_provider_id_label;
		wxTextCtrl* m_provider_id;
	
	public:
		
		wxEAPProviderIDPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxEAPProviderIDPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPProviderLockPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPProviderLockPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_provider_lock_icon;
		wxStaticText* m_provider_lock_label;
		wxCheckBox* m_provider_lock;
		wxStaticText* m_provider_lock_note;
	
	public:
		
		wxEAPProviderLockPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL, const wxString& name = wxEmptyString ); 
		~wxEAPProviderLockPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPProviderSelectDialogBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPProviderSelectDialogBase : public wxDialog 
{
	private:
	
	protected:
		wxEAPBannerPanel *m_banner;
		wxBoxSizer* m_providers;
		wxStdDialogButtonSizer* m_buttons;
		wxButton* m_buttonsCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnInitDialog( wxInitDialogEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPProviderSelectDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("EAP Identity Provider"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE ); 
		~wxEAPProviderSelectDialogBase();
	
};

#endif //__WXEAP_UI_H__
