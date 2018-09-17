///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXTLS_UI_H__
#define __WXTLS_UI_H__

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
class wxEAPCredentialsPanelBase;

#include "../../EAPBase_UI/include/wxEAP_UIBase.h"
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
#include <wx/listbox.h>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/textctrl.h>
#include <wx/statbox.h>
#include <wx/panel.h>
#include <wx/choice.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxTLSServerTrustPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxTLSServerTrustPanelBase : public wxPanel 
{
	private:
	
	protected:
		wxStaticBitmap* m_server_trust_icon;
		wxStaticText* m_server_trust_label;
		wxStaticText* m_root_ca_lbl;
		wxListBox* m_root_ca;
		wxButton* m_root_ca_add_store;
		wxButton* m_root_ca_add_file;
		wxButton* m_root_ca_remove;
		wxStaticText* m_server_names_label;
		wxTextCtrl* m_server_names;
		wxStaticText* m_server_names_note;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		virtual void OnRootCADClick( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnRootCAAddStore( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnRootCAAddFile( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnRootCARemove( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxTLSServerTrustPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, long style = wxTAB_TRAVERSAL ); 
		~wxTLSServerTrustPanelBase();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class wxTLSCredentialsPanelBase
///////////////////////////////////////////////////////////////////////////////
class wxTLSCredentialsPanelBase : public wxEAPCredentialsPanelBase
{
	private:
	
	protected:
		wxStaticBoxSizer* m_sb_credentials;
		wxStaticBitmap* m_credentials_icon;
		wxBoxSizer* m_sb_credentials_vert;
		wxStaticText* m_certificate_label;
		wxChoice* m_certificate;
		wxStaticText* m_identity_label;
		wxTextCtrl* m_identity;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnUpdateUI( wxUpdateUIEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxTLSCredentialsPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, long style = wxTAB_TRAVERSAL ); 
		~wxTLSCredentialsPanelBase();
	
};

#endif //__WXTLS_UI_H__
