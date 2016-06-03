///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Jun 17 2015)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __WXEAPTTLS_H__
#define __WXEAPTTLS_H__

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
#include <wx/radiobut.h>
#include <wx/textctrl.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/panel.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class wxEAPTTLSConfigBase
///////////////////////////////////////////////////////////////////////////////
class wxEAPTTLSConfigBase : public wxPanel 
{
	DECLARE_EVENT_TABLE()
	private:
		
		// Private event handlers
		void _wxFB_OnOuterIdentitySame( wxCommandEvent& event ){ OnOuterIdentitySame( event ); }
		void _wxFB_OnOuterIdentityEmpty( wxCommandEvent& event ){ OnOuterIdentityEmpty( event ); }
		void _wxFB_OnOuterIdentityCustom( wxCommandEvent& event ){ OnOuterIdentityCustom( event ); }
		
	
	protected:
		wxStaticBitmap* m_outer_identity_icon;
		wxStaticText* m_outer_identity_label;
		wxRadioButton* m_outer_identity_same;
		wxRadioButton* m_outer_identity_empty;
		wxRadioButton* m_outer_identity_custom;
		wxTextCtrl* m_outer_identity_custom_val;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnOuterIdentitySame( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnOuterIdentityEmpty( wxCommandEvent& event ) { event.Skip(); }
		virtual void OnOuterIdentityCustom( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		wxEAPTTLSConfigBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,-1 ), long style = wxTAB_TRAVERSAL ); 
		~wxEAPTTLSConfigBase();
	
};

#endif //__WXEAPTTLS_H__
