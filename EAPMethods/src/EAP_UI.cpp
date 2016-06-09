/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GÉANTLink.

    GÉANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GÉANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include <StdAfx.h>


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialsDialog
//////////////////////////////////////////////////////////////////////

wxEAPCredentialsDialog::wxEAPCredentialsDialog(wxWindow* parent) : wxEAPCredentialsDialogBase(parent)
{
    // Set extra style here, as wxFormBuilder overrides all default flags.
    this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

    m_buttonsOK->SetDefault();
}


void wxEAPCredentialsDialog::AddContents(wxPanel **contents, size_t content_count)
{
    if (content_count) {
        for (size_t i = 0; i < content_count; i++)
            m_panels->Add(contents[i], 0, wxALL|wxEXPAND, 5);

        this->Layout();
        this->GetSizer()->Fit(this);
        contents[0]->SetFocusFromKbd();
    }
}


void wxEAPCredentialsDialog::OnInitDialog(wxInitDialogEvent& event)
{
    for (wxSizerItemList::compatibility_iterator panel = m_panels->GetChildren().GetFirst(); panel; panel = panel->GetNext())
        panel->GetData()->GetWindow()->GetEventHandler()->ProcessEvent(event);
}


//////////////////////////////////////////////////////////////////////
// wxEAPBannerPanel
//////////////////////////////////////////////////////////////////////

wxEAPBannerPanel::wxEAPBannerPanel(wxWindow* parent) : wxEAPBannerPanelBase(parent)
{
    m_title->SetLabelText(wxT(PRODUCT_NAME_STR));
}


//////////////////////////////////////////////////////////////////////
// wxPasswordCredentialsPanel
//////////////////////////////////////////////////////////////////////

const wxStringCharType *wxPasswordCredentialsPanel::s_dummy_password = wxT("dummypass");


wxPasswordCredentialsPanel::wxPasswordCredentialsPanel(eap::credentials_pass &cred, LPCTSTR pszCredTarget, wxWindow* parent, bool is_config) :
    wxCredentialsPanel<wxPasswordCredentialsPanelBase, eap::credentials_pass>(cred, pszCredTarget, parent, is_config)
{
    // Load and set icon.
    if (m_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        wxSetIconFromResource(m_credentials_icon, m_icon, m_shell32, MAKEINTRESOURCE(269));
}


bool wxPasswordCredentialsPanel::TransferDataToWindow()
{
    wxCHECK(__super::TransferDataToWindow(), false);

    m_identity->SetValue(m_cred.m_identity);
    m_password->SetValue(m_cred.m_password.empty() ? wxEmptyString : s_dummy_password);

    return true;
}


bool wxPasswordCredentialsPanel::TransferDataFromWindow()
{
    m_cred.m_identity = m_identity->GetValue();

    wxString pass = m_password->GetValue();
    if (pass.compare(s_dummy_password) != 0) {
        m_cred.m_password = pass;
        pass.assign(pass.length(), wxT('*'));
    }

    return __super::TransferDataFromWindow();
}
