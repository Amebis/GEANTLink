/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "../../EAPBase_UI/include/EAP_UI.h"
#include "../../EapHost/include/Config.h"

class wxEAPMethodTypeClientData;
class wxEapHostMethodConfigPanel;
class wxEapHostConfigPanel;

/// \addtogroup EAPBaseGUI
/// @{

///
/// EapHost peer method credential configuration panel
///
typedef wxEAPCredentialsConfigPanel<eap::credentials_pass, wxPasswordCredentialsPanel<eap::credentials_pass, wxPasswordCredentialsPanelBase> > wxEapHostCredentialsConfigPanel;

/// @}

#pragma once

#include "../res/wxEapHost_UI.h"

#include <wx/panel.h>
#include <wx/stattext.h>

#include <Windows.h>


/// \addtogroup EAPBaseGUI
/// @{

///
/// Helper class for auto-destroyable EAP_METHOD_TYPE used in wxWidget's item containers
///
class wxEAPMethodTypeClientData : public wxClientData
{
public:
    ///
    /// Constructs client data object with existing handle
    ///
    wxEAPMethodTypeClientData(const EAP_METHOD_TYPE &type, DWORD properties);

public:
    EAP_METHOD_TYPE m_type;             ///< EapHost method type
    DWORD m_properties;                 ///< Method properties
    eap::sanitizing_blob m_cfg_blob;    ///< Method configuration BLOB
};


///
/// Inner EAP method config panel
///
class wxEapHostMethodConfigPanel : public wxEapHostMethodConfigPanelBase
{
public:
    ///
    /// Constructs an inner EAP method config panel
    ///
    /// \param[in   ] prov    Provider configuration data
    /// \param[inout] cfg     Method configuration data
    /// \param[in   ] parent  Parent window
    ///
    wxEapHostMethodConfigPanel(const eap::config_provider &prov, eap::config_method_eaphost &cfg, wxWindow *parent);

protected:
    /// \cond internal
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();
    virtual void OnUpdateUI(wxUpdateUIEvent& event);
    virtual void OnSettings(wxCommandEvent& event);
    /// \endcond

protected:
    eap::config_method_eaphost &m_cfg;   ///< Method configuration
};


///
/// EapHost peer method configuration panel
///
class wxEapHostConfigPanel : public wxPanel
{
public:
    ///
    /// Constructs a configuration panel
    ///
    /// \param[in   ] prov    Provider configuration data
    /// \param[inout] cfg     Method configuration data
    /// \param[in   ] parent  Parent window
    ///
    wxEapHostConfigPanel(const eap::config_provider &prov, eap::config_method_eaphost &cfg, wxWindow* parent);

    ///
    /// Destructs the configuration panel
    ///
    virtual ~wxEapHostConfigPanel();

protected:
    /// \cond internal
    virtual void OnInitDialog(wxInitDialogEvent& event);
    /// \endcond

protected:
    wxEapHostMethodConfigPanel *m_method; ///< Method configuration panel
};

/// @}
