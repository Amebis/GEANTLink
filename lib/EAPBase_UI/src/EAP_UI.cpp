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

#include "StdAfx.h"


//////////////////////////////////////////////////////////////////////
// wxEAPBannerPanel
//////////////////////////////////////////////////////////////////////

wxEAPBannerPanel::wxEAPBannerPanel(wxWindow* parent) : wxEAPBannerPanelBase(parent)
{
}


bool wxEAPBannerPanel::AcceptsFocusFromKeyboard() const
{
    return false;
}


//////////////////////////////////////////////////////////////////////
// wxEAPGeneralDialog
//////////////////////////////////////////////////////////////////////

wxEAPGeneralDialog::wxEAPGeneralDialog(wxWindow *parent, wxWindowID id, const wxString &title, const wxPoint &pos, const wxSize &size, long style) :
    wxEAPGeneralDialogBase(parent, id, title, pos, size, style)
{
    // Set extra style here, as wxFormBuilder overrides all default flags.
    this->SetExtraStyle(this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);

    // Load window icons.
#ifdef __WINDOWS__
    wxIconBundle icons;
    icons.AddIcon(wxIcon(wxT("product.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON)));
    icons.AddIcon(wxIcon(wxT("product.ico"), wxBITMAP_TYPE_ICO_RESOURCE, ::GetSystemMetrics(SM_CXICON  ), ::GetSystemMetrics(SM_CYICON  )));
    this->SetIcons(icons);
#else
    this->SetIcon(wxIcon(wxICON(product.ico)));
#endif

    m_buttonsOK->SetDefault();
}


void wxEAPGeneralDialog::AddContent(wxPanel **contents, size_t content_count)
{
    if (content_count) {
        for (size_t i = 0; i < content_count; i++)
            m_panels->Add(contents[i], 0, wxALL|wxEXPAND, 5);

        this->Layout();
        this->GetSizer()->Fit(this);
        contents[0]->SetFocusFromKbd();
    }
}


void wxEAPGeneralDialog::AddContent(wxPanel *content)
{
    AddContent(&content, 1);
}


void wxEAPGeneralDialog::OnInitDialog(wxInitDialogEvent& event)
{
    wxEAPGeneralDialogBase::OnInitDialog(event);

    for (wxSizerItemList::compatibility_iterator panel = m_panels->GetChildren().GetFirst(); panel; panel = panel->GetNext())
        panel->GetData()->GetWindow()->GetEventHandler()->ProcessEvent(event);
}


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialsDialog
//////////////////////////////////////////////////////////////////////

wxEAPCredentialsDialog::wxEAPCredentialsDialog(const eap::config_provider &prov, wxWindow *parent, wxWindowID id, const wxString &title, const wxPoint &pos, const wxSize &size, long style) :
    wxEAPGeneralDialog(parent, id, title, pos, size, style)
{
    // Set banner title.
    m_banner->m_title->SetLabel(wxString::Format(_("%s Credentials"), wxEAPGetProviderName(prov.m_name)));
}


//////////////////////////////////////////////////////////////////////
// wxEAPNotePanel
//////////////////////////////////////////////////////////////////////

wxEAPNotePanel::wxEAPNotePanel(wxWindow* parent) :
    m_provider_notice(NULL),
    m_help_web_label(NULL),
    m_help_web_value(NULL),
    m_help_email_label(NULL),
    m_help_email_value(NULL),
    m_help_phone_label(NULL),
    m_help_phone_value(NULL),
    wxEAPNotePanelBase(parent)
{
}


bool wxEAPNotePanel::AcceptsFocusFromKeyboard() const
{
    return m_help_web_value || m_help_email_value || m_help_phone_label;
}


void wxEAPNotePanel::CreateContactFields(const eap::config_provider &prov)
{
    if (!prov.m_help_email.empty() || !prov.m_help_web.empty() || !prov.m_help_phone.empty()) {
        m_provider_notice = new wxStaticText(this, wxID_ANY, wxString::Format(_("For additional help and instructions, please contact %s at:"),
            !prov.m_name.empty() ? prov.m_name.c_str() : _("your provider")), wxDefaultPosition, wxDefaultSize, 0);
        m_provider_notice->Wrap(449);
        m_note_vert->Add(m_provider_notice, 0, wxUP|wxLEFT|wxRIGHT|wxEXPAND, 5);

        wxFlexGridSizer* sb_contact_tbl;
        sb_contact_tbl = new wxFlexGridSizer(0, 2, 5, 5);
        sb_contact_tbl->AddGrowableCol(1);
        sb_contact_tbl->SetFlexibleDirection(wxBOTH);
        sb_contact_tbl->SetNonFlexibleGrowMode(wxFLEX_GROWMODE_SPECIFIED);

        wxFont font_wingdings(-1, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Wingdings"));

        if (!prov.m_help_web.empty()) {
            m_help_web_label = new wxStaticText(this, wxID_ANY, wxT("\xb6"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_web_label->Wrap(-1);
            m_help_web_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_web_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_web_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_web, prov.m_help_web, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_web_value->SetToolTip(_("Open the default web browser"));
            sb_contact_tbl->Add(m_help_web_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        if (!prov.m_help_email.empty()) {
            m_help_email_label = new wxStaticText(this, wxID_ANY, wxT("\x2a"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_email_label->Wrap(-1);
            m_help_email_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_email_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_email_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_email, wxString(wxT("mailto:")) + prov.m_help_email, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_email_value->SetToolTip(_("Open your e-mail program"));
            sb_contact_tbl->Add(m_help_email_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        if (!prov.m_help_phone.empty()) {
            m_help_phone_label = new wxStaticText(this, wxID_ANY, wxT("\x29"), wxDefaultPosition, wxDefaultSize, 0);
            m_help_phone_label->Wrap(-1);
            m_help_phone_label->SetFont(font_wingdings);
            sb_contact_tbl->Add(m_help_phone_label, 0, wxEXPAND|wxALIGN_TOP, 5);

            m_help_phone_value = new wxHyperlinkCtrl(this, wxID_ANY, prov.m_help_phone, wxString(wxT("tel:")) + GetPhoneNumber(prov.m_help_phone.c_str()), wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE);
            m_help_phone_value->SetToolTip(_("Dial the phone number"));
            sb_contact_tbl->Add(m_help_phone_value, 0, wxEXPAND|wxALIGN_TOP, 5);
        }

        m_note_vert->Add(sb_contact_tbl, 0, wxLEFT|wxRIGHT|wxDOWN|wxEXPAND, 5);
    }
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderLockedPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderLockedPanel::wxEAPProviderLockedPanel(const eap::config_provider &prov, wxWindow* parent) : wxEAPNotePanel(parent)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_note_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(48)));

    m_note_label->SetLabel(wxString::Format(_("%s has pre-set parts of this configuration. Those parts are locked to prevent accidental modification."),
        !prov.m_name.empty() ? prov.m_name.c_str() : _("Your provider")));
    m_note_label->Wrap(449);

    CreateContactFields(prov);

    this->Layout();
}


//////////////////////////////////////////////////////////////////////
// wxEAPCredentialWarningPanel
//////////////////////////////////////////////////////////////////////

wxEAPCredentialWarningPanel::wxEAPCredentialWarningPanel(const eap::config_provider &prov, eap::config_method::status_t status, wxWindow* parent) : wxEAPNotePanel(parent)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_note_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(161)));

    m_note_label->SetLabel((
        status == eap::config_method::status_cred_invalid  ? _("Previous attempt to connect reported invalid credentials.") :
        status == eap::config_method::status_cred_expired  ? _("Previous attempt to connect reported your credentials expired.") :
        status == eap::config_method::status_cred_changing ? _("Previous attempt to connect reported your credentials are being changed.") :
                                                             _("Previous attempt to connect failed.")) + " " +
        _("Please, make sure your credentials are correct, or try again later."));
    m_note_label->Wrap(449);

    CreateContactFields(prov);

    this->Layout();
}


//////////////////////////////////////////////////////////////////////
// wxEAPConfigWindow
//////////////////////////////////////////////////////////////////////

wxEAPConfigWindow::wxEAPConfigWindow(eap::config_provider &prov, eap::config_method &cfg, wxWindow* parent) :
    m_prov(prov),
    m_cfg(cfg),
    wxScrolledWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL)
{
    this->SetScrollRate(5, 5);

    // Connect Events
    this->Connect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPConfigWindow::OnInitDialog));
}


wxEAPConfigWindow::~wxEAPConfigWindow()
{
    // Disconnect Events
    this->Disconnect(wxEVT_INIT_DIALOG, wxInitDialogEventHandler(wxEAPConfigWindow::OnInitDialog));
}


void wxEAPConfigWindow::OnInitDialog(wxInitDialogEvent& event)
{
    // Call TransferDataToWindow() manually, as wxScrolledWindow somehow skips that.
    TransferDataToWindow();

    event.Skip();
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderContactInfoPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderContactInfoPanel::wxEAPProviderContactInfoPanel(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderContactInfoPanelBase(parent)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_provider_contact_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(259)));
}


bool wxEAPProviderContactInfoPanel::TransferDataToWindow()
{
    m_provider_name ->SetValue(m_prov.m_name      );
    m_provider_web  ->SetValue(m_prov.m_help_web  );
    m_provider_email->SetValue(m_prov.m_help_email);
    m_provider_phone->SetValue(m_prov.m_help_phone);

    return wxEAPProviderContactInfoPanelBase::TransferDataToWindow();
}


bool wxEAPProviderContactInfoPanel::TransferDataFromWindow()
{
    wxCHECK(wxEAPProviderContactInfoPanelBase::TransferDataFromWindow(), false);

    m_prov.m_name       = m_provider_name ->GetValue();
    m_prov.m_help_web   = m_provider_web  ->GetValue();
    m_prov.m_help_email = m_provider_email->GetValue();
    m_prov.m_help_phone = m_provider_phone->GetValue();

    return true;
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderIDPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderIDPanel::wxEAPProviderIDPanel(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderIDPanelBase(parent)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_provider_id_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(29)));
}


bool wxEAPProviderIDPanel::TransferDataToWindow()
{
    m_provider_namespace->SetStringSelection(m_prov.m_namespace);
    m_provider_id       ->SetValue(m_prov.m_id);

    return wxEAPProviderIDPanelBase::TransferDataToWindow();
}


bool wxEAPProviderIDPanel::TransferDataFromWindow()
{
    wxCHECK(wxEAPProviderIDPanelBase::TransferDataFromWindow(), false);

    m_prov.m_namespace = m_provider_namespace->GetStringSelection();
    m_prov.m_id        = m_provider_id       ->GetValue();

    return true;
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderLockPanel
//////////////////////////////////////////////////////////////////////

wxEAPProviderLockPanel::wxEAPProviderLockPanel(eap::config_provider &prov, wxWindow* parent) :
    m_prov(prov),
    wxEAPProviderLockPanelBase(parent)
{
    // Load and set icon.
    winstd::library lib_shell32;
    if (lib_shell32.load(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        m_provider_lock_icon->SetIcon(wxLoadIconFromResource(lib_shell32, MAKEINTRESOURCE(1003)));
}


bool wxEAPProviderLockPanel::TransferDataToWindow()
{
    m_provider_lock->SetValue(m_prov.m_read_only);

    return wxEAPProviderLockPanelBase::TransferDataToWindow();
}


bool wxEAPProviderLockPanel::TransferDataFromWindow()
{
    wxCHECK(wxEAPProviderLockPanelBase::TransferDataFromWindow(), false);

    m_prov.m_read_only = m_provider_lock->GetValue();

    return true;
}


//////////////////////////////////////////////////////////////////////
// wxEAPConfigProvider
//////////////////////////////////////////////////////////////////////

wxEAPConfigProvider::wxEAPConfigProvider(eap::config_provider &prov, wxWindow *parent, wxWindowID id, const wxString &title, const wxPoint &pos, const wxSize &size, long style) :
    m_prov(prov),
    wxEAPGeneralDialog(parent, id, title, pos, size, style)
{
    // Set banner title.
    m_banner->m_title->SetLabel(title);

    m_contact = new wxEAPProviderContactInfoPanel(prov, this);
    AddContent(m_contact);

    m_identity = new wxEAPProviderIDPanel(prov, this);
    AddContent(m_identity);

    m_lock = new wxEAPProviderLockPanel(prov, this);
    AddContent(m_lock);

    m_contact->m_provider_name->SetFocusFromKbd();
}


//////////////////////////////////////////////////////////////////////
// wxEAPProviderSelectDialog
//////////////////////////////////////////////////////////////////////

wxEAPProviderSelectDialog::wxEAPProviderSelectDialog(eap::config_connection &cfg, wxWindow *parent) :
    m_selected(NULL),
    wxEAPProviderSelectDialogBase(parent)
{
    // Set banner title.
    std::unique_ptr<eap::config_method> cfg_dummy(cfg.m_module.make_config_method());
    m_banner->m_title->SetLabel(wxString::Format("%s %s", wxT(PRODUCT_NAME_STR), cfg_dummy->get_method_str()));

    for (auto prov = cfg.m_providers.cbegin(), prov_end = cfg.m_providers.cend(); prov != prov_end; ++prov) {
        wxCommandLinkButton *btn = new wxCommandLinkButton(this, wxID_ANY, wxEAPGetProviderName(prov->m_name));
        m_providers->Add(btn, 0, wxALL|wxEXPAND, 5);

        btn->Connect(wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(wxEAPProviderSelectDialog::OnProvSelect), new wxVariant((void*)&*prov), this);
    }

    this->Layout();
    this->GetSizer()->Fit(this);
}


void wxEAPProviderSelectDialog::OnProvSelect(wxCommandEvent& event)
{
    // Set selected provider and dismiss dialog.
    m_selected = static_cast<eap::config_provider*>(dynamic_cast<const wxVariant*>(event.GetEventUserData())->GetVoidPtr());
    this->EndModal(wxID_OK);
    event.Skip();
}


using namespace std;
using namespace winstd;

//////////////////////////////////////////////////////////////////////
// eap::monitor_ui
//////////////////////////////////////////////////////////////////////

eap::monitor_ui::monitor_ui(_In_ HINSTANCE module, _In_ const GUID &guid) :
    m_hwnd_popup(NULL)
{
    // Verify if the monitor is already running.
    const WNDCLASSEX wnd_class_desc = {
        sizeof(WNDCLASSEX), // cbSize
        0,                  // style
        winproc,            // lpfnWndProc
        0,                  // cbClsExtra
        0,                  // cbWndExtra
        module,             // hInstance
        NULL,               // hIcon
        NULL,               // hCursor
        NULL,               // hbrBackground
        NULL,               // lpszMenuName
        _T(__FUNCTION__),   // lpszClassName
        NULL                // hIconSm
    };
    ATOM wnd_class = RegisterClassEx(&wnd_class_desc);
    if (!wnd_class)
        throw win_runtime_error(__FUNCTION__ " Error registering master monitor window class.");
    tstring_guid guid_str(guid);
    HWND hwnd_master = FindWindowEx(HWND_MESSAGE, NULL, reinterpret_cast<LPCTSTR>(wnd_class), guid_str.c_str());
    if (hwnd_master) {
        // Another monitor is already running.
        m_is_master = false;

        // Register slave windows class slightly different, not to include slaves in FindWindowEx().
        const WNDCLASSEX wnd_class_desc = {
            sizeof(WNDCLASSEX),             // cbSize
            0,                              // style
            winproc,                        // lpfnWndProc
            0,                              // cbClsExtra
            0,                              // cbWndExtra
            module,                         // hInstance
            NULL,                           // hIcon
            NULL,                           // hCursor
            NULL,                           // hbrBackground
            NULL,                           // lpszMenuName
            _T(__FUNCTION__) _T("-Slave"),  // lpszClassName
            NULL                            // hIconSm
        };
        wnd_class = RegisterClassEx(&wnd_class_desc);
        if (!wnd_class)
            throw win_runtime_error(__FUNCTION__ " Error registering slave monitor window class.");
    } else {
        // This is a fresh monitor.
        m_is_master = true;
    }

    m_hwnd = CreateWindowEx(
        0,                                    // dwExStyle
        reinterpret_cast<LPCTSTR>(wnd_class), // lpClassName
        guid_str.c_str(),                     // lpWindowName
        0,                                    // dwStyle
        0,                                    // x
        0,                                    // y
        0,                                    // nWidth
        0,                                    // nHeight
        HWND_MESSAGE,                         // hWndParent
        NULL,                                 // hMenu
        module,                               // hInstance
        this);                                // lpParam

    if (!m_is_master) {
        // Notify master we are waiting him.
        SendMessage(hwnd_master, s_msg_attach, 0, (LPARAM)m_hwnd);

        // Slaves must pump message queue until finished.
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}


eap::monitor_ui::~monitor_ui()
{
    if (m_hwnd)
        DestroyWindow(m_hwnd);
}


void eap::monitor_ui::set_popup(_In_ HWND hwnd)
{
    m_hwnd_popup = hwnd;
}


void eap::monitor_ui::release_slaves(_In_bytecount_(size) const void *data, _In_ size_t size) const
{
    assert(!size || data);

    for (auto slave = m_slaves.cbegin(), slave_end = m_slaves.cend(); slave != slave_end; ++slave) {
        // Get slave's PID.
        DWORD pid_slave;
        GetWindowThreadProcessId(*slave, &pid_slave);

        // Get slave's process handle.
        process proc_slave;
        if (!proc_slave.open(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, pid_slave))
            continue;

        // Allocate memory in slave's virtual memory space and save data to it.
        vmemory mem_slave;
        if (!mem_slave.alloc(proc_slave, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
            continue;
        if (!WriteProcessMemory(proc_slave, mem_slave, data, size, NULL))
            continue;

        // Notify slave. Use SendMessage(), not PostMessage(), as memory will get cleaned up.
        SendMessage(*slave, s_msg_finish, (WPARAM)size, (LPARAM)(LPVOID)mem_slave);
    }
}


LRESULT eap::monitor_ui::winproc(
    _In_ UINT   msg,
    _In_ WPARAM wparam,
    _In_ LPARAM lparam)
{
    UNREFERENCED_PARAMETER(wparam);

    if (msg == s_msg_attach) {
        // Attach a new slave.
        assert(m_is_master);
        m_slaves.push_back((HWND)lparam);

        if (m_hwnd_popup) {
            // Bring pop-up window up.
            if (::IsIconic(m_hwnd_popup))
                ::SendMessage(m_hwnd_popup, WM_SYSCOMMAND, SC_RESTORE, 0);
            ::SetActiveWindow(m_hwnd_popup);
            ::SetForegroundWindow(m_hwnd_popup);
        }

        return TRUE;
    } else if (msg == s_msg_finish) {
        // Master finished.
        assert(!m_is_master);
        m_data.assign(reinterpret_cast<const unsigned char*>(lparam), reinterpret_cast<const unsigned char*>(lparam) + wparam);

        // Finish slave too.
        DestroyWindow(m_hwnd);
        return TRUE;
    } else if (msg == WM_DESTROY) {
        // Stop the message pump.
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(m_hwnd, msg, wparam, lparam);
}


LRESULT CALLBACK eap::monitor_ui::winproc(
    _In_ HWND   hwnd,
    _In_ UINT   msg,
    _In_ WPARAM wparam,
    _In_ LPARAM lparam)
{
    if (msg == WM_CREATE) {
        // Set window's user data to "this" pointer.
        const CREATESTRUCT *cs = (CREATESTRUCT*)lparam;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);

        // Forward to our handler.
        return ((eap::monitor_ui*)cs->lpCreateParams)->winproc(msg, wparam, lparam);
    } else {
        // Get "this" pointer from window's user data.
        eap::monitor_ui *_this = (eap::monitor_ui*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        if (_this) {
            // Forward to our handler.
            return _this->winproc(msg, wparam, lparam);
        } else
            return DefWindowProc(hwnd, msg, wparam, lparam);
    }
}


const UINT eap::monitor_ui::s_msg_attach  = RegisterWindowMessage(_T(PRODUCT_NAME_STR) _T("-Attach"));
const UINT eap::monitor_ui::s_msg_finish  = RegisterWindowMessage(_T(PRODUCT_NAME_STR) _T("-Finish"));
