/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"
#if defined(__WXMSW__)
#pragma comment(lib, "msi.lib")
#endif


//////////////////////////////////////////////////////////////////////////
// wxEventMonitorApp
//////////////////////////////////////////////////////////////////////////

#pragma warning(suppress: 28251)
wxIMPLEMENT_APP(wxEventMonitorApp);


wxEventMonitorApp::wxEventMonitorApp() : wxApp()
{
}


bool wxEventMonitorApp::OnInit()
{
#if defined(__WXMSW__)
    // To compensate migration to non-advertised shortcut, do the Microsoft Installer's feature completeness check manually.
    // If execution got this far in the first place (EXE and dependent DLLs are present and loadable).
    // Furthermore, this increments program usage counter.
    if (::MsiQueryFeatureState(_T(PRODUCT_VERSION_GUID), _T("featEventMonitor")) != INSTALLSTATE_UNKNOWN)
        ::MsiUseFeature(_T(PRODUCT_VERSION_GUID), _T("featEventMonitor"));
#endif

    wxInitializeConfig();

    if (!wxApp::OnInit())
        return false;

    if (wxInitializeLocale(m_locale)) {
        wxVERIFY(m_locale.AddCatalog(wxT("wxExtend") wxT(wxExtendVersion)));
        wxVERIFY(m_locale.AddCatalog(wxT("EventMonitor")));
    }

#ifdef __WXMSW__
    // Find EventMonitor window if already running.
    HWND hWnd = ::FindWindow(_T("wxWindowNR"), _("Event Monitor"));
    if (hWnd) {
        if (::IsIconic(hWnd))
            ::SendMessage(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0);
        ::SetActiveWindow(hWnd);
        ::SetForegroundWindow(hWnd);

        // Not an error condition actually; Just nothing else to do...
        return false;
    }
#endif

    wxEventMonitorFrame *mainWnd = new wxEventMonitorFrame(NULL);
    wxPersistentRegisterAndRestore<wxEventMonitorFrame>(mainWnd);
    mainWnd->Show();

    return true;
}
