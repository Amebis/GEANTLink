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
#if defined(__WXMSW__)
#pragma comment(lib, "msi.lib")
#endif


//////////////////////////////////////////////////////////////////////////
// wxEventMonitorApp
//////////////////////////////////////////////////////////////////////////

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

    wxConfigBase *cfgPrev = wxConfigBase::Set(new wxConfig(wxT(PRODUCT_NAME_STR), wxT(VENDOR_NAME_STR)));
    if (cfgPrev) wxDELETE(cfgPrev);

    if (!wxApp::OnInit())
        return false;

    // Set desired locale.
    wxLanguage lang_code;
    wxString lang;
    if (wxConfigBase::Get()->Read(wxT("Language"), &lang)) {
        const wxLanguageInfo *lang_info = wxLocale::FindLanguageInfo(lang);
        lang_code = lang_info ? (wxLanguage)lang_info->Language : wxLANGUAGE_DEFAULT;
    } else
        lang_code = wxLANGUAGE_DEFAULT;
    if (wxLocale::IsAvailable(lang_code)) {
        wxString sPath;
        if (wxConfigBase::Get()->Read(wxT("LocalizationRepositoryPath"), &sPath))
            m_locale.AddCatalogLookupPathPrefix(sPath);
        if (m_locale.Init(lang_code)) {
            //wxVERIFY(m_locale.AddCatalog(wxT("wxExtend") wxT(wxExtendVersion)));
            wxVERIFY(m_locale.AddCatalog(wxT("EventMonitor")));
        }
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

    m_mainWnd = new wxEventMonitorFrame(NULL);
    wxPersistentRegisterAndRestore<wxEventMonitorFrame>(m_mainWnd);
    m_mainWnd->Show();

    return true;
}
