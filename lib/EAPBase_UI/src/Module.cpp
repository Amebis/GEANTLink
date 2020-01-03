/*
    Copyright 2015-2020 Amebis
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

using namespace std;
using namespace winstd;

//////////////////////////////////////////////////////////////////////
// eap::peer_ui
//////////////////////////////////////////////////////////////////////

eap::peer_ui::peer_ui(_In_ eap_type_t eap_method) : module(eap_method)
{
}


//////////////////////////////////////////////////////////////////////
// eap::monitor_ui
//////////////////////////////////////////////////////////////////////

eap::monitor_ui::monitor_ui(_In_ HINSTANCE module, _In_ const GUID &guid) :
    m_hwnd_popup(NULL)
{
    // Verify if the monitor is already running.
    const WNDCLASSEX wnd_class_desc_master = {
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
    LPCTSTR wnd_class = reinterpret_cast<LPCTSTR>(RegisterClassEx(&wnd_class_desc_master));
    if (!wnd_class) {
        DWORD dwResult = GetLastError();
        if (dwResult == ERROR_CLASS_ALREADY_EXISTS)
            wnd_class = _T(__FUNCTION__);
        else
            throw win_runtime_error(dwResult, __FUNCTION__ " Error registering master monitor window class.");
    }
    tstring_guid guid_str(guid);
    HWND hwnd_master = FindWindowEx(HWND_MESSAGE, NULL, wnd_class, guid_str.c_str());
    if (hwnd_master) {
        // Another monitor is already running.
        m_is_master = false;

        // Register slave windows class slightly different, not to include slaves in FindWindowEx().
        const WNDCLASSEX wnd_class_desc_slave = {
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
        wnd_class = reinterpret_cast<LPCTSTR>(RegisterClassEx(&wnd_class_desc_slave));
        if (!wnd_class) {
            DWORD dwResult = GetLastError();
            if (dwResult == ERROR_CLASS_ALREADY_EXISTS)
                wnd_class = _T(__FUNCTION__) _T("-Slave");
            else
                throw win_runtime_error(dwResult, __FUNCTION__ " Error registering slave monitor window class.");
        }
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


/// \cond internal

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

        HWND hwnd_popup = m_hwnd_popup;
        if (hwnd_popup) {
            // Bring pop-up window up.
            if (::IsIconic(hwnd_popup))
                ::SendMessage(hwnd_popup, WM_SYSCOMMAND, SC_RESTORE, 0);
            ::SetActiveWindow(hwnd_popup);
            ::SetForegroundWindow(hwnd_popup);
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

/// \endcond


const UINT eap::monitor_ui::s_msg_attach  = RegisterWindowMessage(_T(PRODUCT_NAME_STR) _T("-Attach"));
const UINT eap::monitor_ui::s_msg_finish  = RegisterWindowMessage(_T(PRODUCT_NAME_STR) _T("-Finish"));
