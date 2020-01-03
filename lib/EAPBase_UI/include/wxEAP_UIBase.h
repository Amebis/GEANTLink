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

class wxEAPCredentialsPanelBase;

#pragma once

#include <wx/panel.h>


///
/// \defgroup EAPBaseGUI  GUI
/// Graphical User Interface
///
/// @{

///
/// Base class for all credential entry panel that must provide "Remember" credentials checkbox
///
class wxEAPCredentialsPanelBase : public wxPanel
{
public:
    ///
    /// Constructs a wxPanel with "Remember" credentials checkbox
    ///
    /// \param[in] parent  The parent window
    /// \param[in] winid   An identifier for the panel. \c wxID_ANY is taken to mean a default.
    /// \param[in] pos     The panel position. The value \c wxDefaultPosition indicates a default position, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] size    The panel size. The value \c wxDefaultSize indicates a default size, chosen by either the windowing system or wxWidgets, depending on platform.
    /// \param[in] style   The window style. See `wxPanel`.
    /// \param[in] name    Window name
    ///
    wxEAPCredentialsPanelBase(wxWindow *parent,
            wxWindowID winid = wxID_ANY,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            long style = wxTAB_TRAVERSAL | wxNO_BORDER,
            const wxString& name = wxPanelNameStr) : wxPanel(parent, winid, pos, size, style, name)
    {
    }

    ///
    /// (Un)checks "Remember credentials" checkbox
    ///
    /// \param[in] val  If \c true, checkbox is checked; otherwise cleared
    ///
    virtual void SetRemember(bool val) = 0;

    ///
    /// Returns \c true if "Remember credentials" checkbox is checked
    ///
    virtual bool GetRemember() const = 0;
};

/// @}
