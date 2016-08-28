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

///
/// Base class for all credential entry panel that must provide "Remember" credentials checkbox
///
class wxEAPCredentialsPanelBase;

#pragma once

#include <wx/panel.h>


class wxEAPCredentialsPanelBase : public wxPanel
{
public:
    ///
    /// Constructs a wxPanel with "Remember" credentials checkbox
    ///
    wxEAPCredentialsPanelBase(wxWindow *parent,
            wxWindowID winid = wxID_ANY,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            long style = wxTAB_TRAVERSAL | wxNO_BORDER,
            const wxString& name = wxPanelNameStr) : wxPanel(parent, winid, pos, size, style, name)
    {
    }

    virtual void SetRemember(bool val) = 0;
    virtual bool GetRemember() const = 0;
};
