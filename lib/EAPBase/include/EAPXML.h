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

#include <MsXml.h>
#include <msxml6.h>
#include <sal.h>

#include <string>
#include <vector>

namespace eapxml
{
    inline HRESULT get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ IXMLDOMDocument2 **ppXmlDoc);
    inline HRESULT select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode);
    inline HRESULT select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes);
    inline HRESULT select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement);
    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode);
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue);
    template<class _Traits, class _Ax> inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue);
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool *pbValue);
    template<class _Ty, class _Ax> inline HRESULT get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue);
    template<class _Ty, class _Ax> inline HRESULT get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue);
    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ BSTR *pbstrValue);
    template<class _Traits, class _Ax> inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);
    inline HRESULT put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue);
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue);
    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue);
    inline HRESULT put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline HRESULT put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ BSTR *pbstrValue);
    template<class _Traits, class _Ax> inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ DWORD *pdwValue);
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ bool *pbValue);
    template<class _Ty, class _Ax> inline HRESULT get_attrib_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue);
    template<class _Ty, class _Ax> inline HRESULT get_attrib_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue);
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_opt_z_ _In_z_ const BSTR bstrValue);
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_opt_z_ _In_ DWORD dwValue);
    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_opt_z_ _In_ bool bValue);
    inline HRESULT put_attrib_base64(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_opt_z_ _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline HRESULT put_attrib_hex(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline std::wstring get_xpath(_In_ IXMLDOMNode *pXmlNode);
}

#pragma once

#include <WinStd/Base64.h>
#include <WinStd/COM.h>
#include <WinStd/Hex.h>

#include <assert.h>


namespace eapxml
{
    inline HRESULT get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ IXMLDOMDocument2 **ppXmlDoc)
    {
        assert(pXmlNode);
        assert(ppXmlDoc);

        HRESULT hr;
        winstd::com_obj<IXMLDOMDocument> doc;

        return
            SUCCEEDED(hr = pXmlNode->get_ownerDocument(&doc)) &&
            SUCCEEDED(hr = doc.query_interface(ppXmlDoc)) ? S_OK : hr;
    }


    inline HRESULT select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode)
    {
        assert(pXmlParent);
        assert(ppXmlNode);

        HRESULT hr;

        return
            SUCCEEDED(hr = pXmlParent->selectSingleNode(bstrNodeName, ppXmlNode)) ?
            *ppXmlNode ? S_OK : E_NOT_SET : hr;
    }


    inline HRESULT select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes)
    {
        assert(pXmlParent);
        assert(ppXmlNodes);

        HRESULT hr;

        return
            SUCCEEDED(hr = pXmlParent->selectNodes(bstrNodeName, ppXmlNodes)) ?
            *ppXmlNodes ? S_OK : E_NOT_SET : hr;
    }


    inline HRESULT select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(ppXmlElement);

        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            SUCCEEDED(hr = select_node(pXmlParent, bstrElementName, &pXmlNode)) ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            *ppXmlElement ? S_OK : E_NOT_SET : hr : hr;
    }


    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(pDoc);
        assert(ppXmlElement);

        static const winstd::variant varNodeTypeEl(NODE_ELEMENT);
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlNode)) ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            *ppXmlElement ? S_OK : E_NOT_SET : hr : hr;
    }


    inline HRESULT create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(pDoc);
        assert(pXmlParent);
        assert(ppXmlElement);

        HRESULT hr;

        return
            SUCCEEDED(hr = select_element(pXmlParent, bstrElementNameSelect, ppXmlElement)) ? S_OK :
            SUCCEEDED(hr = create_element(pDoc, bstrElementNameCreate, bstrNamespace, ppXmlElement)) ?
            SUCCEEDED(hr = pXmlParent->appendChild(*ppXmlElement, NULL)) ? S_OK : hr : hr;
    }


    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode)
    {
        assert(pXmlNode);

        winstd::com_obj<IXMLDOMNode> pXmlNodeParent;

        return SUCCEEDED(pXmlNode->get_parentNode(&pXmlNodeParent)) && pXmlNodeParent;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue)
    {
        assert(pbstrValue);

        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;

        return
            SUCCEEDED(hr = select_element(pXmlParent, bstrElementName, &pXmlElement)) ?
            SUCCEEDED(hr = pXmlElement->get_text(pbstrValue)) ?
            *pbstrValue ? S_OK : E_NOT_SET : hr : hr;
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue)
    {
        assert(pdwValue);

        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (SUCCEEDED(hr))
            *pdwValue = wcstoul(bstr, NULL, 10);
        return hr;
    }


    inline HRESULT get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool *pbValue)
    {
        assert(pbValue);

        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (SUCCEEDED(hr)) {
            if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = true;
            else if (
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = false;
            else
                hr = E_NOT_VALID_STATE;
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::base64_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::hex_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ BSTR *pbstrValue)
    {
        assert(pbstrValue);

        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;

        if (FAILED(hr = select_element(pXmlParent, bstrElementName, &pXmlElement)))
            return hr;

        winstd::com_obj<IXMLDOMNodeList> pXmlListLocalizedText;
        long lCount = 0;
        if (FAILED(select_nodes(pXmlElement, winstd::bstr(L"eap-metadata:localized-text"), &pXmlListLocalizedText)) ||
            FAILED(pXmlListLocalizedText->get_length(&lCount)) ||
            lCount <= 0)
        {
            return
                SUCCEEDED(hr = pXmlElement->get_text(pbstrValue)) ?
                *pbstrValue ? S_OK : E_NOT_SET : hr;
        }

        winstd::bstr bstrDefault, bstrEn;
        for (long i = 0; ; i++) {
            if (i >= lCount) {
                if (bstrDefault != NULL) {
                    // Return "C" localization.
                    *pbstrValue = bstrDefault.detach();
                    return S_OK;
                } else if (bstrEn != NULL) {
                    // Return "en" localization.
                    *pbstrValue = bstrEn.detach();
                    return S_OK;
                } else
                    return ERROR_NOT_FOUND;
            }

            winstd::com_obj<IXMLDOMNode> pXmlElLocalizedText;
            pXmlListLocalizedText->get_item(i, &pXmlElLocalizedText);

            {
                // Read <lang>.
                winstd::bstr bstrLang;
                if (FAILED(get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:lang"), &bstrLang)) ||
                    CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"C" , -1, NULL, NULL, 0) == CSTR_EQUAL)
                {
                    // <lang> is missing or "C" language found.
                    winstd::bstr bstr;
                    if (SUCCEEDED(hr = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), &bstr)))
                        bstrDefault.attach(bstr.detach());
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), pszLang, -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // Found an exact match.
                    return get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), pbstrValue);
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"en", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // "en" language found.
                    winstd::bstr bstr;
                    if (SUCCEEDED(hr = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), &bstr)))
                        bstrEn.attach(bstr.detach());
                }
            }
        }
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_element_localized(pXmlParent, bstrElementName, pszLang, &bstr);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(pDoc);
        assert(pCurrentDOMNode);
        assert(ppXmlElement);

        static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlEl;

        return 
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl)) &&
            SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)) &&
            SUCCEEDED(hr = pXmlEl.query_interface(ppXmlElement)) ? S_OK : hr;
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue)
    {
        assert(pDoc);

        static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlEl;
        winstd::com_obj<IXMLDOMText> pXmlElText;

        return
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl)) &&
            SUCCEEDED(hr = pDoc->createTextNode(bstrValue, &pXmlElText)) &&
            SUCCEEDED(hr = pXmlEl->appendChild(pXmlElText, NULL)) &&
            SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)) ? S_OK : hr;
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(winstd::wstring_printf(L"%d", dwValue)));
    }


    inline HRESULT put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(bValue ? L"true": L"false"));
    }


    inline HRESULT put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sBase64;
        winstd::base64_enc enc;
        enc.encode(sBase64, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sBase64));
    }


    inline HRESULT put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sHex;
        winstd::hex_enc enc;
        enc.encode(sHex, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sHex));
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ BSTR *pbstrValue)
    {
        assert(pbstrValue);

        HRESULT hr;
        winstd::com_obj<IXMLDOMNamedNodeMap> pXmlAttributes;
        winstd::com_obj<IXMLDOMNode> pXmlAt;
        VARIANT varValue;
        V_VT(&varValue) = VT_EMPTY;

        return
            SUCCEEDED(hr = pXmlParent->get_attributes(&pXmlAttributes)) ?
            SUCCEEDED(hr = pXmlAttributes->getNamedItem(bstrAttributeName, &pXmlAt)) ?
            pXmlAt ?
            SUCCEEDED(hr = pXmlAt->get_nodeValue(&varValue)) ?
            V_VT(&varValue) == VT_BSTR ? *pbstrValue = V_BSTR(&varValue), S_OK : E_UNEXPECTED : hr : E_NOT_SET : hr : hr;
    }


    template<class _Traits, class _Ax>
    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr))
            sValue.assign(bstr, bstr.length());
        return hr;
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ DWORD *pdwValue)
    {
        assert(pdwValue);

        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr))
            *pdwValue = wcstoul(bstr, NULL, 10);
        return hr;
    }


    inline HRESULT get_attrib_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ bool *pbValue)
    {
        assert(pbValue);

        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr)) {
            if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = true;
            else if (
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = false;
            else
                hr = E_NOT_VALID_STATE;
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_attrib_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::base64_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    template<class _Ty, class _Ax>
    inline HRESULT get_attrib_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrAttributeName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        HRESULT hr = get_attrib_value(pXmlParent, bstrAttributeName, &bstr);
        if (SUCCEEDED(hr)) {
            winstd::hex_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return hr;
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_z_ const BSTR bstrValue)
    {
        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlEl;
        VARIANT varValue;
        V_VT(&varValue) = VT_BSTR;
        V_BSTR(&varValue) = bstrValue;

        return
            SUCCEEDED(hr = pCurrentDOMNode->QueryInterface(__uuidof(IXMLDOMElement), (void**)&pXmlEl)) &&
            SUCCEEDED(hr = pXmlEl->setAttribute(bstrAttributeName, varValue)) ? S_OK : hr;
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ DWORD dwValue)
    {
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(winstd::wstring_printf(L"%d", dwValue)));
    }


    inline HRESULT put_attrib_value(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_ bool bValue)
    {
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(bValue ? L"true": L"false"));
    }


    inline HRESULT put_attrib_base64(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sBase64;
        winstd::base64_enc enc;
        enc.encode(sBase64, pValue, nValueLen);
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(sBase64));
    }


    inline HRESULT put_attrib_hex(_In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrAttributeName, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sHex;
        winstd::hex_enc enc;
        enc.encode(sHex, pValue, nValueLen);
        return put_attrib_value(pCurrentDOMNode, bstrAttributeName, winstd::bstr(sHex));
    }


    inline std::wstring get_xpath(_In_ IXMLDOMNode *pXmlNode)
    {
        if (pXmlNode) {
            winstd::bstr bstr;
            winstd::com_obj<IXMLDOMNode> pXmlNodeParent;

            return
                SUCCEEDED(pXmlNode->get_nodeName(&bstr)) ?
                SUCCEEDED(pXmlNode->get_parentNode(&pXmlNodeParent)) ? get_xpath(pXmlNodeParent) + L"/" + (LPCWSTR)bstr : (LPCWSTR)bstr : L"?";
        } else
            return L"";
    }
}
