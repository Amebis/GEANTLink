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
    inline DWORD get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ IXMLDOMDocument2 **ppXmlDoc);
    inline DWORD select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode);
    inline DWORD select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes);
    inline DWORD select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement);
    inline DWORD create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline DWORD create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode);
    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue);
    template<class _Traits, class _Ax> inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);
    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue);
    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool *pbValue);
    template<class _Ty, class _Ax> inline DWORD get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue);
    template<class _Ty, class _Ax> inline DWORD get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue);
    inline DWORD get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ BSTR *pbstrValue);
    template<class _Traits, class _Ax> inline DWORD get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue);
    inline DWORD put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue);
    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue);
    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue);
    inline DWORD put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline DWORD put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    inline std::wstring get_xpath(_In_ IXMLDOMNode *pXmlNode);
}

#pragma once

#include <WinStd/Base64.h>
#include <WinStd/COM.h>
#include <WinStd/Hex.h>

#include <assert.h>


namespace eapxml
{
    inline DWORD get_document(_In_ IXMLDOMNode *pXmlNode, _Out_ IXMLDOMDocument2 **ppXmlDoc)
    {
        assert(pXmlNode);
        assert(ppXmlDoc);

        HRESULT hr;
        winstd::com_obj<IXMLDOMDocument> doc;

        return
            SUCCEEDED(hr = pXmlNode->get_ownerDocument(&doc)) &&
            SUCCEEDED(hr = doc.query_interface(ppXmlDoc)) ? ERROR_SUCCESS : HRESULT_CODE(hr);
    }


    inline DWORD select_node(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode)
    {
        assert(pXmlParent);
        assert(ppXmlNode);

        HRESULT hr;

        return
            SUCCEEDED(hr = pXmlParent->selectSingleNode(bstrNodeName, ppXmlNode)) ?
            *ppXmlNode ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr);
    }


    inline DWORD select_nodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes)
    {
        assert(pXmlParent);
        assert(ppXmlNodes);

        HRESULT hr;

        return
            SUCCEEDED(hr = pXmlParent->selectNodes(bstrNodeName, ppXmlNodes)) ?
            *ppXmlNodes ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr);
    }


    inline DWORD select_element(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(ppXmlElement);

        DWORD dwResult;
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            (dwResult = select_node(pXmlParent, bstrElementName, &pXmlNode)) == ERROR_SUCCESS ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            *ppXmlElement ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr) : dwResult;
    }


    inline DWORD create_element(_In_ IXMLDOMDocument *pDoc, _In_z_ const BSTR bstrElementName, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(pDoc);
        assert(ppXmlElement);

        static const winstd::variant varNodeTypeEl(NODE_ELEMENT);
        HRESULT hr;
        winstd::com_obj<IXMLDOMNode> pXmlNode;

        return
            SUCCEEDED(hr = pDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlNode)) ?
            SUCCEEDED(hr = pXmlNode.query_interface(ppXmlElement)) ?
            *ppXmlElement ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr) : HRESULT_CODE(hr);
    }


    inline DWORD create_element(_In_ IXMLDOMDocument *pDoc, IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementNameSelect, _In_z_ const BSTR bstrElementNameCreate, _In_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
    {
        assert(pDoc);
        assert(pXmlParent);
        assert(ppXmlElement);

        DWORD dwResult;
        HRESULT hr;

        return
            (dwResult = select_element(pXmlParent, bstrElementNameSelect, ppXmlElement)) == ERROR_SUCCESS ? ERROR_SUCCESS :
            (dwResult = create_element(pDoc, bstrElementNameCreate, bstrNamespace, ppXmlElement)) == ERROR_SUCCESS ?
            SUCCEEDED(hr = pXmlParent->appendChild(*ppXmlElement, NULL)) ? ERROR_SUCCESS : HRESULT_CODE(hr) : dwResult;
    }


    inline bool has_parent(_In_ IXMLDOMNode *pXmlNode)
    {
        assert(pXmlNode);

        winstd::com_obj<IXMLDOMNode> pXmlNodeParent;

        return SUCCEEDED(pXmlNode->get_parentNode(&pXmlNodeParent)) && pXmlNodeParent;
    }


    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue)
    {
        assert(pbstrValue);

        DWORD dwResult;
        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;

        return
            (dwResult = select_element(pXmlParent, bstrElementName, &pXmlElement)) == ERROR_SUCCESS ?
            SUCCEEDED(hr = pXmlElement->get_text(pbstrValue)) ?
            *pbstrValue ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr) : dwResult;
    }


    template<class _Traits, class _Ax>
    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        DWORD dwResult = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (dwResult == ERROR_SUCCESS)
            sValue.assign(bstr, bstr.length());
        return dwResult;
    }


    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue)
    {
        assert(pdwValue);

        winstd::bstr bstr;
        DWORD dwResult = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (dwResult == ERROR_SUCCESS)
            *pdwValue = wcstoul(bstr, NULL, 10);
        return dwResult;
    }


    inline DWORD get_element_value(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ bool *pbValue)
    {
        assert(pbValue);

        winstd::bstr bstr;
        DWORD dwResult = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (dwResult == ERROR_SUCCESS) {
            if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = true;
            else if (
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
                CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
                *pbValue = false;
            else
                dwResult = ERROR_INVALID_DATA;
        }

        return dwResult;
    }


    template<class _Ty, class _Ax>
    inline DWORD get_element_base64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        DWORD dwResult = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (dwResult == ERROR_SUCCESS) {
            winstd::base64_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return dwResult;
    }


    template<class _Ty, class _Ax>
    inline DWORD get_element_hex(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ std::vector<_Ty, _Ax> &aValue)
    {
        winstd::bstr bstr;
        DWORD dwResult = get_element_value(pXmlParent, bstrElementName, &bstr);
        if (dwResult == ERROR_SUCCESS) {
            winstd::hex_dec dec;
            bool is_last;
            dec.decode(aValue, is_last, (BSTR)bstr, bstr.length());
        }

        return dwResult;
    }


    inline DWORD get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ BSTR *pbstrValue)
    {
        assert(pbstrValue);

        HRESULT hr;
        winstd::com_obj<IXMLDOMElement> pXmlElement;

        DWORD dwResult = select_element(pXmlParent, bstrElementName, &pXmlElement);
        if (dwResult != ERROR_SUCCESS)
            return dwResult;

        winstd::com_obj<IXMLDOMNodeList> pXmlListLocalizedText;
        long lCount = 0;
        if (select_nodes(pXmlElement, winstd::bstr(L"eap-metadata:localized-text"), &pXmlListLocalizedText) != ERROR_SUCCESS ||
            FAILED(pXmlListLocalizedText->get_length(&lCount)) ||
            lCount <= 0)
        {
            return
                SUCCEEDED(hr = pXmlElement->get_text(pbstrValue)) ?
                *pbstrValue ? ERROR_SUCCESS : ERROR_NO_DATA : HRESULT_CODE(hr);
        }

        winstd::bstr bstrDefault, bstrEn;
        for (long i = 0; ; i++) {
            if (i >= lCount) {
                if (bstrDefault != NULL) {
                    // Return "C" localization.
                    *pbstrValue = bstrDefault.detach();
                    return ERROR_SUCCESS;
                } else if (bstrEn != NULL) {
                    // Return "en" localization.
                    *pbstrValue = bstrEn.detach();
                    return ERROR_SUCCESS;
                } else
                    return ERROR_NOT_FOUND;
            }

            winstd::com_obj<IXMLDOMNode> pXmlElLocalizedText;
            pXmlListLocalizedText->get_item(i, &pXmlElLocalizedText);

            {
                // Read <lang>.
                winstd::bstr bstrLang;
                if (get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:lang"), &bstrLang) != ERROR_SUCCESS ||
                    CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"C" , -1, NULL, NULL, 0) == CSTR_EQUAL)
                {
                    // <lang> is missing or "C" language found.
                    winstd::bstr bstr;
                    if ((dwResult = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), &bstr)) == ERROR_SUCCESS)
                        bstrDefault.attach(bstr.detach());
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), pszLang, -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // Found an exact match.
                    return get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), pbstrValue);
                } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.length(), L"en", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    // "en" language found.
                    winstd::bstr bstr;
                    if ((dwResult = get_element_value(pXmlElLocalizedText, winstd::bstr(L"eap-metadata:text"), &bstr)) == ERROR_SUCCESS)
                        bstrEn.attach(bstr.detach());
                }
            }
        }
    }


    template<class _Traits, class _Ax>
    inline DWORD get_element_localized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCWSTR pszLang, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &sValue)
    {
        winstd::bstr bstr;
        DWORD dwResult = get_element_localized(pXmlParent, bstrElementName, pszLang, &bstr);
        if (dwResult == ERROR_SUCCESS)
            sValue.assign(bstr, bstr.length());
        return dwResult;
    }


    inline DWORD put_element(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
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
            SUCCEEDED(hr = pXmlEl.query_interface(ppXmlElement)) ? ERROR_SUCCESS : HRESULT_CODE(hr);
    }


    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue)
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
            SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)) ? ERROR_SUCCESS : HRESULT_CODE(hr);
    }


    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(winstd::wstring_printf(L"%d", dwValue)));
    }


    inline DWORD put_element_value(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ bool bValue)
    {
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(bValue ? L"true": L"false"));
    }


    inline DWORD put_element_base64(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sBase64;
        winstd::base64_enc enc;
        enc.encode(sBase64, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sBase64));
    }


    inline DWORD put_element_hex(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
    {
        std::wstring sHex;
        winstd::hex_enc enc;
        enc.encode(sHex, pValue, nValueLen);
        return put_element_value(pDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, winstd::bstr(sHex));
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
