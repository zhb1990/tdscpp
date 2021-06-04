#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#include "tdscpp.h"
#include "tdscpp-private.h"
#include "config.h"
#include <iostream>
#include <string>

#ifndef _WIN32
#include <codecvt>
#endif

#include <list>
#include <map>
#include <charconv>
#include <regex>
#include <fmt/format.h>
#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#ifdef HAVE_GSSAPI
#include <gssapi/gssapi.h>
#endif

#include <unistd.h>
#else
#define SECURITY_WIN32
#include <sspi.h>
#endif

// #define DEBUG_SHOW_MSGS

#ifndef _WIN32
#define CP_UTF8 65001
#include <unicode/ucnv.h>
#endif

using namespace std;

#define BROWSER_PORT 1434

static const uint32_t tds_74_version = 0x4000074;

template<>
struct fmt::formatter<enum tds::token> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum tds::token t, format_context& ctx) {
        switch (t) {
            case tds::token::OFFSET:
                return format_to(ctx.out(), "OFFSET");

            case tds::token::RETURNSTATUS:
                return format_to(ctx.out(), "RETURNSTATUS");

            case tds::token::COLMETADATA:
                return format_to(ctx.out(), "COLMETADATA");

            case tds::token::ALTMETADATA:
                return format_to(ctx.out(), "ALTMETADATA");

            case tds::token::DATACLASSIFICATION:
                return format_to(ctx.out(), "DATACLASSIFICATION");

            case tds::token::TABNAME:
                return format_to(ctx.out(), "TABNAME");

            case tds::token::COLINFO:
                return format_to(ctx.out(), "COLINFO");

            case tds::token::ORDER:
                return format_to(ctx.out(), "ORDER");

            case tds::token::TDS_ERROR:
                return format_to(ctx.out(), "ERROR");

            case tds::token::INFO:
                return format_to(ctx.out(), "INFO");

            case tds::token::RETURNVALUE:
                return format_to(ctx.out(), "RETURNVALUE");

            case tds::token::LOGINACK:
                return format_to(ctx.out(), "LOGINACK");

            case tds::token::FEATUREEXTACK:
                return format_to(ctx.out(), "FEATUREEXTACK");

            case tds::token::ROW:
                return format_to(ctx.out(), "ROW");

            case tds::token::NBCROW:
                return format_to(ctx.out(), "NBCROW");

            case tds::token::ALTROW:
                return format_to(ctx.out(), "ALTROW");

            case tds::token::ENVCHANGE:
                return format_to(ctx.out(), "ENVCHANGE");

            case tds::token::SESSIONSTATE:
                return format_to(ctx.out(), "SESSIONSTATE");

            case tds::token::SSPI:
                return format_to(ctx.out(), "SSPI");

            case tds::token::FEDAUTHINFO:
                return format_to(ctx.out(), "FEDAUTHINFO");

            case tds::token::DONE:
                return format_to(ctx.out(), "DONE");

            case tds::token::DONEPROC:
                return format_to(ctx.out(), "DONEPROC");

            case tds::token::DONEINPROC:
                return format_to(ctx.out(), "DONEINPROC");

            default:
                return format_to(ctx.out(), "{:x}", (uint8_t)t);
        }
    }
};


namespace tds {
    u16string utf8_to_utf16(const string_view& sv) {
#ifdef _WIN32
        u16string ret;

        if (sv.empty())
            return u"";

        auto len = MultiByteToWideChar(CP_UTF8, 0, sv.data(), (int)sv.length(), nullptr, 0);

        if (len == 0)
            throw runtime_error("MultiByteToWideChar 1 failed.");

        ret.resize(len);

        len = MultiByteToWideChar(CP_UTF8, 0, sv.data(), (int)sv.length(), (wchar_t*)ret.data(), len);

        if (len == 0)
            throw runtime_error("MultiByteToWideChar 2 failed.");

        return ret;
#else
        wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

        return convert.from_bytes(sv.data(), sv.data() + sv.length());
#endif
    }

    string utf16_to_utf8(const u16string_view& sv) {
#ifdef _WIN32
        string ret;

        if (sv.empty())
            return "";

        auto len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)sv.data(), (int)sv.length(), nullptr, 0,
                                    nullptr, nullptr);

        if (len == 0)
            throw runtime_error("WideCharToMultiByte 1 failed.");

        ret.resize(len);

        len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)sv.data(), (int)sv.length(), ret.data(), len,
                                nullptr, nullptr);

        if (len == 0)
            throw runtime_error("WideCharToMultiByte 2 failed.");

        return ret;
#else
        wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

        return convert.to_bytes(sv.data(), sv.data() + sv.length());
#endif
    }
}

#ifdef _WIN32
template<>
struct fmt::formatter<enum sec_error> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum sec_error t, format_context& ctx) {
        switch (t) {
            case sec_error::_SEC_E_OK:
                return format_to(ctx.out(), "SEC_E_OK");

            case sec_error::_SEC_E_INSUFFICIENT_MEMORY:
                return format_to(ctx.out(), "SEC_E_INSUFFICIENT_MEMORY");

            case sec_error::_SEC_E_INVALID_HANDLE:
                return format_to(ctx.out(), "SEC_E_INVALID_HANDLE");

            case sec_error::_SEC_E_UNSUPPORTED_FUNCTION:
                return format_to(ctx.out(), "SEC_E_UNSUPPORTED_FUNCTION");

            case sec_error::_SEC_E_TARGET_UNKNOWN:
                return format_to(ctx.out(), "SEC_E_TARGET_UNKNOWN");

            case sec_error::_SEC_E_INTERNAL_ERROR:
                return format_to(ctx.out(), "SEC_E_INTERNAL_ERROR");

            case sec_error::_SEC_E_SECPKG_NOT_FOUND:
                return format_to(ctx.out(), "SEC_E_SECPKG_NOT_FOUND");

            case sec_error::_SEC_E_NOT_OWNER:
                return format_to(ctx.out(), "SEC_E_NOT_OWNER");

            case sec_error::_SEC_E_CANNOT_INSTALL:
                return format_to(ctx.out(), "SEC_E_CANNOT_INSTALL");

            case sec_error::_SEC_E_INVALID_TOKEN:
                return format_to(ctx.out(), "SEC_E_INVALID_TOKEN");

            case sec_error::_SEC_E_CANNOT_PACK:
                return format_to(ctx.out(), "SEC_E_CANNOT_PACK");

            case sec_error::_SEC_E_QOP_NOT_SUPPORTED:
                return format_to(ctx.out(), "SEC_E_QOP_NOT_SUPPORTED");

            case sec_error::_SEC_E_NO_IMPERSONATION:
                return format_to(ctx.out(), "SEC_E_NO_IMPERSONATION");

            case sec_error::_SEC_E_LOGON_DENIED:
                return format_to(ctx.out(), "SEC_E_LOGON_DENIED");

            case sec_error::_SEC_E_UNKNOWN_CREDENTIALS:
                return format_to(ctx.out(), "SEC_E_UNKNOWN_CREDENTIALS");

            case sec_error::_SEC_E_NO_CREDENTIALS:
                return format_to(ctx.out(), "SEC_E_NO_CREDENTIALS");

            case sec_error::_SEC_E_MESSAGE_ALTERED:
                return format_to(ctx.out(), "SEC_E_MESSAGE_ALTERED");

            case sec_error::_SEC_E_OUT_OF_SEQUENCE:
                return format_to(ctx.out(), "SEC_E_OUT_OF_SEQUENCE");

            case sec_error::_SEC_E_NO_AUTHENTICATING_AUTHORITY:
                return format_to(ctx.out(), "SEC_E_NO_AUTHENTICATING_AUTHORITY");

            case sec_error::_SEC_I_CONTINUE_NEEDED:
                return format_to(ctx.out(), "SEC_I_CONTINUE_NEEDED");

            case sec_error::_SEC_I_COMPLETE_NEEDED:
                return format_to(ctx.out(), "SEC_I_COMPLETE_NEEDED");

            case sec_error::_SEC_I_COMPLETE_AND_CONTINUE:
                return format_to(ctx.out(), "SEC_I_COMPLETE_AND_CONTINUE");

            case sec_error::_SEC_I_LOCAL_LOGON:
                return format_to(ctx.out(), "SEC_I_LOCAL_LOGON");

            case sec_error::_SEC_I_GENERIC_EXTENSION_RECEIVED:
                return format_to(ctx.out(), "SEC_I_GENERIC_EXTENSION_RECEIVED");

            case sec_error::_SEC_E_BAD_PKGID:
                return format_to(ctx.out(), "SEC_E_BAD_PKGID");

            case sec_error::_SEC_E_CONTEXT_EXPIRED:
                return format_to(ctx.out(), "SEC_E_CONTEXT_EXPIRED");

            case sec_error::_SEC_I_CONTEXT_EXPIRED:
                return format_to(ctx.out(), "SEC_I_CONTEXT_EXPIRED");

            case sec_error::_SEC_E_INCOMPLETE_MESSAGE:
                return format_to(ctx.out(), "SEC_E_INCOMPLETE_MESSAGE");

            case sec_error::_SEC_E_INCOMPLETE_CREDENTIALS:
                return format_to(ctx.out(), "SEC_E_INCOMPLETE_CREDENTIALS");

            case sec_error::_SEC_E_BUFFER_TOO_SMALL:
                return format_to(ctx.out(), "SEC_E_BUFFER_TOO_SMALL");

            case sec_error::_SEC_I_INCOMPLETE_CREDENTIALS:
                return format_to(ctx.out(), "SEC_I_INCOMPLETE_CREDENTIALS");

            case sec_error::_SEC_I_RENEGOTIATE:
                return format_to(ctx.out(), "SEC_I_RENEGOTIATE");

            case sec_error::_SEC_E_WRONG_PRINCIPAL:
                return format_to(ctx.out(), "SEC_E_WRONG_PRINCIPAL");

            case sec_error::_SEC_I_NO_LSA_CONTEXT:
                return format_to(ctx.out(), "SEC_I_NO_LSA_CONTEXT");

            case sec_error::_SEC_E_TIME_SKEW:
                return format_to(ctx.out(), "SEC_E_TIME_SKEW");

            case sec_error::_SEC_E_UNTRUSTED_ROOT:
                return format_to(ctx.out(), "SEC_E_UNTRUSTED_ROOT");

            case sec_error::_SEC_E_ILLEGAL_MESSAGE:
                return format_to(ctx.out(), "SEC_E_ILLEGAL_MESSAGE");

            case sec_error::_SEC_E_CERT_UNKNOWN:
                return format_to(ctx.out(), "SEC_E_CERT_UNKNOWN");

            case sec_error::_SEC_E_CERT_EXPIRED:
                return format_to(ctx.out(), "SEC_E_CERT_EXPIRED");

            case sec_error::_SEC_E_ENCRYPT_FAILURE:
                return format_to(ctx.out(), "SEC_E_ENCRYPT_FAILURE");

            case sec_error::_SEC_E_DECRYPT_FAILURE:
                return format_to(ctx.out(), "SEC_E_DECRYPT_FAILURE");

            case sec_error::_SEC_E_ALGORITHM_MISMATCH:
                return format_to(ctx.out(), "SEC_E_ALGORITHM_MISMATCH");

            case sec_error::_SEC_E_SECURITY_QOS_FAILED:
                return format_to(ctx.out(), "SEC_E_SECURITY_QOS_FAILED");

            case sec_error::_SEC_E_UNFINISHED_CONTEXT_DELETED:
                return format_to(ctx.out(), "SEC_E_UNFINISHED_CONTEXT_DELETED");

            case sec_error::_SEC_E_NO_TGT_REPLY:
                return format_to(ctx.out(), "SEC_E_NO_TGT_REPLY");

            case sec_error::_SEC_E_NO_IP_ADDRESSES:
                return format_to(ctx.out(), "SEC_E_NO_IP_ADDRESSES");

            case sec_error::_SEC_E_WRONG_CREDENTIAL_HANDLE:
                return format_to(ctx.out(), "SEC_E_WRONG_CREDENTIAL_HANDLE");

            case sec_error::_SEC_E_CRYPTO_SYSTEM_INVALID:
                return format_to(ctx.out(), "SEC_E_CRYPTO_SYSTEM_INVALID");

            case sec_error::_SEC_E_MAX_REFERRALS_EXCEEDED:
                return format_to(ctx.out(), "SEC_E_MAX_REFERRALS_EXCEEDED");

            case sec_error::_SEC_E_MUST_BE_KDC:
                return format_to(ctx.out(), "SEC_E_MUST_BE_KDC");

            case sec_error::_SEC_E_STRONG_CRYPTO_NOT_SUPPORTED:
                return format_to(ctx.out(), "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED");

            case sec_error::_SEC_E_TOO_MANY_PRINCIPALS:
                return format_to(ctx.out(), "SEC_E_TOO_MANY_PRINCIPALS");

            case sec_error::_SEC_E_NO_PA_DATA:
                return format_to(ctx.out(), "SEC_E_NO_PA_DATA");

            case sec_error::_SEC_E_PKINIT_NAME_MISMATCH:
                return format_to(ctx.out(), "SEC_E_PKINIT_NAME_MISMATCH");

            case sec_error::_SEC_E_SMARTCARD_LOGON_REQUIRED:
                return format_to(ctx.out(), "SEC_E_SMARTCARD_LOGON_REQUIRED");

            case sec_error::_SEC_E_SHUTDOWN_IN_PROGRESS:
                return format_to(ctx.out(), "SEC_E_SHUTDOWN_IN_PROGRESS");

            case sec_error::_SEC_E_KDC_INVALID_REQUEST:
                return format_to(ctx.out(), "SEC_E_KDC_INVALID_REQUEST");

            case sec_error::_SEC_E_KDC_UNABLE_TO_REFER:
                return format_to(ctx.out(), "SEC_E_KDC_UNABLE_TO_REFER");

            case sec_error::_SEC_E_KDC_UNKNOWN_ETYPE:
                return format_to(ctx.out(), "SEC_E_KDC_UNKNOWN_ETYPE");

            case sec_error::_SEC_E_UNSUPPORTED_PREAUTH:
                return format_to(ctx.out(), "SEC_E_UNSUPPORTED_PREAUTH");

            case sec_error::_SEC_E_DELEGATION_REQUIRED:
                return format_to(ctx.out(), "SEC_E_DELEGATION_REQUIRED");

            case sec_error::_SEC_E_BAD_BINDINGS:
                return format_to(ctx.out(), "SEC_E_BAD_BINDINGS");

            case sec_error::_SEC_E_MULTIPLE_ACCOUNTS:
                return format_to(ctx.out(), "SEC_E_MULTIPLE_ACCOUNTS");

            case sec_error::_SEC_E_NO_KERB_KEY:
                return format_to(ctx.out(), "SEC_E_NO_KERB_KEY");

            case sec_error::_SEC_E_CERT_WRONG_USAGE:
                return format_to(ctx.out(), "SEC_E_CERT_WRONG_USAGE");

            case sec_error::_SEC_E_DOWNGRADE_DETECTED:
                return format_to(ctx.out(), "SEC_E_DOWNGRADE_DETECTED");

            case sec_error::_SEC_E_SMARTCARD_CERT_REVOKED:
                return format_to(ctx.out(), "SEC_E_SMARTCARD_CERT_REVOKED");

            case sec_error::_SEC_E_ISSUING_CA_UNTRUSTED:
                return format_to(ctx.out(), "SEC_E_ISSUING_CA_UNTRUSTED");

            case sec_error::_SEC_E_REVOCATION_OFFLINE_C:
                return format_to(ctx.out(), "SEC_E_REVOCATION_OFFLINE_C");

            case sec_error::_SEC_E_PKINIT_CLIENT_FAILURE:
                return format_to(ctx.out(), "SEC_E_PKINIT_CLIENT_FAILURE");

            case sec_error::_SEC_E_SMARTCARD_CERT_EXPIRED:
                return format_to(ctx.out(), "SEC_E_SMARTCARD_CERT_EXPIRED");

            case sec_error::_SEC_E_NO_S4U_PROT_SUPPORT:
                return format_to(ctx.out(), "SEC_E_NO_S4U_PROT_SUPPORT");

            case sec_error::_SEC_E_CROSSREALM_DELEGATION_FAILURE:
                return format_to(ctx.out(), "SEC_E_CROSSREALM_DELEGATION_FAILURE");

            case sec_error::_SEC_E_REVOCATION_OFFLINE_KDC:
                return format_to(ctx.out(), "SEC_E_REVOCATION_OFFLINE_KDC");

            case sec_error::_SEC_E_ISSUING_CA_UNTRUSTED_KDC:
                return format_to(ctx.out(), "SEC_E_ISSUING_CA_UNTRUSTED_KDC");

            case sec_error::_SEC_E_KDC_CERT_EXPIRED:
                return format_to(ctx.out(), "SEC_E_KDC_CERT_EXPIRED");

            case sec_error::_SEC_E_KDC_CERT_REVOKED:
                return format_to(ctx.out(), "SEC_E_KDC_CERT_REVOKED");

            case sec_error::_SEC_I_SIGNATURE_NEEDED:
                return format_to(ctx.out(), "SEC_I_SIGNATURE_NEEDED");

            case sec_error::_SEC_E_INVALID_PARAMETER:
                return format_to(ctx.out(), "SEC_E_INVALID_PARAMETER");

            case sec_error::_SEC_E_DELEGATION_POLICY:
                return format_to(ctx.out(), "SEC_E_DELEGATION_POLICY");

            case sec_error::_SEC_E_POLICY_NLTM_ONLY:
                return format_to(ctx.out(), "SEC_E_POLICY_NLTM_ONLY");

            case sec_error::_SEC_I_NO_RENEGOTIATION:
                return format_to(ctx.out(), "SEC_I_NO_RENEGOTIATION");

            case sec_error::_SEC_E_NO_CONTEXT:
                return format_to(ctx.out(), "SEC_E_NO_CONTEXT");

            case sec_error::_SEC_E_PKU2U_CERT_FAILURE:
                return format_to(ctx.out(), "SEC_E_PKU2U_CERT_FAILURE");

            case sec_error::_SEC_E_MUTUAL_AUTH_FAILED:
                return format_to(ctx.out(), "SEC_E_MUTUAL_AUTH_FAILED");

            case sec_error::_SEC_I_MESSAGE_FRAGMENT:
                return format_to(ctx.out(), "SEC_I_MESSAGE_FRAGMENT");

            case sec_error::_SEC_E_ONLY_HTTPS_ALLOWED:
                return format_to(ctx.out(), "SEC_E_ONLY_HTTPS_ALLOWED");

            case sec_error::_SEC_I_CONTINUE_NEEDED_MESSAGE_OK:
                return format_to(ctx.out(), "SEC_I_CONTINUE_NEEDED_MESSAGE_OK");

            case sec_error::_SEC_E_APPLICATION_PROTOCOL_MISMATCH:
                return format_to(ctx.out(), "SEC_E_APPLICATION_PROTOCOL_MISMATCH");

            case sec_error::_SEC_I_ASYNC_CALL_PENDING:
                return format_to(ctx.out(), "SEC_I_ASYNC_CALL_PENDING");

            case sec_error::_SEC_E_INVALID_UPN_NAME:
                return format_to(ctx.out(), "SEC_E_INVALID_UPN_NAME");

            case sec_error::_SEC_E_EXT_BUFFER_TOO_SMALL:
                return format_to(ctx.out(), "SEC_E_EXT_BUFFER_TOO_SMALL");

            case sec_error::_SEC_E_INSUFFICIENT_BUFFERS:
                return format_to(ctx.out(), "SEC_E_INSUFFICIENT_BUFFERS");

            default:
                return format_to(ctx.out(), "{:08x}", (uint32_t)t);
        }
    }
};
#elif defined(HAVE_GSSAPI)
template<>
struct fmt::formatter<enum krb5_minor> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum krb5_minor t, format_context& ctx) {
        switch (t) {
            case krb5_minor::KRB5KDC_ERR_NONE:
                return format_to(ctx.out(), "KRB5KDC_ERR_NONE");

            case krb5_minor::KRB5KDC_ERR_NAME_EXP:
                return format_to(ctx.out(), "KRB5KDC_ERR_NAME_EXP");

            case krb5_minor::KRB5KDC_ERR_SERVICE_EXP:
                return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_EXP");

            case krb5_minor::KRB5KDC_ERR_BAD_PVNO:
                return format_to(ctx.out(), "KRB5KDC_ERR_BAD_PVNO");

            case krb5_minor::KRB5KDC_ERR_C_OLD_MAST_KVNO:
                return format_to(ctx.out(), "KRB5KDC_ERR_C_OLD_MAST_KVNO");

            case krb5_minor::KRB5KDC_ERR_S_OLD_MAST_KVNO:
                return format_to(ctx.out(), "KRB5KDC_ERR_S_OLD_MAST_KVNO");

            case krb5_minor::KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
                return format_to(ctx.out(), "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN");

            case krb5_minor::KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
                return format_to(ctx.out(), "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN");

            case krb5_minor::KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:
                return format_to(ctx.out(), "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE");

            case krb5_minor::KRB5KDC_ERR_NULL_KEY:
                return format_to(ctx.out(), "KRB5KDC_ERR_NULL_KEY");

            case krb5_minor::KRB5KDC_ERR_CANNOT_POSTDATE:
                return format_to(ctx.out(), "KRB5KDC_ERR_CANNOT_POSTDATE");

            case krb5_minor::KRB5KDC_ERR_NEVER_VALID:
                return format_to(ctx.out(), "KRB5KDC_ERR_NEVER_VALID");

            case krb5_minor::KRB5KDC_ERR_POLICY:
                return format_to(ctx.out(), "KRB5KDC_ERR_POLICY");

            case krb5_minor::KRB5KDC_ERR_BADOPTION:
                return format_to(ctx.out(), "KRB5KDC_ERR_BADOPTION");

            case krb5_minor::KRB5KDC_ERR_ETYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5KDC_ERR_ETYPE_NOSUPP");

            case krb5_minor::KRB5KDC_ERR_SUMTYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5KDC_ERR_SUMTYPE_NOSUPP");

            case krb5_minor::KRB5KDC_ERR_PADATA_TYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5KDC_ERR_PADATA_TYPE_NOSUPP");

            case krb5_minor::KRB5KDC_ERR_TRTYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5KDC_ERR_TRTYPE_NOSUPP");

            case krb5_minor::KRB5KDC_ERR_CLIENT_REVOKED:
                return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_REVOKED");

            case krb5_minor::KRB5KDC_ERR_SERVICE_REVOKED:
                return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_REVOKED");

            case krb5_minor::KRB5KDC_ERR_TGT_REVOKED:
                return format_to(ctx.out(), "KRB5KDC_ERR_TGT_REVOKED");

            case krb5_minor::KRB5KDC_ERR_CLIENT_NOTYET:
                return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOTYET");

            case krb5_minor::KRB5KDC_ERR_SERVICE_NOTYET:
                return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_NOTYET");

            case krb5_minor::KRB5KDC_ERR_KEY_EXP:
                return format_to(ctx.out(), "KRB5KDC_ERR_KEY_EXP");

            case krb5_minor::KRB5KDC_ERR_PREAUTH_FAILED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_FAILED");

            case krb5_minor::KRB5KDC_ERR_PREAUTH_REQUIRED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_REQUIRED");

            case krb5_minor::KRB5KDC_ERR_SERVER_NOMATCH:
                return format_to(ctx.out(), "KRB5KDC_ERR_SERVER_NOMATCH");

            case krb5_minor::KRB5KDC_ERR_MUST_USE_USER2USER:
                return format_to(ctx.out(), "KRB5KDC_ERR_MUST_USE_USER2USER");

            case krb5_minor::KRB5KDC_ERR_PATH_NOT_ACCEPTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PATH_NOT_ACCEPTED");

            case krb5_minor::KRB5KDC_ERR_SVC_UNAVAILABLE:
                return format_to(ctx.out(), "KRB5KDC_ERR_SVC_UNAVAILABLE");

            case krb5_minor::KRB5PLACEHOLD_30:
                return format_to(ctx.out(), "KRB5PLACEHOLD_30");

            case krb5_minor::KRB5KRB_AP_ERR_BAD_INTEGRITY:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BAD_INTEGRITY");

            case krb5_minor::KRB5KRB_AP_ERR_TKT_EXPIRED:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_EXPIRED");

            case krb5_minor::KRB5KRB_AP_ERR_TKT_NYV:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_NYV");

            case krb5_minor::KRB5KRB_AP_ERR_REPEAT:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_REPEAT");

            case krb5_minor::KRB5KRB_AP_ERR_NOT_US:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_NOT_US");

            case krb5_minor::KRB5KRB_AP_ERR_BADMATCH:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADMATCH");

            case krb5_minor::KRB5KRB_AP_ERR_SKEW:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_SKEW");

            case krb5_minor::KRB5KRB_AP_ERR_BADADDR:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADADDR");

            case krb5_minor::KRB5KRB_AP_ERR_BADVERSION:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADVERSION");

            case krb5_minor::KRB5KRB_AP_ERR_MSG_TYPE:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_MSG_TYPE");

            case krb5_minor::KRB5KRB_AP_ERR_MODIFIED:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_MODIFIED");

            case krb5_minor::KRB5KRB_AP_ERR_BADORDER:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADORDER");

            case krb5_minor::KRB5KRB_AP_ERR_ILL_CR_TKT:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_ILL_CR_TKT");

            case krb5_minor::KRB5KRB_AP_ERR_BADKEYVER:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADKEYVER");

            case krb5_minor::KRB5KRB_AP_ERR_NOKEY:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_NOKEY");

            case krb5_minor::KRB5KRB_AP_ERR_MUT_FAIL:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_MUT_FAIL");

            case krb5_minor::KRB5KRB_AP_ERR_BADDIRECTION:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADDIRECTION");

            case krb5_minor::KRB5KRB_AP_ERR_METHOD:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_METHOD");

            case krb5_minor::KRB5KRB_AP_ERR_BADSEQ:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADSEQ");

            case krb5_minor::KRB5KRB_AP_ERR_INAPP_CKSUM:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_INAPP_CKSUM");

            case krb5_minor::KRB5KRB_AP_PATH_NOT_ACCEPTED:
                return format_to(ctx.out(), "KRB5KRB_AP_PATH_NOT_ACCEPTED");

            case krb5_minor::KRB5KRB_ERR_RESPONSE_TOO_BIG:
                return format_to(ctx.out(), "KRB5KRB_ERR_RESPONSE_TOO_BIG");

            case krb5_minor::KRB5PLACEHOLD_53:
                return format_to(ctx.out(), "KRB5PLACEHOLD_53");

            case krb5_minor::KRB5PLACEHOLD_54:
                return format_to(ctx.out(), "KRB5PLACEHOLD_54");

            case krb5_minor::KRB5PLACEHOLD_55:
                return format_to(ctx.out(), "KRB5PLACEHOLD_55");

            case krb5_minor::KRB5PLACEHOLD_56:
                return format_to(ctx.out(), "KRB5PLACEHOLD_56");

            case krb5_minor::KRB5PLACEHOLD_57:
                return format_to(ctx.out(), "KRB5PLACEHOLD_57");

            case krb5_minor::KRB5PLACEHOLD_58:
                return format_to(ctx.out(), "KRB5PLACEHOLD_58");

            case krb5_minor::KRB5PLACEHOLD_59:
                return format_to(ctx.out(), "KRB5PLACEHOLD_59");

            case krb5_minor::KRB5KRB_ERR_GENERIC:
                return format_to(ctx.out(), "KRB5KRB_ERR_GENERIC");

            case krb5_minor::KRB5KRB_ERR_FIELD_TOOLONG:
                return format_to(ctx.out(), "KRB5KRB_ERR_FIELD_TOOLONG");

            case krb5_minor::KRB5KDC_ERR_CLIENT_NOT_TRUSTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOT_TRUSTED");

            case krb5_minor::KRB5KDC_ERR_KDC_NOT_TRUSTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_KDC_NOT_TRUSTED");

            case krb5_minor::KRB5KDC_ERR_INVALID_SIG:
                return format_to(ctx.out(), "KRB5KDC_ERR_INVALID_SIG");

            case krb5_minor::KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED");

            case krb5_minor::KRB5KDC_ERR_CERTIFICATE_MISMATCH:
                return format_to(ctx.out(), "KRB5KDC_ERR_CERTIFICATE_MISMATCH");

            case krb5_minor::KRB5KRB_AP_ERR_NO_TGT:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_NO_TGT");

            case krb5_minor::KRB5KDC_ERR_WRONG_REALM:
                return format_to(ctx.out(), "KRB5KDC_ERR_WRONG_REALM");

            case krb5_minor::KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED");

            case krb5_minor::KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE:
                return format_to(ctx.out(), "KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE");

            case krb5_minor::KRB5KDC_ERR_INVALID_CERTIFICATE:
                return format_to(ctx.out(), "KRB5KDC_ERR_INVALID_CERTIFICATE");

            case krb5_minor::KRB5KDC_ERR_REVOKED_CERTIFICATE:
                return format_to(ctx.out(), "KRB5KDC_ERR_REVOKED_CERTIFICATE");

            case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN:
                return format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN");

            case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:
                return format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE");

            case krb5_minor::KRB5KDC_ERR_CLIENT_NAME_MISMATCH:
                return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NAME_MISMATCH");

            case krb5_minor::KRB5KDC_ERR_KDC_NAME_MISMATCH:
                return format_to(ctx.out(), "KRB5KDC_ERR_KDC_NAME_MISMATCH");

            case krb5_minor::KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE:
                return format_to(ctx.out(), "KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE");

            case krb5_minor::KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED");

            case krb5_minor::KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED");

            case krb5_minor::KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED");

            case krb5_minor::KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED");

            case krb5_minor::KRB5PLACEHOLD_82:
                return format_to(ctx.out(), "KRB5PLACEHOLD_82");

            case krb5_minor::KRB5PLACEHOLD_83:
                return format_to(ctx.out(), "KRB5PLACEHOLD_83");

            case krb5_minor::KRB5PLACEHOLD_84:
                return format_to(ctx.out(), "KRB5PLACEHOLD_84");

            case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND");

            case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE");

            case krb5_minor::KRB5PLACEHOLD_87:
                return format_to(ctx.out(), "KRB5PLACEHOLD_87");

            case krb5_minor::KRB5PLACEHOLD_88:
                return format_to(ctx.out(), "KRB5PLACEHOLD_88");

            case krb5_minor::KRB5PLACEHOLD_89:
                return format_to(ctx.out(), "KRB5PLACEHOLD_89");

            case krb5_minor::KRB5KDC_ERR_PREAUTH_EXPIRED:
                return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_EXPIRED");

            case krb5_minor::KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED:
                return format_to(ctx.out(), "KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED");

            case krb5_minor::KRB5PLACEHOLD_92:
                return format_to(ctx.out(), "KRB5PLACEHOLD_92");

            case krb5_minor::KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION:
                return format_to(ctx.out(), "KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION");

            case krb5_minor::KRB5PLACEHOLD_94:
                return format_to(ctx.out(), "KRB5PLACEHOLD_94");

            case krb5_minor::KRB5PLACEHOLD_95:
                return format_to(ctx.out(), "KRB5PLACEHOLD_95");

            case krb5_minor::KRB5PLACEHOLD_96:
                return format_to(ctx.out(), "KRB5PLACEHOLD_96");

            case krb5_minor::KRB5PLACEHOLD_97:
                return format_to(ctx.out(), "KRB5PLACEHOLD_97");

            case krb5_minor::KRB5PLACEHOLD_98:
                return format_to(ctx.out(), "KRB5PLACEHOLD_98");

            case krb5_minor::KRB5PLACEHOLD_99:
                return format_to(ctx.out(), "KRB5PLACEHOLD_99");

            case krb5_minor::KRB5KDC_ERR_NO_ACCEPTABLE_KDF:
                return format_to(ctx.out(), "KRB5KDC_ERR_NO_ACCEPTABLE_KDF");

            case krb5_minor::KRB5PLACEHOLD_101:
                return format_to(ctx.out(), "KRB5PLACEHOLD_101");

            case krb5_minor::KRB5PLACEHOLD_102:
                return format_to(ctx.out(), "KRB5PLACEHOLD_102");

            case krb5_minor::KRB5PLACEHOLD_103:
                return format_to(ctx.out(), "KRB5PLACEHOLD_103");

            case krb5_minor::KRB5PLACEHOLD_104:
                return format_to(ctx.out(), "KRB5PLACEHOLD_104");

            case krb5_minor::KRB5PLACEHOLD_105:
                return format_to(ctx.out(), "KRB5PLACEHOLD_105");

            case krb5_minor::KRB5PLACEHOLD_106:
                return format_to(ctx.out(), "KRB5PLACEHOLD_106");

            case krb5_minor::KRB5PLACEHOLD_107:
                return format_to(ctx.out(), "KRB5PLACEHOLD_107");

            case krb5_minor::KRB5PLACEHOLD_108:
                return format_to(ctx.out(), "KRB5PLACEHOLD_108");

            case krb5_minor::KRB5PLACEHOLD_109:
                return format_to(ctx.out(), "KRB5PLACEHOLD_109");

            case krb5_minor::KRB5PLACEHOLD_110:
                return format_to(ctx.out(), "KRB5PLACEHOLD_110");

            case krb5_minor::KRB5PLACEHOLD_111:
                return format_to(ctx.out(), "KRB5PLACEHOLD_111");

            case krb5_minor::KRB5PLACEHOLD_112:
                return format_to(ctx.out(), "KRB5PLACEHOLD_112");

            case krb5_minor::KRB5PLACEHOLD_113:
                return format_to(ctx.out(), "KRB5PLACEHOLD_113");

            case krb5_minor::KRB5PLACEHOLD_114:
                return format_to(ctx.out(), "KRB5PLACEHOLD_114");

            case krb5_minor::KRB5PLACEHOLD_115:
                return format_to(ctx.out(), "KRB5PLACEHOLD_115");

            case krb5_minor::KRB5PLACEHOLD_116:
                return format_to(ctx.out(), "KRB5PLACEHOLD_116");

            case krb5_minor::KRB5PLACEHOLD_117:
                return format_to(ctx.out(), "KRB5PLACEHOLD_117");

            case krb5_minor::KRB5PLACEHOLD_118:
                return format_to(ctx.out(), "KRB5PLACEHOLD_118");

            case krb5_minor::KRB5PLACEHOLD_119:
                return format_to(ctx.out(), "KRB5PLACEHOLD_119");

            case krb5_minor::KRB5PLACEHOLD_120:
                return format_to(ctx.out(), "KRB5PLACEHOLD_120");

            case krb5_minor::KRB5PLACEHOLD_121:
                return format_to(ctx.out(), "KRB5PLACEHOLD_121");

            case krb5_minor::KRB5PLACEHOLD_122:
                return format_to(ctx.out(), "KRB5PLACEHOLD_122");

            case krb5_minor::KRB5PLACEHOLD_123:
                return format_to(ctx.out(), "KRB5PLACEHOLD_123");

            case krb5_minor::KRB5PLACEHOLD_124:
                return format_to(ctx.out(), "KRB5PLACEHOLD_124");

            case krb5_minor::KRB5PLACEHOLD_125:
                return format_to(ctx.out(), "KRB5PLACEHOLD_125");

            case krb5_minor::KRB5PLACEHOLD_126:
                return format_to(ctx.out(), "KRB5PLACEHOLD_126");

            case krb5_minor::KRB5PLACEHOLD_127:
                return format_to(ctx.out(), "KRB5PLACEHOLD_127");

            case krb5_minor::KRB5_ERR_RCSID:
                return format_to(ctx.out(), "KRB5_ERR_RCSID");

            case krb5_minor::KRB5_LIBOS_BADLOCKFLAG:
                return format_to(ctx.out(), "KRB5_LIBOS_BADLOCKFLAG");

            case krb5_minor::KRB5_LIBOS_CANTREADPWD:
                return format_to(ctx.out(), "KRB5_LIBOS_CANTREADPWD");

            case krb5_minor::KRB5_LIBOS_BADPWDMATCH:
                return format_to(ctx.out(), "KRB5_LIBOS_BADPWDMATCH");

            case krb5_minor::KRB5_LIBOS_PWDINTR:
                return format_to(ctx.out(), "KRB5_LIBOS_PWDINTR");

            case krb5_minor::KRB5_PARSE_ILLCHAR:
                return format_to(ctx.out(), "KRB5_PARSE_ILLCHAR");

            case krb5_minor::KRB5_PARSE_MALFORMED:
                return format_to(ctx.out(), "KRB5_PARSE_MALFORMED");

            case krb5_minor::KRB5_CONFIG_CANTOPEN:
                return format_to(ctx.out(), "KRB5_CONFIG_CANTOPEN");

            case krb5_minor::KRB5_CONFIG_BADFORMAT:
                return format_to(ctx.out(), "KRB5_CONFIG_BADFORMAT");

            case krb5_minor::KRB5_CONFIG_NOTENUFSPACE:
                return format_to(ctx.out(), "KRB5_CONFIG_NOTENUFSPACE");

            case krb5_minor::KRB5_BADMSGTYPE:
                return format_to(ctx.out(), "KRB5_BADMSGTYPE");

            case krb5_minor::KRB5_CC_BADNAME:
                return format_to(ctx.out(), "KRB5_CC_BADNAME");

            case krb5_minor::KRB5_CC_UNKNOWN_TYPE:
                return format_to(ctx.out(), "KRB5_CC_UNKNOWN_TYPE");

            case krb5_minor::KRB5_CC_NOTFOUND:
                return format_to(ctx.out(), "KRB5_CC_NOTFOUND");

            case krb5_minor::KRB5_CC_END:
                return format_to(ctx.out(), "KRB5_CC_END");

            case krb5_minor::KRB5_NO_TKT_SUPPLIED:
                return format_to(ctx.out(), "KRB5_NO_TKT_SUPPLIED");

            case krb5_minor::KRB5KRB_AP_WRONG_PRINC:
                return format_to(ctx.out(), "KRB5KRB_AP_WRONG_PRINC");

            case krb5_minor::KRB5KRB_AP_ERR_TKT_INVALID:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_INVALID");

            case krb5_minor::KRB5_PRINC_NOMATCH:
                return format_to(ctx.out(), "KRB5_PRINC_NOMATCH");

            case krb5_minor::KRB5_KDCREP_MODIFIED:
                return format_to(ctx.out(), "KRB5_KDCREP_MODIFIED");

            case krb5_minor::KRB5_KDCREP_SKEW:
                return format_to(ctx.out(), "KRB5_KDCREP_SKEW");

            case krb5_minor::KRB5_IN_TKT_REALM_MISMATCH:
                return format_to(ctx.out(), "KRB5_IN_TKT_REALM_MISMATCH");

            case krb5_minor::KRB5_PROG_ETYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5_PROG_ETYPE_NOSUPP");

            case krb5_minor::KRB5_PROG_KEYTYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5_PROG_KEYTYPE_NOSUPP");

            case krb5_minor::KRB5_WRONG_ETYPE:
                return format_to(ctx.out(), "KRB5_WRONG_ETYPE");

            case krb5_minor::KRB5_PROG_SUMTYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5_PROG_SUMTYPE_NOSUPP");

            case krb5_minor::KRB5_REALM_UNKNOWN:
                return format_to(ctx.out(), "KRB5_REALM_UNKNOWN");

            case krb5_minor::KRB5_SERVICE_UNKNOWN:
                return format_to(ctx.out(), "KRB5_SERVICE_UNKNOWN");

            case krb5_minor::KRB5_KDC_UNREACH:
                return format_to(ctx.out(), "KRB5_KDC_UNREACH");

            case krb5_minor::KRB5_NO_LOCALNAME:
                return format_to(ctx.out(), "KRB5_NO_LOCALNAME");

            case krb5_minor::KRB5_MUTUAL_FAILED:
                return format_to(ctx.out(), "KRB5_MUTUAL_FAILED");

            case krb5_minor::KRB5_RC_TYPE_EXISTS:
                return format_to(ctx.out(), "KRB5_RC_TYPE_EXISTS");

            case krb5_minor::KRB5_RC_MALLOC:
                return format_to(ctx.out(), "KRB5_RC_MALLOC");

            case krb5_minor::KRB5_RC_TYPE_NOTFOUND:
                return format_to(ctx.out(), "KRB5_RC_TYPE_NOTFOUND");

            case krb5_minor::KRB5_RC_UNKNOWN:
                return format_to(ctx.out(), "KRB5_RC_UNKNOWN");

            case krb5_minor::KRB5_RC_REPLAY:
                return format_to(ctx.out(), "KRB5_RC_REPLAY");

            case krb5_minor::KRB5_RC_IO:
                return format_to(ctx.out(), "KRB5_RC_IO");

            case krb5_minor::KRB5_RC_NOIO:
                return format_to(ctx.out(), "KRB5_RC_NOIO");

            case krb5_minor::KRB5_RC_PARSE:
                return format_to(ctx.out(), "KRB5_RC_PARSE");

            case krb5_minor::KRB5_RC_IO_EOF:
                return format_to(ctx.out(), "KRB5_RC_IO_EOF");

            case krb5_minor::KRB5_RC_IO_MALLOC:
                return format_to(ctx.out(), "KRB5_RC_IO_MALLOC");

            case krb5_minor::KRB5_RC_IO_PERM:
                return format_to(ctx.out(), "KRB5_RC_IO_PERM");

            case krb5_minor::KRB5_RC_IO_IO:
                return format_to(ctx.out(), "KRB5_RC_IO_IO");

            case krb5_minor::KRB5_RC_IO_UNKNOWN:
                return format_to(ctx.out(), "KRB5_RC_IO_UNKNOWN");

            case krb5_minor::KRB5_RC_IO_SPACE:
                return format_to(ctx.out(), "KRB5_RC_IO_SPACE");

            case krb5_minor::KRB5_TRANS_CANTOPEN:
                return format_to(ctx.out(), "KRB5_TRANS_CANTOPEN");

            case krb5_minor::KRB5_TRANS_BADFORMAT:
                return format_to(ctx.out(), "KRB5_TRANS_BADFORMAT");

            case krb5_minor::KRB5_LNAME_CANTOPEN:
                return format_to(ctx.out(), "KRB5_LNAME_CANTOPEN");

            case krb5_minor::KRB5_LNAME_NOTRANS:
                return format_to(ctx.out(), "KRB5_LNAME_NOTRANS");

            case krb5_minor::KRB5_LNAME_BADFORMAT:
                return format_to(ctx.out(), "KRB5_LNAME_BADFORMAT");

            case krb5_minor::KRB5_CRYPTO_INTERNAL:
                return format_to(ctx.out(), "KRB5_CRYPTO_INTERNAL");

            case krb5_minor::KRB5_KT_BADNAME:
                return format_to(ctx.out(), "KRB5_KT_BADNAME");

            case krb5_minor::KRB5_KT_UNKNOWN_TYPE:
                return format_to(ctx.out(), "KRB5_KT_UNKNOWN_TYPE");

            case krb5_minor::KRB5_KT_NOTFOUND:
                return format_to(ctx.out(), "KRB5_KT_NOTFOUND");

            case krb5_minor::KRB5_KT_END:
                return format_to(ctx.out(), "KRB5_KT_END");

            case krb5_minor::KRB5_KT_NOWRITE:
                return format_to(ctx.out(), "KRB5_KT_NOWRITE");

            case krb5_minor::KRB5_KT_IOERR:
                return format_to(ctx.out(), "KRB5_KT_IOERR");

            case krb5_minor::KRB5_NO_TKT_IN_RLM:
                return format_to(ctx.out(), "KRB5_NO_TKT_IN_RLM");

            case krb5_minor::KRB5DES_BAD_KEYPAR:
                return format_to(ctx.out(), "KRB5DES_BAD_KEYPAR");

            case krb5_minor::KRB5DES_WEAK_KEY:
                return format_to(ctx.out(), "KRB5DES_WEAK_KEY");

            case krb5_minor::KRB5_BAD_ENCTYPE:
                return format_to(ctx.out(), "KRB5_BAD_ENCTYPE");

            case krb5_minor::KRB5_BAD_KEYSIZE:
                return format_to(ctx.out(), "KRB5_BAD_KEYSIZE");

            case krb5_minor::KRB5_BAD_MSIZE:
                return format_to(ctx.out(), "KRB5_BAD_MSIZE");

            case krb5_minor::KRB5_CC_TYPE_EXISTS:
                return format_to(ctx.out(), "KRB5_CC_TYPE_EXISTS");

            case krb5_minor::KRB5_KT_TYPE_EXISTS:
                return format_to(ctx.out(), "KRB5_KT_TYPE_EXISTS");

            case krb5_minor::KRB5_CC_IO:
                return format_to(ctx.out(), "KRB5_CC_IO");

            case krb5_minor::KRB5_FCC_PERM:
                return format_to(ctx.out(), "KRB5_FCC_PERM");

            case krb5_minor::KRB5_FCC_NOFILE:
                return format_to(ctx.out(), "KRB5_FCC_NOFILE");

            case krb5_minor::KRB5_FCC_INTERNAL:
                return format_to(ctx.out(), "KRB5_FCC_INTERNAL");

            case krb5_minor::KRB5_CC_WRITE:
                return format_to(ctx.out(), "KRB5_CC_WRITE");

            case krb5_minor::KRB5_CC_NOMEM:
                return format_to(ctx.out(), "KRB5_CC_NOMEM");

            case krb5_minor::KRB5_CC_FORMAT:
                return format_to(ctx.out(), "KRB5_CC_FORMAT");

            case krb5_minor::KRB5_CC_NOT_KTYPE:
                return format_to(ctx.out(), "KRB5_CC_NOT_KTYPE");

            case krb5_minor::KRB5_INVALID_FLAGS:
                return format_to(ctx.out(), "KRB5_INVALID_FLAGS");

            case krb5_minor::KRB5_NO_2ND_TKT:
                return format_to(ctx.out(), "KRB5_NO_2ND_TKT");

            case krb5_minor::KRB5_NOCREDS_SUPPLIED:
                return format_to(ctx.out(), "KRB5_NOCREDS_SUPPLIED");

            case krb5_minor::KRB5_SENDAUTH_BADAUTHVERS:
                return format_to(ctx.out(), "KRB5_SENDAUTH_BADAUTHVERS");

            case krb5_minor::KRB5_SENDAUTH_BADAPPLVERS:
                return format_to(ctx.out(), "KRB5_SENDAUTH_BADAPPLVERS");

            case krb5_minor::KRB5_SENDAUTH_BADRESPONSE:
                return format_to(ctx.out(), "KRB5_SENDAUTH_BADRESPONSE");

            case krb5_minor::KRB5_SENDAUTH_REJECTED:
                return format_to(ctx.out(), "KRB5_SENDAUTH_REJECTED");

            case krb5_minor::KRB5_PREAUTH_BAD_TYPE:
                return format_to(ctx.out(), "KRB5_PREAUTH_BAD_TYPE");

            case krb5_minor::KRB5_PREAUTH_NO_KEY:
                return format_to(ctx.out(), "KRB5_PREAUTH_NO_KEY");

            case krb5_minor::KRB5_PREAUTH_FAILED:
                return format_to(ctx.out(), "KRB5_PREAUTH_FAILED");

            case krb5_minor::KRB5_RCACHE_BADVNO:
                return format_to(ctx.out(), "KRB5_RCACHE_BADVNO");

            case krb5_minor::KRB5_CCACHE_BADVNO:
                return format_to(ctx.out(), "KRB5_CCACHE_BADVNO");

            case krb5_minor::KRB5_KEYTAB_BADVNO:
                return format_to(ctx.out(), "KRB5_KEYTAB_BADVNO");

            case krb5_minor::KRB5_PROG_ATYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5_PROG_ATYPE_NOSUPP");

            case krb5_minor::KRB5_RC_REQUIRED:
                return format_to(ctx.out(), "KRB5_RC_REQUIRED");

            case krb5_minor::KRB5_ERR_BAD_HOSTNAME:
                return format_to(ctx.out(), "KRB5_ERR_BAD_HOSTNAME");

            case krb5_minor::KRB5_ERR_HOST_REALM_UNKNOWN:
                return format_to(ctx.out(), "KRB5_ERR_HOST_REALM_UNKNOWN");

            case krb5_minor::KRB5_SNAME_UNSUPP_NAMETYPE:
                return format_to(ctx.out(), "KRB5_SNAME_UNSUPP_NAMETYPE");

            case krb5_minor::KRB5KRB_AP_ERR_V4_REPLY:
                return format_to(ctx.out(), "KRB5KRB_AP_ERR_V4_REPLY");

            case krb5_minor::KRB5_REALM_CANT_RESOLVE:
                return format_to(ctx.out(), "KRB5_REALM_CANT_RESOLVE");

            case krb5_minor::KRB5_TKT_NOT_FORWARDABLE:
                return format_to(ctx.out(), "KRB5_TKT_NOT_FORWARDABLE");

            case krb5_minor::KRB5_FWD_BAD_PRINCIPAL:
                return format_to(ctx.out(), "KRB5_FWD_BAD_PRINCIPAL");

            case krb5_minor::KRB5_GET_IN_TKT_LOOP:
                return format_to(ctx.out(), "KRB5_GET_IN_TKT_LOOP");

            case krb5_minor::KRB5_CONFIG_NODEFREALM:
                return format_to(ctx.out(), "KRB5_CONFIG_NODEFREALM");

            case krb5_minor::KRB5_SAM_UNSUPPORTED:
                return format_to(ctx.out(), "KRB5_SAM_UNSUPPORTED");

            case krb5_minor::KRB5_SAM_INVALID_ETYPE:
                return format_to(ctx.out(), "KRB5_SAM_INVALID_ETYPE");

            case krb5_minor::KRB5_SAM_NO_CHECKSUM:
                return format_to(ctx.out(), "KRB5_SAM_NO_CHECKSUM");

            case krb5_minor::KRB5_SAM_BAD_CHECKSUM:
                return format_to(ctx.out(), "KRB5_SAM_BAD_CHECKSUM");

            case krb5_minor::KRB5_KT_NAME_TOOLONG:
                return format_to(ctx.out(), "KRB5_KT_NAME_TOOLONG");

            case krb5_minor::KRB5_KT_KVNONOTFOUND:
                return format_to(ctx.out(), "KRB5_KT_KVNONOTFOUND");

            case krb5_minor::KRB5_APPL_EXPIRED:
                return format_to(ctx.out(), "KRB5_APPL_EXPIRED");

            case krb5_minor::KRB5_LIB_EXPIRED:
                return format_to(ctx.out(), "KRB5_LIB_EXPIRED");

            case krb5_minor::KRB5_CHPW_PWDNULL:
                return format_to(ctx.out(), "KRB5_CHPW_PWDNULL");

            case krb5_minor::KRB5_CHPW_FAIL:
                return format_to(ctx.out(), "KRB5_CHPW_FAIL");

            case krb5_minor::KRB5_KT_FORMAT:
                return format_to(ctx.out(), "KRB5_KT_FORMAT");

            case krb5_minor::KRB5_NOPERM_ETYPE:
                return format_to(ctx.out(), "KRB5_NOPERM_ETYPE");

            case krb5_minor::KRB5_CONFIG_ETYPE_NOSUPP:
                return format_to(ctx.out(), "KRB5_CONFIG_ETYPE_NOSUPP");

            case krb5_minor::KRB5_OBSOLETE_FN:
                return format_to(ctx.out(), "KRB5_OBSOLETE_FN");

            case krb5_minor::KRB5_EAI_FAIL:
                return format_to(ctx.out(), "KRB5_EAI_FAIL");

            case krb5_minor::KRB5_EAI_NODATA:
                return format_to(ctx.out(), "KRB5_EAI_NODATA");

            case krb5_minor::KRB5_EAI_NONAME:
                return format_to(ctx.out(), "KRB5_EAI_NONAME");

            case krb5_minor::KRB5_EAI_SERVICE:
                return format_to(ctx.out(), "KRB5_EAI_SERVICE");

            case krb5_minor::KRB5_ERR_NUMERIC_REALM:
                return format_to(ctx.out(), "KRB5_ERR_NUMERIC_REALM");

            case krb5_minor::KRB5_ERR_BAD_S2K_PARAMS:
                return format_to(ctx.out(), "KRB5_ERR_BAD_S2K_PARAMS");

            case krb5_minor::KRB5_ERR_NO_SERVICE:
                return format_to(ctx.out(), "KRB5_ERR_NO_SERVICE");

            case krb5_minor::KRB5_CC_READONLY:
                return format_to(ctx.out(), "KRB5_CC_READONLY");

            case krb5_minor::KRB5_CC_NOSUPP:
                return format_to(ctx.out(), "KRB5_CC_NOSUPP");

            case krb5_minor::KRB5_DELTAT_BADFORMAT:
                return format_to(ctx.out(), "KRB5_DELTAT_BADFORMAT");

            case krb5_minor::KRB5_PLUGIN_NO_HANDLE:
                return format_to(ctx.out(), "KRB5_PLUGIN_NO_HANDLE");

            case krb5_minor::KRB5_PLUGIN_OP_NOTSUPP:
                return format_to(ctx.out(), "KRB5_PLUGIN_OP_NOTSUPP");

            case krb5_minor::KRB5_ERR_INVALID_UTF8:
                return format_to(ctx.out(), "KRB5_ERR_INVALID_UTF8");

            case krb5_minor::KRB5_ERR_FAST_REQUIRED:
                return format_to(ctx.out(), "KRB5_ERR_FAST_REQUIRED");

            case krb5_minor::KRB5_LOCAL_ADDR_REQUIRED:
                return format_to(ctx.out(), "KRB5_LOCAL_ADDR_REQUIRED");

            case krb5_minor::KRB5_REMOTE_ADDR_REQUIRED:
                return format_to(ctx.out(), "KRB5_REMOTE_ADDR_REQUIRED");

            case krb5_minor::KRB5_TRACE_NOSUPP:
                return format_to(ctx.out(), "KRB5_TRACE_NOSUPP");

            default:
                return format_to(ctx.out(), "{}", (int32_t)t);
        }
    }
};

class gss_error : public exception {
public:
    gss_error(const string& func, OM_uint32 major, OM_uint32 minor) {
        OM_uint32 message_context = 0;
        OM_uint32 min_status;
        gss_buffer_desc status_string;
        bool first = true;

        msg = fmt::format(FMT_STRING("{} failed (minor {}): "), func, (enum krb5_minor)minor);

        do {
            gss_display_status(&min_status, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
                               &message_context, &status_string);

            if (!first)
                msg += "; ";

            msg += string((char*)status_string.value, status_string.length);

            gss_release_buffer(&min_status, &status_string);
            first = false;
        } while (message_context != 0);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};
#endif

static bool is_byte_len_type(enum tds::sql_type type) {
    switch (type) {
        case tds::sql_type::UNIQUEIDENTIFIER:
        case tds::sql_type::INTN:
        case tds::sql_type::DECIMAL:
        case tds::sql_type::NUMERIC:
        case tds::sql_type::BITN:
        case tds::sql_type::FLTN:
        case tds::sql_type::MONEYN:
        case tds::sql_type::DATETIMN:
        case tds::sql_type::DATE:
        case tds::sql_type::TIME:
        case tds::sql_type::DATETIME2:
        case tds::sql_type::DATETIMEOFFSET:
            return true;

        default:
            return false;
    }
}

namespace tds {
    tds::tds(const string& server, const string_view& user, const string_view& password,
             const string_view& app_name, const msg_handler& message_handler,
             const func_count_handler& count_handler, uint16_t port) {
        impl = new tds_impl(server, user, password, app_name, message_handler, count_handler, port);
    }

    tds::~tds() {
        delete impl;
    }

    tds_impl::tds_impl(const string& server, const string_view& user, const string_view& password,
                       const string_view& app_name, const msg_handler& message_handler,
                       const func_count_handler& count_handler, uint16_t port) : message_handler(message_handler), count_handler(count_handler) {
#ifdef _WIN32
        WSADATA wsa_data;

        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
            throw runtime_error("WSAStartup failed.");
#endif

        connect(server, port, user.empty());

        send_prelogin_msg();

        send_login_msg(user, password, server, app_name);
    }

    tds_impl::~tds_impl() {
#ifdef _WIN32
        if (sock != INVALID_SOCKET)
            closesocket(sock);
#else
        if (sock != 0)
            close(sock);
#endif
    }

    void tds_impl::connect(const string& server, uint16_t port, bool get_fqdn) {
        struct addrinfo hints;
        struct addrinfo* res;
        struct addrinfo* orig_res;
        int ret;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        ret = getaddrinfo(server.c_str(), nullptr, &hints, &res);

        if (ret != 0)
            throw formatted_error("getaddrinfo returned {}", ret);

        orig_res = res;
#ifdef _WIN32
        sock = INVALID_SOCKET;
#else
        sock = 0;
#endif

        do {
            char hostname[NI_MAXHOST];

            sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

#ifdef _WIN32
            if (sock == INVALID_SOCKET)
                continue;
#else
            if (sock < 0)
                continue;
#endif

            if (res->ai_family == AF_INET)
                ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(port);
            else if (res->ai_family == AF_INET6)
                ((struct sockaddr_in6*)res->ai_addr)->sin6_port = htons(port);
            else {
#ifdef _WIN32
                closesocket(sock);
                sock = INVALID_SOCKET;
#else
                close(sock);
                sock = 0;
#endif
                continue;
            }

            if (::connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
#ifdef _WIN32
                closesocket(sock);
                sock = INVALID_SOCKET;
#else
                close(sock);
                sock = 0;
#endif
                continue;
            }

            if (get_fqdn) {
                if (getnameinfo(res->ai_addr, (socklen_t)res->ai_addrlen, hostname, sizeof(hostname), nullptr, 0, 0) == 0)
                    fqdn = hostname;
            }

            break;
        } while ((res = res->ai_next));

        freeaddrinfo(orig_res);

#ifdef _WIN32
        if (sock == INVALID_SOCKET)
            throw formatted_error("Could not connect to {}:{}.", server, port);
#else
        if (sock <= 0)
            throw formatted_error("Could not connect to {}:{}.", server, port);
#endif
    }

    void tds_impl::send_prelogin_msg() {
        string msg;
        vector<login_opt> opts;
        login_opt_version lov;
        size_t size, off;
        enum tds_encryption_type enc;
        uint8_t mars;

        // FIXME - allow the user to specify this
        static const char instance[] = "MSSQLServer";

        // version

        lov.major = 9;
        lov.minor = 0;
        lov.build = 0;
        lov.subbuild = 0;

        opts.emplace_back(tds_login_opt_type::version, string_view{(char*)&lov, sizeof(lov)});

        // encryption
        // FIXME - actually support encryption
        // FIXME - handle error message if server insists on encryption

        enc = tds_encryption_type::ENCRYPT_NOT_SUP;

        opts.emplace_back(tds_login_opt_type::encryption, string_view{(char*)&enc, sizeof(enc)});

        // instopt

        // needs trailing zero
        opts.emplace_back(tds_login_opt_type::instopt, string_view{instance, sizeof(instance)});

        // MARS

        mars = 0;
        opts.emplace_back(tds_login_opt_type::mars, string_view{(char*)&mars, sizeof(mars)});

        size = (sizeof(tds_login_opt) * opts.size()) + sizeof(enum tds_login_opt_type);
        off = size;

        for (const auto& opt : opts) {
            size += opt.payload.size();
        }

        msg.resize(size);

        auto tlo = (tds_login_opt*)msg.data();

        for (const auto& opt : opts) {
            tlo->type = opt.type;
            tlo->offset = htons((uint16_t)off);
            tlo->length = htons((uint16_t)opt.payload.size());

            memcpy(msg.data() + off, opt.payload.data(), opt.payload.size());
            off += opt.payload.size();

            tlo++;
        }

        tlo->type = tds_login_opt_type::terminator;

        send_msg(tds_msg::prelogin, msg);

        {
            enum tds_msg type;
            string payload;

            wait_for_msg(type, payload);
            // FIXME - timeout

            if (type != tds_msg::tabular_result)
                throw formatted_error("Received message type {}, expected tabular_result", (int)type);

            // FIXME - parse payload for anything we care about (in particular, what server says about encryption)
        }
    }

#ifdef _WIN32
    class sspi_handle {
    public:
        sspi_handle() {
            SECURITY_STATUS sec_status;
            TimeStamp timestamp;

            sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)L"Negotiate", SECPKG_CRED_OUTBOUND, nullptr,
                                                   nullptr, nullptr, nullptr, &cred_handle, &timestamp);
            if (FAILED(sec_status))
                throw formatted_error("AcquireCredentialsHandle returned {}", (enum sec_error)sec_status);
        }

        ~sspi_handle() {
            if (ctx_handle_set)
                DeleteSecurityContext(&ctx_handle);

            FreeCredentialsHandle(&cred_handle);
        }

        SECURITY_STATUS init_security_context(const char16_t* target_name, uint32_t context_req, uint32_t target_data_rep,
                                              PSecBufferDesc input, PSecBufferDesc output, uint32_t* context_attr,
                                              PTimeStamp timestamp) {
            SECURITY_STATUS sec_status;

            sec_status = InitializeSecurityContextW(&cred_handle, nullptr, (SEC_WCHAR*)target_name, context_req, 0,
                                                    target_data_rep, input, 0, &ctx_handle, output,
                                                    (ULONG*)context_attr, timestamp);

            if (FAILED(sec_status))
                throw formatted_error("InitializeSecurityContext returned {}", (enum sec_error)sec_status);

            ctx_handle_set = true;

            return sec_status;
        }

        CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
        CtxtHandle ctx_handle;
        bool ctx_handle_set = false;
    };
#endif

    static size_t fixed_len_size(enum sql_type type) {
        switch (type) {
            case sql_type::TINYINT:
                return 1;

            case sql_type::SMALLINT:
                return 2;

            case sql_type::INT:
                return 4;

            case sql_type::BIGINT:
                return 8;

            case sql_type::DATETIME:
                return 8;

            case sql_type::DATETIM4:
                return 4;

            case sql_type::SMALLMONEY:
                return 4;

            case sql_type::MONEY:
                return 8;

            case sql_type::REAL:
                return 4;

            case sql_type::FLOAT:
                return 8;

            case sql_type::BIT:
                return 1;

            case sql_type::SQL_NULL:
                return 0;

            default:
                return 0;
        }
    }

    static bool parse_row_col(enum sql_type type, unsigned int max_length, string_view& sv) {
        switch (type) {
            case sql_type::SQL_NULL:
            case sql_type::TINYINT:
            case sql_type::BIT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::DATETIM4:
            case sql_type::REAL:
            case sql_type::MONEY:
            case sql_type::DATETIME:
            case sql_type::FLOAT:
            case sql_type::SMALLMONEY:
            case sql_type::BIGINT:
            {
                auto len = fixed_len_size(type);

                if (sv.length() < len)
                    return false;

                sv = sv.substr(len);

                break;
            }

            case sql_type::UNIQUEIDENTIFIER:
            case sql_type::INTN:
            case sql_type::DECIMAL:
            case sql_type::NUMERIC:
            case sql_type::BITN:
            case sql_type::FLTN:
            case sql_type::MONEYN:
            case sql_type::DATETIMN:
            case sql_type::DATE:
            case sql_type::TIME:
            case sql_type::DATETIME2:
            case sql_type::DATETIMEOFFSET:
            {
                if (sv.length() < sizeof(uint8_t))
                    return false;

                auto len = *(uint8_t*)sv.data();

                sv = sv.substr(1);

                if (sv.length() < len)
                    return false;

                sv = sv.substr(len);

                break;
            }

            case sql_type::VARCHAR:
            case sql_type::NVARCHAR:
            case sql_type::VARBINARY:
            case sql_type::CHAR:
            case sql_type::NCHAR:
            case sql_type::BINARY:
            case sql_type::XML:
                if (max_length == 0xffff || type == sql_type::XML) {
                    if (sv.length() < sizeof(uint64_t))
                        return false;

                    auto len = *(uint64_t*)sv.data();

                    sv = sv.substr(sizeof(uint64_t));

                    if (len == 0xffffffffffffffff)
                        return true;

                    do {
                        if (sv.length() < sizeof(uint32_t))
                            return false;

                        auto chunk_len = *(uint32_t*)sv.data();

                        sv = sv.substr(sizeof(uint32_t));

                        if (chunk_len == 0)
                            break;

                        if (sv.length() < chunk_len)
                            return false;

                        sv = sv.substr(chunk_len);
                    } while (true);
                } else {
                    if (sv.length() < sizeof(uint16_t))
                        return false;

                    auto len = *(uint16_t*)sv.data();

                    sv = sv.substr(sizeof(uint16_t));

                    if (len == 0xffff)
                        return true;

                    if (sv.length() < len)
                        return false;

                    sv = sv.substr(len);
                }

                break;

            case sql_type::SQL_VARIANT:
            {
                if (sv.length() < sizeof(uint32_t))
                    return false;

                auto len = *(uint32_t*)sv.data();

                sv = sv.substr(sizeof(uint32_t));

                if (len == 0xffffffff)
                    return true;

                if (sv.length() < len)
                    return false;

                sv = sv.substr(len);

                break;
            }

            case sql_type::IMAGE:
            case sql_type::NTEXT:
            case sql_type::TEXT:
            {
                // text pointer

                if (sv.length() < sizeof(uint8_t))
                    return false;

                auto textptrlen = (uint8_t)sv[0];

                sv = sv.substr(1);

                if (sv.length() < textptrlen)
                    return false;

                sv = sv.substr(textptrlen);

                if (textptrlen != 0) {
                    // timestamp

                    if (sv.length() < 8)
                        return false;

                    sv = sv.substr(8);

                    // data

                    if (sv.length() < sizeof(uint32_t))
                        return false;

                    auto len = *(uint32_t*)sv.data();

                    sv = sv.substr(sizeof(uint32_t));

                    if (sv.length() < len)
                        return false;

                    sv = sv.substr(len);
                }

                break;
            }

            default:
                throw formatted_error("Unhandled type {} in ROW message.", type);
        }

        return true;
    }

    static void parse_tokens(string_view& sv, list<string>& tokens, vector<column>& buf_columns) {
        while (!sv.empty()) {
            auto type = (token)sv[0];

            switch (type) {
                case token::TABNAME:
                case token::COLINFO:
                case token::ORDER:
                case token::TDS_ERROR:
                case token::INFO:
                case token::LOGINACK:
                case token::ENVCHANGE:
                case token::SSPI: {
                    if (sv.length() < 1 + sizeof(uint16_t))
                        return;

                    auto len = *(uint16_t*)&sv[1];

                    if (sv.length() < (size_t)(1 + sizeof(uint16_t) + len))
                        return;

                    tokens.emplace_back(sv.substr(0, 1 + sizeof(uint16_t) + len));
                    sv = sv.substr(1 + sizeof(uint16_t) + len);

                    break;
                }

                case token::DONE:
                case token::DONEPROC:
                case token::DONEINPROC:
                    if (sv.length() < 1 + sizeof(tds_done_msg))
                        return;

                    tokens.emplace_back(sv.substr(0, 1 + sizeof(tds_done_msg)));
                    sv = sv.substr(1 + sizeof(tds_done_msg));
                break;

                case token::COLMETADATA: {
                    if (sv.length() < 5)
                        return;

                    auto num_columns = *(uint16_t*)&sv[1];

                    if (num_columns == 0) {
                        buf_columns.clear();
                        tokens.emplace_back(sv.substr(0, 5));
                        sv = sv.substr(5);
                        continue;
                    }

                    vector<column> cols;

                    cols.reserve(num_columns);

                    string_view sv2 = sv;

                    sv2 = sv2.substr(1 + sizeof(uint16_t));

                    for (unsigned int i = 0; i < num_columns; i++) {
                        if (sv2.length() < sizeof(tds_colmetadata_col))
                            return;

                        cols.emplace_back();

                        auto& col = cols.back();

                        auto& c = *(tds_colmetadata_col*)&sv2[0];

                        col.type = c.type;

                        sv2 = sv2.substr(sizeof(tds_colmetadata_col));

                        switch (c.type) {
                            case sql_type::SQL_NULL:
                            case sql_type::TINYINT:
                            case sql_type::BIT:
                            case sql_type::SMALLINT:
                            case sql_type::INT:
                            case sql_type::DATETIM4:
                            case sql_type::REAL:
                            case sql_type::MONEY:
                            case sql_type::DATETIME:
                            case sql_type::FLOAT:
                            case sql_type::SMALLMONEY:
                            case sql_type::BIGINT:
                            case sql_type::DATE:
                                // nop
                            break;

                            case sql_type::INTN:
                            case sql_type::FLTN:
                            case sql_type::TIME:
                            case sql_type::DATETIME2:
                            case sql_type::DATETIMN:
                            case sql_type::DATETIMEOFFSET:
                            case sql_type::BITN:
                            case sql_type::MONEYN:
                            case sql_type::UNIQUEIDENTIFIER:
                                if (sv2.length() < sizeof(uint8_t))
                                    return;

                                col.max_length = *(uint8_t*)sv2.data();

                                sv2 = sv2.substr(1);
                            break;

                            case sql_type::VARCHAR:
                            case sql_type::NVARCHAR:
                            case sql_type::CHAR:
                            case sql_type::NCHAR:
                                if (sv2.length() < sizeof(uint16_t) + sizeof(collation))
                                    return;

                                col.max_length = *(uint16_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint16_t) + sizeof(collation));
                            break;

                            case sql_type::VARBINARY:
                            case sql_type::BINARY:
                                if (sv2.length() < sizeof(uint16_t))
                                    return;

                                col.max_length = *(uint16_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint16_t));
                            break;

                            case sql_type::XML:
                                if (sv2.length() < sizeof(uint8_t))
                                    return;

                                sv2 = sv2.substr(sizeof(uint8_t));
                            break;

                            case sql_type::DECIMAL:
                            case sql_type::NUMERIC:
                                if (sv2.length() < 1)
                                    return;

                                col.max_length = *(uint8_t*)sv2.data();

                                sv2 = sv2.substr(1);

                                if (sv2.length() < 2)
                                    return;

                                sv2 = sv2.substr(2);
                            break;

                            case sql_type::SQL_VARIANT:
                                if (sv2.length() < sizeof(uint32_t))
                                    return;

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));
                            break;

                            case sql_type::IMAGE:
                            case sql_type::NTEXT:
                            case sql_type::TEXT:
                            {
                                if (sv2.length() < sizeof(uint32_t))
                                    return;

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));

                                if (c.type == sql_type::TEXT || c.type == sql_type::NTEXT) {
                                    if (sv2.length() < sizeof(collation))
                                        return;

                                    sv2 = sv2.substr(sizeof(collation));
                                }

                                if (sv2.length() < 1)
                                    return;

                                auto num_parts = (uint8_t)sv2[0];

                                sv2 = sv2.substr(1);

                                for (uint8_t j = 0; j < num_parts; j++) {
                                    if (sv2.length() < sizeof(uint16_t))
                                        return;

                                    auto partlen = *(uint16_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint16_t));

                                    if (sv2.length() < partlen * sizeof(char16_t))
                                        return;

                                    sv2 = sv2.substr(partlen * sizeof(char16_t));
                                }

                                break;
                            }

                            default:
                                throw formatted_error("Unhandled type {} in COLMETADATA message.", c.type);
                        }

                        if (sv2.length() < 1)
                            return;

                        auto name_len = (uint8_t)sv2[0];

                        sv2 = sv2.substr(1);

                        if (sv2.length() < name_len * sizeof(char16_t))
                            return;

                        sv2 = sv2.substr(name_len * sizeof(char16_t));
                    }

                    auto len = (size_t)(sv2.data() - sv.data());

                    tokens.emplace_back(sv.substr(0, len));
                    sv = sv.substr(len);

                    buf_columns = cols;

                    break;
                }

                case token::ROW: {
                    auto sv2 = sv.substr(1);

                    for (unsigned int i = 0; i < buf_columns.size(); i++) {
                        if (!parse_row_col(buf_columns[i].type, buf_columns[i].max_length, sv2))
                            return;
                    }

                    auto len = (size_t)(sv2.data() - sv.data());

                    tokens.emplace_back(sv.substr(0, len));
                    sv = sv.substr(len);

                    break;
                }

                case token::NBCROW:
                {
                    if (buf_columns.empty())
                        break;

                    auto sv2 = sv.substr(1);

                    auto bitset_length = (buf_columns.size() + 7) / 8;

                    if (sv2.length() < bitset_length)
                        return;

                    string_view bitset(sv2.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv2 = sv2.substr(bitset_length);

                    for (unsigned int i = 0; i < buf_columns.size(); i++) {
                        if (i != 0) {
                            if ((i & 7) == 0) {
                                bitset = bitset.substr(1);
                                bsv = (uint8_t)bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (!(bsv & 1)) { // not NULL
                            if (!parse_row_col(buf_columns[i].type, buf_columns[i].max_length, sv2))
                                return;
                        }
                    }

                    auto len = (size_t)(sv2.data() - sv.data());

                    tokens.emplace_back(sv.substr(0, len));
                    sv = sv.substr(len);

                    break;
                }

                case token::RETURNSTATUS:
                {
                    if (sv.length() < 1 + sizeof(int32_t))
                        return;

                    tokens.emplace_back(sv.substr(0, 1 + sizeof(int32_t)));
                    sv = sv.substr(1 + sizeof(int32_t));

                    break;
                }

                case token::RETURNVALUE:
                {
                    auto h = (tds_return_value*)&sv[1];

                    if (sv.length() < 1 + sizeof(tds_return_value))
                        return;

                    // FIXME - param name

                    if (is_byte_len_type(h->type)) {
                        uint8_t len;

                        if (sv.length() < 1 + sizeof(tds_return_value) + 2)
                            return;

                        len = *((uint8_t*)&sv[1] + sizeof(tds_return_value) + 1);

                        if (sv.length() < 1 + sizeof(tds_return_value) + 2 + len)
                            return;

                        tokens.emplace_back(sv.substr(0, 1 + sizeof(tds_return_value) + 2 + len));
                        sv = sv.substr(1 + sizeof(tds_return_value) + 2 + len);
                    } else
                        throw formatted_error("Unhandled type {} in RETURNVALUE message.", h->type);

                    break;
                }

                case token::FEATUREEXTACK:
                {
                    auto sv2 = sv.substr(1);

                    while (true) {
                        if (sv2.length() < 1)
                            return;

                        if ((uint8_t)sv2[0] == 0xff) {
                            sv2 = sv2.substr(1);
                            break;
                        }

                        if (sv2.length() < 1 + sizeof(uint32_t))
                            return;

                        auto len = *(uint32_t*)&sv2[1];

                        sv2 = sv2.substr(1 + sizeof(uint32_t));

                        if (sv2.length() < len)
                            return;

                        sv2 = sv2.substr(len);
                    }

                    auto token_len = (size_t)(sv2.data() - sv.data());

                    tokens.emplace_back(sv.substr(0, token_len));
                    sv = sv.substr(token_len);

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} while parsing tokens.", type);
            }
        }
    }

    static u16string_view extract_message(const string_view& sv) {
        return u16string_view((char16_t*)&sv[8], *(uint16_t*)&sv[6]);
    }

    void tds_impl::send_login_msg(const string_view& user, const string_view& password, const string_view& server,
                                  const string_view& app_name) {
        enum tds_msg type;
        string payload, sspi;
#ifdef _WIN32
        u16string spn;
        unique_ptr<sspi_handle> sspih;
#elif defined(HAVE_GSSAPI)
        string spn;
        gss_cred_id_t cred_handle = 0;
        gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
#endif

        auto user_u16 = utf8_to_utf16(user);
        auto password_u16 = utf8_to_utf16(password);

        if (user.empty()) {
            if (fqdn.empty())
                throw runtime_error("Could not do SSPI authentication as could not find server FQDN.");

#ifdef _WIN32
            spn = u"MSSQLSvc/" + utf8_to_utf16(fqdn);

            SECURITY_STATUS sec_status;
            TimeStamp timestamp;
            SecBuffer outbuf;
            SecBufferDesc out;
            uint32_t context_attr;

            sspih.reset(new sspi_handle);

            outbuf.cbBuffer = 0;
            outbuf.BufferType = SECBUFFER_TOKEN;
            outbuf.pvBuffer = nullptr;

            out.ulVersion = SECBUFFER_VERSION;
            out.cBuffers = 1;
            out.pBuffers = &outbuf;

            sec_status = sspih->init_security_context(spn.c_str(), ISC_REQ_ALLOCATE_MEMORY, SECURITY_NATIVE_DREP,
                                                      nullptr, &out, &context_attr, &timestamp);

            sspi = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

            if (outbuf.pvBuffer)
                FreeContextBuffer(outbuf.pvBuffer);

            if (sec_status != SEC_E_OK && sec_status != SEC_I_CONTINUE_NEEDED && sec_status != SEC_I_COMPLETE_AND_CONTINUE)
                throw formatted_error("InitializeSecurityContext returned unexpected status {}", (enum sec_error)sec_status);
#elif defined(HAVE_GSSAPI)
            spn = "MSSQLSvc/" + fqdn;

            OM_uint32 major_status, minor_status;
            gss_buffer_desc recv_tok, send_tok, name_buf;
            gss_name_t gss_name;

            if (cred_handle != 0) {
                major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                                GSS_C_INITIATE, &cred_handle, nullptr, nullptr);

                if (major_status != GSS_S_COMPLETE)
                    throw gss_error("gss_acquire_cred", major_status, minor_status);
            }

            name_buf.length = spn.length();
            name_buf.value = (void*)spn.data();

            major_status = gss_import_name(&minor_status, &name_buf, GSS_C_NO_OID, &gss_name);
            if (major_status != GSS_S_COMPLETE) {
                gss_release_cred(&minor_status, &cred_handle);
                throw gss_error("gss_import_name", major_status, minor_status);
            }

            recv_tok.length = 0;
            recv_tok.value = nullptr;

            major_status = gss_init_sec_context(&minor_status, cred_handle, &ctx_handle, gss_name, GSS_C_NO_OID,
                                                GSS_C_DELEG_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                                &recv_tok, nullptr, &send_tok, nullptr, nullptr);

            if (major_status != GSS_S_CONTINUE_NEEDED && major_status != GSS_S_COMPLETE) {
                gss_release_cred(&minor_status, &cred_handle);
                throw gss_error("gss_init_sec_context", major_status, minor_status);
            }

            if (send_tok.length != 0) {
                sspi = string((char*)send_tok.value, send_tok.length);

                gss_release_buffer(&minor_status, &send_tok);
            }

            gss_delete_sec_context(&minor_status, &ctx_handle, GSS_C_NO_BUFFER);
            gss_release_cred(&minor_status, &cred_handle);
#else
            throw runtime_error("No username given and Kerberos support not compiled in.");
#endif
        }

        u16string client_name;

        {
            char s[255];

            if (gethostname(s, sizeof(s)) != 0) {
#ifdef _WIN32
                throw formatted_error("gethostname failed (error {})", WSAGetLastError());
#else
                throw formatted_error("gethostname failed (error {})", errno);
#endif
            }

            client_name = utf8_to_utf16(s);
        }

        // FIXME - client PID
        // FIXME - option flags (1, 2, 3)
        // FIXME - collation
        // FIXME - app name
        // FIXME - locale name?

        send_login_msg2(0x74000004, packet_size, 0xf8f28306, 0x5ab7, 0, 0xe0, 0x03, 0, 0x08, 0x436,
                        client_name, user_u16, password_u16, utf8_to_utf16(app_name), utf8_to_utf16(server), u"", u"us_english",
                        u"", sspi, u"", u"");

        // FIXME - timeout

        bool received_loginack;
#ifdef _WIN32
        bool go_again;
#endif

        do {
#ifdef _WIN32
            go_again = false;
#endif
            bool last_packet;
            string buf;
            list<string> tokens;
            vector<column> buf_columns;
            string sspibuf;

            do {
                wait_for_msg(type, payload, &last_packet);
                // FIXME - timeout

                if (type != tds_msg::tabular_result)
                    throw formatted_error("Received message type {}, expected tabular_result", (int)type);

                buf += payload;

                {
                    string_view sv = buf;

                    parse_tokens(sv, tokens, buf_columns);

                    buf = sv;
                }

                if (last_packet && !buf.empty())
                    throw formatted_error("Data remaining in buffer");

                received_loginack = false;

                while (!tokens.empty()) {
                    auto t = move(tokens.front());

                    tokens.pop_front();

                    auto type = (token)t[0];

                    auto sv = string_view(t).substr(1);

                    switch (type) {
                        case token::DONE:
                        case token::DONEINPROC:
                        case token::DONEPROC:
                            if (sv.length() < sizeof(tds_done_msg))
                                throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                            break;

                        case token::LOGINACK:
                        case token::INFO:
                        case token::TDS_ERROR:
                        case token::ENVCHANGE:
                        {
                            if (sv.length() < sizeof(uint16_t))
                                throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                            auto len = *(uint16_t*)&sv[0];

                            sv = sv.substr(sizeof(uint16_t));

                            if (sv.length() < len)
                                throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                            if (type == token::LOGINACK) {
                                handle_loginack_msg(sv.substr(0, len));
                                received_loginack = true;
                            } else if (type == token::INFO) {
                                if (message_handler)
                                    handle_info_msg(sv.substr(0, len), false);
                            } else if (type == token::TDS_ERROR) {
                                if (message_handler)
                                    handle_info_msg(sv.substr(0, len), true);

                                throw formatted_error("Login failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                            } else if (type == token::ENVCHANGE)
                                handle_envchange_msg(sv.substr(0, len));

                            break;
                        }

#ifdef _WIN32
                        case token::SSPI: // FIXME - handle doing this with GSSAPI
                        {
                            if (sv.length() < sizeof(uint16_t))
                                throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                            auto len = *(uint16_t*)&sv[0];

                            sv = sv.substr(sizeof(uint16_t));

                            if (sv.length() < len)
                                throw formatted_error("Short SSPI token ({} bytes, expected {}).", type, sv.length(), len);

                            if (!sspih)
                                throw runtime_error("SSPI token received, but no current SSPI context.");

                            sspibuf = sv.substr(0, len);
                            go_again = true;

                            break;
                        }
#endif

                        case token::FEATUREEXTACK:
                        {
                            while (true) {
                                auto feature = (enum tds_feature)sv[0];

                                if (feature == tds_feature::TERMINATOR)
                                    break;

                                auto len = *(uint32_t*)&sv[1];

                                if (feature == tds_feature::UTF8_SUPPORT && len >= 1)
                                    has_utf8 = (uint8_t)sv[1 + sizeof(uint32_t)];

                                sv = sv.substr(1 + sizeof(uint32_t) + len);
                            }

                            break;
                        }

                        default:
                            break;
                    }
                }
            } while (!last_packet);

#ifdef _WIN32
            if (go_again)
                send_sspi_msg(&sspih->cred_handle, &sspih->ctx_handle, spn, sspibuf);
#endif
            if (received_loginack)
                break;
        } while (true);
    }

#ifdef _WIN32
    void tds_impl::send_sspi_msg(CredHandle* cred_handle, CtxtHandle* ctx_handle, const u16string& spn, const string_view& sspi) {
        SECURITY_STATUS sec_status;
        TimeStamp timestamp;
        SecBuffer inbufs[2], outbuf;
        SecBufferDesc in, out;
        unsigned long context_attr;
        string ret;

        inbufs[0].cbBuffer = (uint32_t)sspi.length();
        inbufs[0].BufferType = SECBUFFER_TOKEN;
        inbufs[0].pvBuffer = (void*)sspi.data();

        inbufs[1].cbBuffer = 0;
        inbufs[1].BufferType = SECBUFFER_EMPTY;
        inbufs[1].pvBuffer = nullptr;

        in.ulVersion = SECBUFFER_VERSION;
        in.cBuffers = 2;
        in.pBuffers = inbufs;

        outbuf.cbBuffer = 0;
        outbuf.BufferType = SECBUFFER_TOKEN;
        outbuf.pvBuffer = nullptr;

        out.ulVersion = SECBUFFER_VERSION;
        out.cBuffers = 1;
        out.pBuffers = &outbuf;

        sec_status = InitializeSecurityContextW(cred_handle, ctx_handle, (SEC_WCHAR*)spn.c_str(),
                                                ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                                                &in, 0, ctx_handle, &out, &context_attr, &timestamp);
        if (FAILED(sec_status))
            throw formatted_error("InitializeSecurityContext returned {}", (enum sec_error)sec_status);

        ret = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

        if (outbuf.pvBuffer)
            FreeContextBuffer(outbuf.pvBuffer);

        if (!ret.empty())
            send_msg(tds_msg::sspi, ret);
    }
#endif

    void tds_impl::send_login_msg2(uint32_t tds_version, uint32_t packet_size, uint32_t client_version, uint32_t client_pid,
                                   uint32_t connexion_id, uint8_t option_flags1, uint8_t option_flags2, uint8_t sql_type_flags,
                                   uint8_t option_flags3, uint32_t collation, const u16string_view& client_name,
                                   const u16string_view& username, const u16string_view& password, const u16string_view& app_name,
                                   const u16string_view& server_name, const u16string_view& interface_library,
                                   const u16string_view& locale, const u16string_view& database, const string& sspi,
                                   const u16string_view& attach_db, const u16string_view& new_password) {
        uint32_t length;
        uint16_t off;

        static const vector<string> features = {
            "\x0a\x01\x00\x00\x00\x01"s // UTF-8 support
        };

        length = sizeof(tds_login_msg);
        length += (uint32_t)(client_name.length() * sizeof(char16_t));
        length += (uint32_t)(username.length() * sizeof(char16_t));
        length += (uint32_t)(password.length() * sizeof(char16_t));
        length += (uint32_t)(app_name.length() * sizeof(char16_t));
        length += (uint32_t)(server_name.length() * sizeof(char16_t));
        length += (uint32_t)(interface_library.length() * sizeof(char16_t));
        length += (uint32_t)(locale.length() * sizeof(char16_t));
        length += (uint32_t)(database.length() * sizeof(char16_t));
        length += (uint32_t)sspi.length();

        length += sizeof(uint32_t);
        for (const auto& f : features) {
            length += (uint32_t)f.length();
        }
        length += sizeof(uint8_t);

        string payload;

        payload.resize(length);

        auto msg = (tds_login_msg*)payload.data();

        msg->length = length;
        msg->tds_version = tds_version;
        msg->packet_size = packet_size;
        msg->client_version = client_version;
        msg->client_pid = client_pid;
        msg->connexion_id = connexion_id;
        msg->option_flags1 = option_flags1;
        msg->option_flags2 = option_flags2 | (uint8_t)(!sspi.empty() ? 0x80 : 0);
        msg->sql_type_flags = sql_type_flags;
        msg->option_flags3 = option_flags3 | 0x10;
        msg->timezone = 0;
        msg->collation = collation;

        off = sizeof(tds_login_msg);

        msg->client_name_offset = off;

        if (!client_name.empty()) {
            msg->client_name_length = (uint16_t)client_name.length();
            memcpy((uint8_t*)msg + msg->client_name_offset, client_name.data(),
                    client_name.length() * sizeof(char16_t));

            off += (uint16_t)(client_name.length() * sizeof(char16_t));
        } else
            msg->client_name_length = 0;

        msg->username_offset = off;

        if (!username.empty()) {
            msg->username_length = (uint16_t)username.length();
            memcpy((uint8_t*)msg + msg->username_offset, username.data(),
                    username.length() * sizeof(char16_t));

            off += (uint16_t)(username.length() * sizeof(char16_t));
        } else
            msg->username_length = 0;

        msg->password_offset = off;

        if (!password.empty()) {
            msg->password_length = (uint16_t)password.length();

            auto pw_dest = (uint8_t*)msg + msg->password_offset;
            auto pw_src = (uint8_t*)password.data();

            for (unsigned int i = 0; i < password.length() * sizeof(char16_t); i++) {
                uint8_t c = *pw_src;

                c = (uint8_t)(((c & 0xf) << 4) | (c >> 4));
                c ^= 0xa5;

                *pw_dest = c;

                pw_src++;
                pw_dest++;
            }

            off += (uint16_t)(password.length() * sizeof(char16_t));
        } else
            msg->password_length = 0;

        msg->app_name_offset = off;

        if (!app_name.empty()) {
            msg->app_name_length = (uint16_t)app_name.length();
            memcpy((uint8_t*)msg + msg->app_name_offset, app_name.data(),
                    app_name.length() * sizeof(char16_t));

            off += (uint16_t)(app_name.length() * sizeof(char16_t));
        } else
            msg->app_name_length = 0;

        msg->server_name_offset = off;

        if (!server_name.empty()) {
            msg->server_name_length = (uint16_t)server_name.length();
            memcpy((uint8_t*)msg + msg->server_name_offset, server_name.data(),
                    server_name.length() * sizeof(char16_t));

            off += (uint16_t)(server_name.length() * sizeof(char16_t));
        } else
            msg->server_name_length = 0;

        msg->interface_library_offset = off;

        if (!interface_library.empty()) {
            msg->interface_library_length = (uint16_t)interface_library.length();
            memcpy((uint8_t*)msg + msg->interface_library_offset, interface_library.data(),
                    interface_library.length() * sizeof(char16_t));

            off += (uint16_t)(interface_library.length() * sizeof(char16_t));
        } else
            msg->interface_library_length = 0;

        msg->locale_offset = off;

        if (!locale.empty()) {
            msg->locale_length = (uint16_t)locale.length();
            memcpy((uint8_t*)msg + msg->locale_offset, locale.data(),
                    locale.length() * sizeof(char16_t));

            off += (uint16_t)(locale.length() * sizeof(char16_t));
        } else
            msg->locale_length = 0;

        msg->database_offset = off;

        if (!database.empty()) {
            msg->database_length = (uint16_t)database.length();
            memcpy((uint8_t*)msg + msg->database_offset, database.data(),
                    database.length() * sizeof(char16_t));

            off += (uint16_t)(database.length() * sizeof(char16_t));
        } else
            msg->database_length = 0;

        // FIXME - set MAC address properly?
        memset(msg->mac_address, 0, 6);

        msg->attach_db_offset = off;

        if (!attach_db.empty()) {
            msg->attach_db_length = (uint16_t)attach_db.length();
            memcpy((uint8_t*)msg + msg->attach_db_offset, attach_db.data(),
                    attach_db.length() * sizeof(char16_t));

            off += (uint16_t)(attach_db.length() * sizeof(char16_t));
        } else
            msg->attach_db_length = 0;

        msg->new_password_offset = off;

        if (!new_password.empty()) {
            msg->new_password_length = (uint16_t)new_password.length();
            memcpy((uint8_t*)msg + msg->new_password_offset, new_password.data(),
                    new_password.length() * sizeof(char16_t));

            off += (uint16_t)(new_password.length() * sizeof(char16_t));
        } else
            msg->new_password_length = 0;

        if (sspi.empty()) {
            msg->sspi_offset = 0;
            msg->sspi_length = 0;
            msg->sspi_long = 0;
        } else {
            msg->sspi_offset = off;

            if (sspi.length() >= numeric_limits<uint16_t>::max()) {
                msg->sspi_length = numeric_limits<uint16_t>::max();
                msg->sspi_long = (uint32_t)sspi.length();
            } else {
                msg->sspi_length = (uint16_t)sspi.length();
                msg->sspi_long = 0;
            }

            memcpy((uint8_t*)msg + msg->sspi_offset, sspi.data(), sspi.length());

            off += (uint16_t)sspi.length();
        }

        msg->extension_offset = off;
        msg->extension_length = sizeof(uint32_t);

        *(uint32_t*)((uint8_t*)msg + msg->extension_offset) = off + sizeof(uint32_t);
        off += sizeof(uint32_t);

        for (const auto& f : features) {
            memcpy((uint8_t*)msg + off, f.data(), f.length());
            off += (uint16_t)f.length();
        }

        *(enum tds_feature*)((uint8_t*)msg + off) = tds_feature::TERMINATOR;

        send_msg(tds_msg::tds7_login, payload);
    }

    void tds_impl::send_msg(enum tds_msg type, const string_view& msg) {
        string payload;
        const size_t size = packet_size - sizeof(tds_header);
        string_view sv = msg;

        while (true) {
            string_view sv2;

            if (sv.length() > size)
                sv2 = sv.substr(0, size);
            else
                sv2 = sv;

            payload.resize(sv2.length() + sizeof(tds_header));

            auto h = (tds_header*)payload.data();

            h->type = type;
            h->status = sv2.length() == sv.length() ? 1 : 0; // 1 == last message
            h->length = htons((uint16_t)(sv2.length() + sizeof(tds_header)));
            h->spid = 0;
            h->packet_id = 0; // FIXME? "Currently ignored" according to spec
            h->window = 0;

            if (!sv2.empty())
                memcpy(payload.data() + sizeof(tds_header), sv2.data(), sv2.size());

            auto ptr = (uint8_t*)payload.data();
            auto left = (int)payload.length();

            do {
                auto ret = send(sock, (char*)ptr, left, 0);

#ifdef _WIN32
                if (ret < 0)
                    throw formatted_error("send failed (error {})", WSAGetLastError());
#else
                if (ret < 0)
                    throw formatted_error("send failed (error {})", errno);
#endif

                if (ret == left)
                    break;

                ptr += left;
                ret -= left;
            } while (true);

            if (sv2.length() == sv.length())
                return;

            sv = sv.substr(size);
        }
    }

    void tds_impl::wait_for_msg(enum tds_msg& type, string& payload, bool* last_packet) {
        tds_header h;
        auto ptr = (uint8_t*)&h;
        int left = sizeof(tds_header);

        do {
            auto ret = recv(sock, (char*)ptr, left, 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error("recv failed (error {})", WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error("recv failed (error {})", errno);
#endif

            if (ret == 0)
                throw formatted_error("Disconnected.");

            if (ret == left)
                break;

            ptr += ret;
            left -= (int)ret;
        } while (true);

        if (htons(h.length) < sizeof(tds_header)) {
            throw formatted_error("message length was {}, expected at least {}",
                                    htons(h.length), sizeof(tds_header));
        }

        type = h.type;

        if (htons(h.length) > sizeof(tds_header)) {
            left = (int)(htons(h.length) - sizeof(tds_header));

            payload.resize(left);

            ptr = (uint8_t*)&payload[0];

            do {
                auto ret = recv(sock, (char*)ptr, (int)left, 0);

                if (ret < 0)
                    throw formatted_error("recv failed (error {})", errno);

                if (ret == 0)
                    throw formatted_error("Disconnected.");

                if (ret == left)
                    break;

                ptr += ret;
                left -= (int)ret;
            } while (true);
        } else
            payload.clear();

        if (last_packet)
            *last_packet = h.status & 1;

        spid = htons(h.spid);
    }

    void tds_impl::handle_loginack_msg(string_view sv) {
        uint8_t server_name_len;
        uint32_t tds_version;
#ifdef DEBUG_SHOW_MSGS
        uint8_t interf;
        uint32_t server_version;
#endif
        u16string_view server_name;

        if (sv.length() < 10)
            throw runtime_error("Short LOGINACK message.");

        server_name_len = (uint8_t)sv[5];

        if (sv.length() < 10 + (server_name_len * sizeof(char16_t)))
            throw runtime_error("Short LOGINACK message.");

#ifdef DEBUG_SHOW_MSGS
        interf = (uint8_t)sv[0];
#endif
        tds_version = *(uint32_t*)&sv[1];
        server_name = u16string_view((char16_t*)&sv[6], server_name_len);
#ifdef DEBUG_SHOW_MSGS
        server_version = *(uint32_t*)&sv[6 + (server_name_len * sizeof(char16_t))];
#endif

#ifdef DEBUG_SHOW_MSGS
        while (!server_name.empty() && server_name.back() == 0) {
            server_name = server_name.substr(0, server_name.length() - 1);
        }

        fmt::print("LOGINACK: interface = {}, TDS version = {:x}, server = {}, server version = {}.{}.{}\n",
                   interf, tds_version, utf16_to_utf8(server_name), server_version & 0xff, (server_version & 0xff00) >> 8,
                    ((server_version & 0xff0000) >> 8) | (server_version >> 24));
#endif

        if (tds_version != tds_74_version)
            throw formatted_error("Server not using TDS 7.4. Version was {:x}, expected {:x}.", tds_version, tds_74_version);
    }

    void tds_impl::handle_info_msg(string_view sv, bool error) {
        if (sv.length() < sizeof(tds_info_msg))
            throw formatted_error("Short INFO message ({} bytes, expected at least 6).", sv.length());

        auto tim = (tds_info_msg*)sv.data();

        sv = sv.substr(sizeof(tds_info_msg));

        if (sv.length() < sizeof(uint16_t))
            throw formatted_error("Short INFO message ({} bytes left, expected at least 2).", sv.length());

        auto msg_len = *(uint16_t*)sv.data();
        sv = sv.substr(sizeof(uint16_t));

        if (sv.length() < msg_len * sizeof(char16_t)) {
            throw formatted_error("Short INFO message ({} bytes left, expected at least {}).",
                                  sv.length(), msg_len * sizeof(char16_t));
        }

        auto msg = u16string_view((char16_t*)sv.data(), msg_len);
        sv = sv.substr(msg_len * sizeof(char16_t));

        if (sv.length() < sizeof(uint8_t))
            throw formatted_error("Short INFO message ({} bytes left, expected at least 1).", sv.length());

        auto server_name_len = (uint8_t)sv[0];
        sv = sv.substr(sizeof(uint8_t));

        if (sv.length() < server_name_len * sizeof(char16_t)) {
            throw formatted_error("Short INFO message ({} bytes left, expected at least {}).",
                                  sv.length(), server_name_len * sizeof(char16_t));
        }

        auto server_name = u16string_view((char16_t*)sv.data(), server_name_len);
        sv = sv.substr(server_name_len * sizeof(char16_t));

        if (sv.length() < sizeof(uint8_t))
            throw formatted_error("Short INFO message ({} bytes left, expected at least 1).", sv.length());

        auto proc_name_len = (uint8_t)sv[0];
        sv = sv.substr(sizeof(uint8_t));

        if (sv.length() < proc_name_len * sizeof(char16_t)) {
            throw formatted_error("Short INFO message ({} bytes left, expected at least {}).",
                                  sv.length(), proc_name_len * sizeof(char16_t));
        }

        auto proc_name = u16string_view((char16_t*)sv.data(), proc_name_len);
        sv = sv.substr(proc_name_len * sizeof(char16_t));

        if (sv.length() < sizeof(int32_t))
            throw formatted_error("Short INFO message ({} bytes left, expected at least 4).", sv.length());

        auto line_number = *(int32_t*)sv.data();

        message_handler(utf16_to_utf8(server_name), utf16_to_utf8(msg), utf16_to_utf8(proc_name), tim->msgno, line_number,
                        tim->state, tim->severity, error);
    }

    value::value() {
        type = (sql_type)0;
    }

    value::value(nullptr_t) {
        type = sql_type::SQL_NULL;
        is_null = true;
    }

    value::value(int32_t i) {
        type = sql_type::INTN;

        val.resize(sizeof(int32_t));
        *(int32_t*)val.data() = i;
    }

    value::value(const optional<int32_t>& i) {
        type = sql_type::INTN;

        val.resize(sizeof(int32_t));

        if (i.has_value())
            *(int32_t*)val.data() = i.value();
        else
            is_null = true;
    }

    value::value(int64_t i) {
        type = sql_type::INTN;

        val.resize(sizeof(int64_t));
        *(int64_t*)val.data() = i;
    }

    value::value(const optional<int64_t>& i) {
        type = sql_type::INTN;

        val.resize(sizeof(int64_t));

        if (i.has_value())
            *(int64_t*)val.data() = i.value();
        else
            is_null = true;
    }

    value::value(uint32_t i) {
        type = sql_type::INTN;

        val.resize(sizeof(int64_t));
        *(int64_t*)val.data() = i;
    }

    value::value(const optional<uint32_t>& i) {
        type = sql_type::INTN;

        val.resize(sizeof(int64_t));

        if (i.has_value())
            *(int64_t*)val.data() = i.value();
        else
            is_null = true;
    }

    value::value(const u16string_view& sv) {
        type = sql_type::NVARCHAR;
        val.resize(sv.length() * sizeof(char16_t));
        memcpy(val.data(), sv.data(), val.length());
    }

    value::value(const u16string& sv) : value(u16string_view(sv)) {
    }

    value::value(const char16_t* sv) : value(u16string_view(sv)) {
    }

    value::value(const optional<u16string_view>& sv) {
        type = sql_type::NVARCHAR;

        if (!sv.has_value())
            is_null = true;
        else {
            val.resize(sv.value().length() * sizeof(char16_t));
            memcpy(val.data(), sv.value().data(), sv.value().length());
        }
    }

    value::value(const string_view& sv) {
        type = sql_type::VARCHAR;
        val.resize(sv.length());
        memcpy(val.data(), sv.data(), val.length());
    }

    value::value(const string& sv) : value(string_view(sv)) {
    }

    value::value(const char* sv) : value(string_view(sv)) {
    }

    value::value(const optional<string_view>& sv) {
        type = sql_type::VARCHAR;

        if (!sv.has_value())
            is_null = true;
        else {
            val.resize(sv.value().length());
            memcpy(val.data(), sv.value().data(), sv.value().length());
        }
    }

#ifdef __cpp_char8_t
    value::value(const u8string_view& sv) {
        type = sql_type::VARCHAR;
        utf8 = true;
        val.resize(sv.length());
        memcpy(val.data(), sv.data(), sv.length());
    }

    value::value(const u8string& sv) : value(u8string_view(sv)) {
    }

    value::value(const char8_t* sv) : value(u8string_view(sv)) {
    }

    value::value(const optional<u8string_view>& sv) {
        type = sql_type::VARCHAR;
        utf8 = true;

        if (!sv.has_value())
            is_null = true;
        else {
            val.resize(sv.value().length());
            memcpy(val.data(), sv.value().data(), sv.value().length());
        }
    }
#endif

    value::value(float f) {
        type = sql_type::FLTN;

        val.resize(sizeof(float));
        memcpy(val.data(), &f, sizeof(float));
    }

    value::value(const optional<float>& f) {
        type = sql_type::FLTN;
        val.resize(sizeof(float));

        if (!f.has_value())
            is_null = true;
        else {
            auto v = f.value();

            memcpy(val.data(), &v, sizeof(float));
        }
    }

    value::value(double d) {
        type = sql_type::FLTN;

        val.resize(sizeof(double));
        memcpy(val.data(), &d, sizeof(double));
    }

    value::value(const optional<double>& d) {
        type = sql_type::FLTN;
        val.resize(sizeof(double));

        if (!d.has_value())
            is_null = true;
        else {
            auto v = d.value();

            memcpy(val.data(), &v, sizeof(double));
        }
    }

    static constexpr int ymd_to_num(const chrono::year_month_day& d) noexcept {
        int m2 = ((int)(unsigned int)d.month() - 14) / 12;
        long long n;

        n = (1461 * ((int)d.year() + 4800 + m2)) / 4;
        n += (367 * ((int)(unsigned int)d.month() - 2 - (12 * m2))) / 12;
        n -= (3 * (((int)d.year() + 4900 + m2)/100)) / 4;
        n += (unsigned int)d.day();
        n -= 2447096;

        return static_cast<int>(n);
    }

    static_assert(ymd_to_num({1y, chrono::January, 1d}) == -693595);
    static_assert(ymd_to_num({1900y, chrono::January, 1d}) == 0);

    static constexpr chrono::year_month_day num_to_ymd(int num) noexcept {
        signed long long j, e, f, g, h;
        uint8_t day, month;
        uint16_t year;

        j = num + 2415021;

        f = (4 * j) + 274277;
        f /= 146097;
        f *= 3;
        f /= 4;
        f += j;
        f += 1363;

        e = (4 * f) + 3;
        g = (e % 1461) / 4;
        h = (5 * g) + 2;

        day = (uint8_t)(((h % 153) / 5) + 1);
        month = (uint8_t)(((h / 153) + 2) % 12 + 1);
        year = static_cast<uint16_t>((e / 1461) - 4716 + ((14 - month) / 12));

        return {chrono::year{year}, chrono::month{month}, chrono::day{day}};
    }

    static_assert(num_to_ymd(-693595) == chrono::year_month_day{1y, chrono::January, 1d});
    static_assert(num_to_ymd(0) == chrono::year_month_day{1900y, chrono::January, 1d});

    static const auto jan1900 = -ymd_to_num({1y, chrono::January, 1d});

    value::value(const chrono::year_month_day& d) {
        int32_t n = ymd_to_num(d) + jan1900;

        type = sql_type::DATE;
        val.resize(3);

        memcpy(val.data(), &n, 3);
    }

    value::value(const optional<chrono::year_month_day>& d) {
        type = sql_type::DATE;

        if (!d.has_value())
            is_null = true;
        else {
            int32_t n = ymd_to_num(d.value()) + jan1900;
            val.resize(3);
            memcpy(val.data(), &n, 3);
        }
    }

    value::value(time_t t) {
        auto secs = (uint32_t)chrono::duration_cast<chrono::seconds>(t).count();

        type = sql_type::TIME;
        max_length = 0; // TIME(0)
        scale = 0;

        val.resize(3);
        memcpy(val.data(), &secs, val.length());
    }

    value::value(const std::optional<time_t>& t) {
        type = sql_type::TIME;
        max_length = 0; // TIME(0)
        scale = 0;

        if (!t.has_value())
            is_null = true;
        else {
            auto secs = (uint32_t)chrono::duration_cast<chrono::seconds>(t.value()).count();

            val.resize(3);
            memcpy(val.data(), &secs, val.length());
        }
    }

    value::value(const datetime& dt) {
        int32_t n;

        type = sql_type::DATETIME2;
        scale = 0;
        val.resize(8);
        max_length = 7; // DATETIME2(7)

        auto secs = (uint64_t)dt.t.count();

        memcpy(val.data(), &secs, 5);

        n = ymd_to_num(dt.d) + jan1900;
        memcpy(val.data() + 5, &n, 3);
    }

    value::value(const optional<datetime>& dt) {
        type = sql_type::DATETIME2;
        scale = 0;
        val.resize(8);
        max_length = 7; // DATETIME2(7)

        if (!dt.has_value())
            is_null = true;
        else {
            int32_t n;

            auto secs = (uint64_t)dt.value().t.count();

            memcpy(val.data(), &secs, 5);

            n = ymd_to_num(dt.value().d) + jan1900;
            memcpy(val.data() + 5, &n, 3);
        }
    }

    value::value(const datetimeoffset& dto) {
        int32_t n;

        type = sql_type::DATETIMEOFFSET;
        scale = 0;
        val.resize(10);
        max_length = 7; // DATETIMEOFFSET(7)

        auto ticks = (uint64_t)dto.t.count();

        memcpy(val.data(), &ticks, 5);

        n = ymd_to_num(dto.d) + jan1900;
        memcpy(val.data() + 5, &n, 3);

        *(int16_t*)(val.data() + 8) = dto.offset;
    }

    value::value(const optional<datetimeoffset>& dto) {
        type = sql_type::DATETIMEOFFSET;
        scale = 0;
        val.resize(10);
        max_length = 7; // DATETIMEOFFSET(7)

        if (!dto.has_value())
            is_null = true;
        else {
            int32_t n;

            auto ticks = (uint64_t)dto.value().t.count();

            memcpy(val.data(), &ticks, 5);

            n = ymd_to_num(dto.value().d) + jan1900;
            memcpy(val.data() + 5, &n, 3);

            *(int16_t*)(val.data() + 8) = dto.value().offset;
        }
    }

    value::value(bool b) {
        type = sql_type::BITN;
        val.resize(sizeof(uint8_t));
        *(uint8_t*)val.data() = b ? 1 : 0;
    }

    value::value(const optional<bool>& b) {
        type = sql_type::BITN;
        val.resize(sizeof(uint8_t));

        if (b.has_value())
            *(uint8_t*)val.data() = b ? 1 : 0;
        else
            is_null = true;
    }

    template<unsigned N>
    static void buf_lshift(uint8_t* scratch) {
        bool carry = false;

        for (unsigned int i = 0; i < N; i++) {
            bool b = scratch[i] & 0x80;

            scratch[i] <<= 1;

            if (carry)
                scratch[i] |= 1;

            carry = b;
        }
    }

    template<unsigned N>
    static void buf_rshift(uint8_t* scratch) {
        bool carry = false;

        for (int i = N - 1; i >= 0; i--) {
            bool b = scratch[i] & 0x1;

            scratch[i] >>= 1;

            if (carry)
                scratch[i] |= 0x80;

            carry = b;
        }
    }

    value::operator string() const {
        auto type2 = type;
        unsigned int max_length2 = max_length;
        uint8_t scale2 = scale;
        string_view d = val;

        if (is_null)
            return "";

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1);

            switch (type2) {
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    max_length2 = d[0];
                break;

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    // ignore precision
                    scale2 = d[1];
                break;

                default:
                break;
            }

            d = d.substr(propbytes);
        }

        switch (type2) {
            case sql_type::TINYINT:
                return fmt::format(FMT_STRING("{}"), *(uint8_t*)d.data());

            case sql_type::SMALLINT:
                return fmt::format(FMT_STRING("{}"), *(int16_t*)d.data());

            case sql_type::INT:
                return fmt::format(FMT_STRING("{}"), *(int32_t*)d.data());

            case sql_type::BIGINT:
                return fmt::format(FMT_STRING("{}"), *(int64_t*)d.data());

            case sql_type::INTN:
                switch (d.length()) {
                    case 1:
                        return fmt::format(FMT_STRING("{}"), *(uint8_t*)d.data());

                    case 2:
                        return fmt::format(FMT_STRING("{}"), *(int16_t*)d.data());

                    case 4:
                        return fmt::format(FMT_STRING("{}"), *(int32_t*)d.data());

                    case 8:
                        return fmt::format(FMT_STRING("{}"), *(int64_t*)d.data());

                    default:
                        throw formatted_error("INTN has unexpected length {}.", d.length());
                }
            break;

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            case sql_type::XML:
            {
                u16string_view sv((char16_t*)d.data(), d.length() / sizeof(char16_t));
                auto s = utf16_to_utf8(sv);

                return fmt::format(FMT_STRING("{}"), s);
            }

            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            case sql_type::VARBINARY:
            case sql_type::BINARY:
            case sql_type::IMAGE:
            {
                string_view sv(d.data(), d.length());

                return fmt::format(FMT_STRING("{}"), sv);
            }

            case sql_type::REAL:
                return fmt::format(FMT_STRING("{}"), *(float*)d.data());

            case sql_type::FLOAT:
                return fmt::format(FMT_STRING("{}"), *(double*)d.data());

            case sql_type::FLTN:
                switch (d.length()) {
                    case sizeof(float):
                        return fmt::format(FMT_STRING("{}"), *(float*)d.data());

                    case sizeof(double):
                        return fmt::format(FMT_STRING("{}"), *(double*)d.data());

                    default:
                        throw formatted_error("FLTN has unexpected length {}.", d.length());
                }
            break;

            case sql_type::DATE: {
                uint32_t v;

                memcpy(&v, d.data(), 3);
                v &= 0xffffff;

                auto d = num_to_ymd(v - jan1900);

                return fmt::format(FMT_STRING("{:04}-{:02}-{:02}"), (int)d.year(), (unsigned int)d.month(), (unsigned int)d.day());
            }

            case sql_type::TIME: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length()));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                time_t t(ticks);
                chrono::hh_mm_ss hms(t);

                if (max_length2 == 0)
                    return fmt::format(FMT_STRING("{:02}:{:02}:{:02}"), hms.hours().count(), hms.minutes().count(), hms.seconds().count());
                else {
                    double s = (double)hms.seconds().count() + ((double)hms.subseconds().count() / 10000000.0);

                    return fmt::format(FMT_STRING("{:02}:{:02}:{:0{}.{}f}"), hms.hours().count(), hms.minutes().count(), s,
                                       max_length2 + 3, max_length2);
                }
            }

            case sql_type::DATETIME2: {
                uint64_t ticks = 0;
                uint32_t v;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                memcpy(&v, d.data() + d.length() - 3, 3);
                v &= 0xffffff;

                datetime dt(num_to_ymd(v - jan1900), time_t(ticks));

                return fmt::format(FMT_STRING("{:{}}"), dt, max_length2);
            }

            case sql_type::DATETIME: {
                auto v = *(int32_t*)d.data();
                auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                datetime dt(num_to_ymd(v), dur);

                return fmt::format(FMT_STRING("{}"), dt);
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto v = *(uint16_t*)d.data();
                        auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                        auto dur = chrono::minutes(t);

                        datetime dt(num_to_ymd(v), dur);

                        return fmt::format(FMT_STRING("{:0}"), dt);
                    }

                    case 8: {
                        auto v = *(int32_t*)d.data();
                        auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                        auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                        datetime dt(num_to_ymd(v), dur);

                        return fmt::format(FMT_STRING("{}"), dt);
                    }

                    default:
                        throw formatted_error("DATETIMN has invalid length {}.", d.length());
                }

            case sql_type::DATETIM4: {
                auto v = *(uint16_t*)d.data();
                auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                auto dur = chrono::minutes(t);

                datetime dt(num_to_ymd(v), dur);

                return fmt::format(FMT_STRING("{:0}"), dt);
            }

            case sql_type::DATETIMEOFFSET: {
                uint64_t ticks = 0;
                uint32_t v;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                memcpy(&v, d.data() + d.length() - 5, 3);
                v &= 0xffffff;

                datetimeoffset dto(num_to_ymd(v - jan1900), (time_t)ticks, *(int16_t*)(d.data() + d.length() - sizeof(int16_t)));

                return fmt::format(FMT_STRING("{:{}}"), dto, max_length2);
            }

            case sql_type::BITN:
            case sql_type::BIT:
                return fmt::format(FMT_STRING("{}"), d[0] != 0);

            case sql_type::NUMERIC:
            case sql_type::DECIMAL: {
                uint8_t scratch[38];
                char s[80], *p, *dot;
                unsigned int pos;
                auto numlen = (unsigned int)(d.length() - 1);

                // double dabble

                memcpy(scratch, d.data() + 1, d.length() - 1);
                memset(scratch + numlen, 0, sizeof(scratch) - numlen);

                for (unsigned int iter = 0; iter < numlen * 8; iter++) {
                    for (unsigned int i = numlen; i < 38; i++) {
                        if (scratch[i] >> 4 >= 5) {
                            uint8_t v = scratch[i] >> 4;

                            v += 3;

                            scratch[i] = (uint8_t)((scratch[i] & 0xf) | (v << 4));
                        }

                        if ((scratch[i] & 0xf) >= 5) {
                            uint8_t v = scratch[i] & 0xf;

                            v += 3;

                            scratch[i] = (uint8_t)((scratch[i] & 0xf0) | v);
                        }
                    }

                    buf_lshift<sizeof(scratch)>(scratch);
                }

                p = s;
                pos = 0;
                for (unsigned int i = 37; i >= numlen; i--) {
                    *p = (char)((scratch[i] >> 4) + '0');
                    p++;
                    pos++;

                    if (pos == 77 - (numlen * 2) - scale2 - 1) {
                        *p = '.';
                        dot = p;
                        p++;
                    }

                    *p = (char)((scratch[i] & 0xf) + '0');
                    p++;
                    pos++;

                    if (pos == 77 - (numlen * 2) - scale2 - 1) {
                        *p = '.';
                        dot = p;
                        p++;
                    }
                }
                *p = 0;

                // remove leading zeroes

                for (p = s; p < dot - 1; p++) {
                    if (*p != '0')
                        break;
                }

                if (scale2 == 0) // remove trailing dot
                    p[strlen(p) - 1] = 0;

                return fmt::format(FMT_STRING("{}{}"), d[0] == 0 ? "-" : "", p);
            }

            case sql_type::MONEYN:
                switch (d.length()) {
                    case sizeof(int64_t): {
                        auto v = *(int64_t*)d.data();

                        v = (v >> 32) | ((v & 0xffffffff) << 32);

                        int16_t p = (int16_t)(v % 10000);

                        if (p < 0)
                            p = -p;

                        return fmt::format(FMT_STRING("{}.{:04}"), v / 10000, p);
                    }

                    case sizeof(int32_t): {
                        auto v = *(int32_t*)d.data();

                        int16_t p = (int16_t)(v % 10000);

                        if (p < 0)
                            p = -p;

                        return fmt::format(FMT_STRING("{}.{:02}"), v / 10000, p);
                    }

                    default:
                        throw formatted_error("MONEYN has unexpected length {}.", d.length());
                }

            case sql_type::MONEY: {
                auto v = *(int64_t*)d.data();

                v = (v >> 32) | ((v & 0xffffffff) << 32);

                int16_t p = (int16_t)(v % 10000);

                if (p < 0)
                    p = -p;

                return fmt::format(FMT_STRING("{}.{:04}"), v / 10000, p);
            }

            case sql_type::SMALLMONEY: {
                auto v = *(int32_t*)d.data();

                int16_t p = (int16_t)(v % 10000);

                if (p < 0)
                    p = -p;

                return fmt::format(FMT_STRING("{}.{:02}"), v / 10000, p);
            }

            case sql_type::UNIQUEIDENTIFIER:
                return fmt::format(FMT_STRING("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}"),
                                   *(uint32_t*)d.data(), *(uint16_t*)(d.data() + 4), *(uint16_t*)(d.data() + 6),
                                   (uint8_t)d[8], (uint8_t)d[9], (uint8_t)d[10], (uint8_t)d[11], (uint8_t)d[12],
                                   (uint8_t)d[13], (uint8_t)d[14], (uint8_t)d[15]);

            default:
                throw formatted_error("Cannot convert {} to string", type2);
        }
    }

    value::operator u16string() const {
        if (type == sql_type::NVARCHAR || type == sql_type::NCHAR || type == sql_type::NTEXT || type == sql_type::XML)
            return u16string(u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t)));
        else
            return utf8_to_utf16(operator string()); // FIXME - VARCHARs might not be valid UTF-8
    }

    value::operator int64_t() const {
        auto type2 = type;
        string_view d = val;

        if (is_null)
            return 0;

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1 + propbytes);
        }

        switch (type2) {
            case sql_type::TINYINT:
                return *(uint8_t*)d.data();

            case sql_type::SMALLINT:
                return *(int16_t*)d.data();

            case sql_type::INT:
                return *(int32_t*)d.data();

            case sql_type::BIGINT:
                return *(int64_t*)d.data();

            case sql_type::INTN:
                switch (d.length()) {
                    case 1:
                        return *(uint8_t*)d.data();

                    case 2:
                        return *(int16_t*)d.data();

                    case 4:
                        return *(int32_t*)d.data();

                    case 8:
                        return *(int64_t*)d.data();

                    default:
                        throw formatted_error("INTN has unexpected length {}.", d.length());
                }

            case sql_type::REAL:
                return (int64_t)*(float*)d.data();

            case sql_type::FLOAT:
                return (int64_t)*(double*)d.data();

            case sql_type::FLTN:
                switch (d.length()) {
                    case sizeof(float):
                        return (int64_t)*(float*)d.data();

                    case sizeof(double):
                        return (int64_t)*(double*)d.data();

                    default:
                        throw formatted_error("FLTN has unexpected length {}.", d.length());
                }

            case sql_type::BITN:
            case sql_type::BIT:
                return d[0] != 0 ? 1 : 0;

            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                if (d.empty())
                    return 0;

                bool first = true;

                for (auto c : d) {
                    if (c == '-') {
                        if (!first)
                            throw formatted_error("Cannot convert string \"{}\" to integer", d);
                    } else if (c < '0' || c > '9')
                        throw formatted_error("Cannot convert string \"{}\" to integer", d);

                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(d.data(), d.data() + d.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error("Cannot convert string \"{}\" to integer", d);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error("String \"{}\" was too large to convert to BIGINT", d);

                return res;
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                if (d.empty())
                    return 0;

                u16string_view v((char16_t*)d.data(), d.length() / sizeof(char16_t));
                string s;

                s.reserve(v.length());

                bool first = true;

                for (auto c : v) {
                    if (c == u'-') {
                        if (!first)
                            throw formatted_error("Cannot convert string \"{}\" to integer", utf16_to_utf8(v));
                    } else if (c < u'0' || c > u'9')
                        throw formatted_error("Cannot convert string \"{}\" to integer", utf16_to_utf8(v));

                    s += (char)c;
                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error("Cannot convert string \"{}\" to integer", s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error("String \"{}\" was too large to convert to BIGINT", s);

                return res;
            }

            case sql_type::DATETIME:
                return *(int32_t*)d.data(); // MSSQL adds 1 if after midday

            case sql_type::DATETIME2: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                return (int32_t)n - jan1900;
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                return (int32_t)n - jan1900;
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4:
                        return *(uint16_t*)d.data(); // MSSQL adds 1 if after midday

                    case 8:
                        return *(int32_t*)d.data(); // MSSQL adds 1 if after midday

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4:
                return *(uint16_t*)d.data(); // MSSQL adds 1 if after midday

            case sql_type::NUMERIC:
            case sql_type::DECIMAL:
            {
                if (d.empty())
                    return 0;

                bool first = true;
                auto s = (string)*this;

                for (auto c : s) {
                    if (c == '-') {
                        if (!first)
                            throw formatted_error("Cannot convert {} to integer", s);
                    } else if (c == '.')
                        break;
                    else if (c < '0' || c > '9')
                        throw formatted_error("Cannot convert {} to integer", s);

                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error("Cannot convert {} to integer", s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error("{} was too large to convert to BIGINT", s);

                return res;
            }

            case sql_type::MONEYN:
                switch (d.length()) {
                    case sizeof(int64_t): {
                        auto v = *(int64_t*)d.data();

                        v = (v >> 32) | ((v & 0xffffffff) << 32);

                        return v / 10000;
                    }

                    case sizeof(int32_t): {
                        auto v = *(int32_t*)d.data();

                        return v / 10000;
                    }

                    default:
                        throw formatted_error("MONEYN has unexpected length {}", d.length());
                }

            case sql_type::MONEY: {
                auto v = *(int64_t*)d.data();

                v = (v >> 32) | ((v & 0xffffffff) << 32);

                return v / 10000;
            }

            case sql_type::SMALLMONEY: {
                auto v = *(int32_t*)d.data();

                return v / 10000;
            }

            // MSSQL doesn't allow conversion to INT for DATE, TIME, DATETIME2, or DATETIMEOFFSET

            // Not allowing VARBINARY even though MSSQL does

            default:
                throw formatted_error("Cannot convert {} to integer", type2);
        }
    }

    static uint8_t parse_month_name(const string_view& sv) {
        if (sv.length() < 3 || sv.length() > 9)
            return 0;

        string s(sv);

        for (auto& c : s) {
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 'a';
            else if (c < 'a' || c > 'z')
                return 0;
        }

        if (sv.length() == 3) {
            if (s == "jan")
                return 1;
            else if (s == "feb")
                return 2;
            else if (s == "mar")
                return 3;
            else if (s == "apr")
                return 4;
            else if (s == "may")
                return 5;
            else if (s == "jun")
                return 6;
            else if (s == "jul")
                return 7;
            else if (s == "aug")
                return 8;
            else if (s == "sep")
                return 9;
            else if (s == "oct")
                return 10;
            else if (s == "nov")
                return 11;
            else if (s == "dec")
                return 12;

            return 0;
        }

        if (s == "january")
            return 1;
        else if (s == "february")
            return 2;
        else if (s == "march")
            return 3;
        else if (s == "april")
            return 4;
        else if (s == "june")
            return 6;
        else if (s == "july")
            return 7;
        else if (s == "august")
            return 8;
        else if (s == "september")
            return 9;
        else if (s == "october")
            return 10;
        else if (s == "november")
            return 11;
        else if (s == "december")
            return 12;

        return 0;
    }

    static bool is_valid_date(uint16_t y, uint8_t m, uint8_t d) {
        if (y == 0 || m == 0 || d == 0)
            return false;

        if (d > 31)
            return false;

        if (d == 31 && (m == 4 || m == 6 || m == 9 || m == 11))
            return false;

        if (d == 30 && m == 2)
            return false;

        if (d == 29 && m == 2) {
            if (y % 4)
                return false;

            if (!(y % 100) && y % 400)
                return false;
        }

        return true;
    }

    static bool parse_date(string_view& s, uint16_t& y, uint8_t& m, uint8_t& d) {
        cmatch rm;
        static const regex r1("^([0-9]{4})([\\-/]?)([0-9]{2})([\\-/]?)([0-9]{2})");
        static const regex r2("^([0-9]{1,2})([\\-/])([0-9]{1,2})([\\-/])([0-9]{4})");
        static const regex r3("^([0-9]{1,2})([\\-/]?)([0-9]{1,2})([\\-/]?)([0-9]{1,2})");
        static const regex r4("^([0-9]{1,2})([\\-/]?)([A-Za-z]*)([\\-/]?)([0-9]{4})");
        static const regex r5("^([0-9]{1,2})([\\-/]?)([A-Za-z]*)([\\-/]?)([0-9]{2})");
        static const regex r6("^([A-Za-z]*)([\\-/ ]?)([0-9]{1,2})(,?)([\\-/ ])([0-9]{4})");
        static const regex r7("^([A-Za-z]*)([\\-/ ]?)([0-9]{1,2})(,?)([\\-/ ])([0-9]{2})");
        static const regex r8("^([A-Za-z]*)( ?)([0-9]{4})");

        // FIXME - allow option for American-style dates?

        if (regex_search(&s[0], s.data() + s.length(), rm, r1)) { // ISO style
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), y);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), m);
            from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), d);
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r2)) { // dd/mm/yyyy
            from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), y);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), m);
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), d);
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r3)) { // dd/mm/yy
            from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), y);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), m);
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), d);

            if (y >= 50)
                y += 1900;
            else
                y += 2000;
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r4)) { // dd/mon/yyyy
            from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), y);
            m = parse_month_name(rm[3].str());
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), d);
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r5)) { // dd/mon/yy
            from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), y);
            m = parse_month_name(rm[3].str());
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), d);

            if (y >= 50)
                y += 1900;
            else
                y += 2000;
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r6)) { // mon dd, yyyy
            from_chars(rm[6].str().data(), rm[6].str().data() + rm[6].length(), y);
            m = parse_month_name(rm[1].str());
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), d);
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r7)) { // mon dd, yy
            from_chars(rm[6].str().data(), rm[6].str().data() + rm[6].length(), y);
            m = parse_month_name(rm[1].str());
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), d);

            if (y >= 50)
                y += 1900;
            else
                y += 2000;
        } else if (regex_search(&s[0], s.data() + s.length(), rm, r8)) { // mon yyyy
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), y);
            m = parse_month_name(rm[1].str());
            d = 1;
        } else
            return false;

        s = s.substr((size_t)rm[0].length());

        return true;
    }

    static bool parse_time(string_view t, time_t& dur, int16_t& offset) {
        uint8_t h, m, s;
        string_view frac;
        cmatch rm;
        static const regex r1("^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(\\.([0-9]{1,7}))?( *)([AaPp])[Mm]");
        static const regex r2("^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(\\.([0-9]{1,7}))?");
        static const regex r3("^([0-9]{1,2})( *)([AaPp])[Mm]");
        static const regex r4("^([0-9]{1,2}):([0-9]{1,2})( *)([AaPp])[Mm]");
        static const regex r5("^([0-9]{1,2}):([0-9]{1,2})");

        if (regex_search(&t[0], t.data() + t.length(), rm, r1)) { // hh:mm:ss.s am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), s);

            auto ap = rm[7].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;

            frac = rm[5].str();
        } else if (regex_search(&t[0], t.data() + t.length(), rm, r2)) { // hh:mm:ss.s
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), s);

            frac = rm[5].str();
        } else if (regex_search(&t[0], t.data() + t.length(), rm, r3)) { // hh am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            m = 0;
            s = 0;

            auto ap = rm[3].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;
        } else if (regex_search(&t[0], t.data() + t.length(), rm, r4)) { // hh:mm am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            s = 0;

            auto ap = rm[4].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;
        } else if (regex_search(&t[0], t.data() + t.length(), rm, r5)) { // hh:mm
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            s = 0;
        } else
            return false;

        if (h > 24 || m > 60 || s > 60)
            return false;

        dur = chrono::hours{h} + chrono::minutes{m} + chrono::seconds{s};

        if (!frac.empty()) {
            uint32_t v;

            from_chars(frac.data(), frac.data() + frac.length(), v);

            for (auto i = frac.length(); i < 7; i++) {
                v *= 10;
            }

            dur += time_t{v};
        }

        t = t.substr((size_t)rm[0].length());

        while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
            t = t.substr(1);
        }

        if (t.empty()) {
            offset = 0;
            return true;
        }

        bool neg = false;

        if (t[0] == '-') {
            neg = true;
            t = t.substr(1);
        } else if (t[0] == '+')
            t = t.substr(1);

        if (t.empty())
            return false;

        uint16_t offset_hours, offset_mins;

        auto fcr = from_chars(t.data(), t.data() + t.length(), offset_hours);

        if (fcr.ec != errc())
            return false;

        t = t.substr(fcr.ptr - t.data());

        if (t.empty() || t[0] != ':') {
            for (auto c : t) {
                if (c != ' ' && c != '\t')
                    return false;
            }

            if (offset_hours >= 100) {
                offset_mins = offset_hours % 100;
                offset_hours /= 100;
            } else
                offset_mins = 0;

            if (offset_hours >= 24 || offset_mins >= 60)
                return false;

            offset = (int16_t)(((unsigned int)offset_hours * 60) + (unsigned int)offset_mins);

            if (neg)
                offset = -offset;

            return true;
        }

        if (offset_hours >= 24)
            return false;

        t = t.substr(1);

        fcr = from_chars(t.data(), t.data() + t.length(), offset_mins);

        if (fcr.ec != errc())
            return false;

        if (offset_mins >= 60)
            return false;

        offset = (int16_t)(((unsigned int)offset_hours * 60) + (unsigned int)offset_mins);

        if (neg)
            offset = -offset;

        return true;
    }

    static bool parse_datetime(string_view t, uint16_t& y, uint8_t& mon, uint8_t& d, time_t& dur) {
        uint8_t h, min, s;

        {
            cmatch rm;
            static const regex iso_date("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\\.([0-9]{1,7}))?(Z|([+\\-][0-9]{2}:[0-9]{2}))?$");

            if (regex_match(&t[0], t.data() + t.length(), rm, iso_date)) {
                from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), y);
                from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), mon);
                from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), d);
                from_chars(rm[4].str().data(), rm[4].str().data() + rm[4].length(), h);
                from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), min);
                from_chars(rm[6].str().data(), rm[6].str().data() + rm[6].length(), s);

                if (!is_valid_date(y, mon, d) || h >= 24 || min >= 60 || s >= 60)
                    return false;

                dur = chrono::hours{h} + chrono::minutes{min} + chrono::seconds{s};

                if (rm[8].length() != 0) {
                    uint32_t v;

                    from_chars(rm[8].str().data(), rm[8].str().data() + rm[8].length(), v);

                    for (auto i = rm[8].length(); i < 7; i++) {
                        v *= 10;
                    }

                    dur += time_t{v};
                }

                return true;
            }
        }

        if (parse_date(t, y, mon, d)) {
            if (!is_valid_date(y, mon, d))
                return false;

            if (t.empty()) {
                h = min = s = 0;
                return true;
            }

            if (t.front() != ' ' && t.front() != '\t')
                return false;

            while (t.front() == ' ' || t.front() == '\t') {
                t = t.substr(1);
            }

            int16_t offset;

            if (!parse_time(t, dur, offset))
                return false;

            return true;
        }

        // try to parse solo time

        int16_t offset;

        if (!parse_time(t, dur, offset))
            return false;

        y = 1900;
        mon = 1;
        d = 1;

        return true;
    }

    static bool parse_datetimeoffset(string_view t, uint16_t& y, uint8_t& mon, uint8_t& d, time_t& dur, int16_t& offset) {
        uint8_t h, min, s;

        {
            cmatch rm;
            static const regex iso_date("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\\.([0-9]+))?(Z|([+\\-][0-9]{2}):([0-9]{2}))?$");

            if (regex_match(&t[0], t.data() + t.length(), rm, iso_date)) {
                from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), y);
                from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), mon);
                from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), d);
                from_chars(rm[4].str().data(), rm[4].str().data() + rm[4].length(), h);
                from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), min);
                from_chars(rm[6].str().data(), rm[6].str().data() + rm[6].length(), s);

                if (!is_valid_date(y, mon, d) || h >= 24 || min >= 60 || s >= 60)
                    return false;

                dur = chrono::hours{h} + chrono::minutes{min} + chrono::seconds{s};

                if (rm[8].length() != 0) {
                    uint32_t v;

                    from_chars(rm[8].str().data(), rm[8].str().data() + rm[8].length(), v);

                    for (auto i = rm[8].length(); i < 7; i++) {
                        v *= 10;
                    }

                    dur += time_t{v};
                }

                if (rm[9].str().empty() || rm[9].str() == "Z") {
                    offset = 0;
                    return true;
                }

                int offset_hours;
                unsigned int offset_mins;

                if (rm[10].str().front() == '+')
                    from_chars(rm[10].str().data() + 1, rm[10].str().data() + rm[10].length() - 1, offset_hours);
                else
                    from_chars(rm[10].str().data(), rm[10].str().data() + rm[10].length(), offset_hours);

                from_chars(rm[11].str().data(), rm[11].str().data() + rm[11].length(), offset_mins);

                if (offset_hours < -24 || offset_hours > 24 || offset_mins >= 60)
                    return false;

                offset = (int16_t)(offset_hours * 60);

                if (offset_hours < 0)
                    offset -= (int16_t)offset_mins;
                else
                    offset += (int16_t)offset_mins;

                return true;
            }
        }

        if (parse_date(t, y, mon, d)) {
            if (!is_valid_date(y, mon, d))
                return false;

            if (t.empty()) {
                dur = time_t::zero();
                offset = 0;
                return true;
            }

            if (t.front() != ' ' && t.front() != '\t')
                return false;

            while (t.front() == ' ' || t.front() == '\t') {
                t = t.substr(1);
            }

            if (!parse_time(t, dur, offset) || offset <= -1440 || offset >= 1440)
                return false;

            return true;
        }

        // try to parse solo time

        if (!parse_time(t, dur, offset) || offset <= -1440 || offset >= 1440)
            return false;

        y = 1900;
        mon = 1;
        d = 1;

        return true;
    }

    value::operator chrono::year_month_day() const {
        auto type2 = type;
        string_view d = val;

        if (is_null)
            return chrono::year_month_day{1900y, chrono::January, 1d};

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1 + propbytes);
        }

        switch (type2) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = d;

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return chrono::year_month_day{1900y, chrono::January, 1d};

                time_t dur;

                if (!parse_datetime(t, y, mon, day, dur) || !is_valid_date(y, mon, day))
                    throw formatted_error("Cannot convert string \"{}\" to date", d);

                return chrono::year_month_day{chrono::year{y}, chrono::month{mon}, chrono::day{day}};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return chrono::year_month_day{1900y, chrono::January, 1d};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                auto sv = string_view(t2);
                time_t dur;

                if (!parse_datetime(sv, y, mon, day, dur) || !is_valid_date(y, mon, day))
                    throw formatted_error("Cannot convert string \"{}\" to date", utf16_to_utf8(u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t))));

                return chrono::year_month_day{chrono::year{y}, chrono::month{mon}, chrono::day{day}};
            }

            case sql_type::DATE: {
                uint32_t n = 0;

                memcpy(&n, d.data(), 3);

                return num_to_ymd(n - jan1900);
            }

            case sql_type::DATETIME:
                return num_to_ymd(*(int32_t*)d.data());

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4:
                        return num_to_ymd(*(uint16_t*)d.data());

                    case 8:
                        return num_to_ymd(*(int32_t*)d.data());

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4:
                return num_to_ymd(*(uint16_t*)d.data());

            case sql_type::DATETIME2: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                return num_to_ymd((int32_t)n - jan1900);
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                return num_to_ymd((int32_t)n - jan1900);
            }

            // MSSQL doesn't allow conversion to DATE for integers, floats, BITs, or TIME

            case sql_type::TINYINT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::BIGINT:
            case sql_type::INTN: {
                auto n = (int64_t)*this;

                throw formatted_error("Cannot convert integer {} to std::chrono::year_month_day", n);
            }

            default:
                throw formatted_error("Cannot convert {} to std::chrono::year_month_day", type2);
        }
    }

    value::operator time_t() const {
        auto type2 = type;
        unsigned int max_length2 = max_length;
        string_view d = val;

        if (is_null)
            return time_t::zero();

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1);

            switch (type2) {
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    max_length2 = d[0];
                    break;

                default:
                    break;
            }

            d = d.substr(propbytes);
        }

        switch (type2) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = d;

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1, t.length() - 1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return time_t::zero();

                time_t dur;

                if (!parse_datetime(t, y, mon, day, dur))
                    throw formatted_error("Cannot convert string \"{}\" to time", d);

                return dur;
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1, t.length() - 1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return time_t::zero();

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                time_t dur;

                if (!parse_datetime(t2, y, mon, day, dur))
                    throw formatted_error("Cannot convert string \"{}\" to time", utf16_to_utf8(u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t))));

                return dur;
            }

            case sql_type::TIME: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length()));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return time_t(ticks);
            }

            case sql_type::DATETIME: {
                auto v = *(uint32_t*)(d.data() + sizeof(int32_t));
                auto dur = chrono::duration<int64_t, ratio<1, 300>>(v);

                return chrono::duration_cast<time_t>(dur);
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto v = *(uint16_t*)(d.data() + sizeof(uint16_t));
                        auto dur = chrono::minutes(v);

                        return chrono::duration_cast<time_t>(dur);
                    }

                    case 8: {
                        auto v = *(uint32_t*)(d.data() + sizeof(int32_t));
                        auto dur = chrono::duration<int64_t, ratio<1, 300>>(v);

                        return chrono::duration_cast<time_t>(dur);
                    }

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4: {
                auto v = *(uint16_t*)(d.data() + sizeof(uint16_t));
                auto dur = chrono::minutes(v);

                return chrono::duration_cast<time_t>(dur);
            }

            case sql_type::DATETIME2: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return time_t(ticks);
            }

            case sql_type::DATETIMEOFFSET: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return time_t(ticks);
            }

            // MSSQL doesn't allow conversion to TIME for integers, floats, BITs, or DATE

            default:
                throw formatted_error("Cannot convert {} to std::chrono::duration", type2);
        }
    }

    value::operator datetime() const {
        auto type2 = type;
        unsigned int max_length2 = max_length;
        string_view d = val;

        if (is_null)
            return datetime{1900y, chrono::January, 1d, 0, 0, 0};

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1);

            switch (type2) {
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    max_length2 = d[0];
                    break;

                default:
                    break;
            }

            d = d.substr(propbytes);
        }

        switch (type2) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = d;

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetime{1900y, chrono::January, 1d, 0, 0, 0};

                time_t dur;

                if (!parse_datetime(t, y, mon, day, dur))
                    throw formatted_error("Cannot convert string \"{}\" to datetime", d);

                return datetime{chrono::year{y}, chrono::month{mon}, chrono::day{day}, dur};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                uint16_t y;
                uint8_t mon, day;

                auto t = u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetime{1900y, chrono::January, 1d, 0, 0, 0};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                time_t dur;

                if (!parse_datetime(t2, y, mon, day, dur))
                    throw formatted_error("Cannot convert string \"{}\" to datetime", utf16_to_utf8(u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t))));

                return datetime{chrono::year{y}, chrono::month{mon}, chrono::day{day}, dur};
            }

            case sql_type::DATE: {
                uint32_t n = 0;

                memcpy(&n, d.data(), 3);

                return datetime{num_to_ymd(n - jan1900), time_t(0)};
            }

            case sql_type::TIME: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length()));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return datetime{chrono::year_month_day{1900y, chrono::January, 1d}, time_t(ticks)};
            }

            case sql_type::DATETIME: {
                auto v = *(int32_t*)d.data();
                auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                return datetime{num_to_ymd(v), dur};
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto v = *(uint16_t*)d.data();
                        auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                        auto dur = chrono::minutes(t);

                        return datetime{num_to_ymd(v), dur};
                    }

                    case 8: {
                        auto v = *(int32_t*)d.data();
                        auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                        auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                        return datetime{num_to_ymd(v), dur};
                    }

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4: {
                auto v = *(uint16_t*)d.data();
                auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                auto dur = chrono::minutes(t);

                return datetime{num_to_ymd(v), dur};
            }

            case sql_type::DATETIME2: {
                uint32_t n = 0;
                uint64_t ticks = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return datetime{num_to_ymd((int32_t)n - jan1900), time_t(ticks)};
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;
                uint64_t ticks = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return datetime{num_to_ymd((int32_t)n - jan1900), time_t(ticks)};
            }

            // MSSQL doesn't allow conversion to DATETIME2 for integers, floats, or BIT

            default:
                throw formatted_error("Cannot convert {} to datetime", type2);
        }
    }

    value::operator datetimeoffset() const {
        auto type2 = type;
        unsigned int max_length2 = max_length;
        string_view d = val;

        if (is_null)
            return datetimeoffset{1900y, chrono::January, 1d, 0, 0, 0, 0};

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1);

            switch (type2) {
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    max_length2 = d[0];
                    break;

                default:
                    break;
            }

            d = d.substr(propbytes);
        }

        switch (type2) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                uint16_t y;
                uint8_t mon, day;
                int16_t offset;

                auto t = d;

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetimeoffset{1900y, chrono::January, 1d, 0, 0, 0, 0};

                time_t dur;

                if (!parse_datetimeoffset(t, y, mon, day, dur, offset))
                    throw formatted_error("Cannot convert string \"{}\" to datetimeoffset", d);

                return datetimeoffset{chrono::year{y}, chrono::month{mon}, chrono::day{day}, dur, offset};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                uint16_t y;
                uint8_t mon, day;
                int16_t offset;

                auto t = u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetimeoffset{1900y, chrono::January, 1d, 0, 0, 0, 0};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                time_t dur;

                if (!parse_datetimeoffset(t2, y, mon, day, dur, offset))
                    throw formatted_error("Cannot convert string \"{}\" to datetimeoffset", utf16_to_utf8(u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t))));

                return datetimeoffset{chrono::year{y}, chrono::month{mon}, chrono::day{day}, dur, offset};
            }

            case sql_type::DATE: {
                uint32_t n = 0;

                memcpy(&n, d.data(), 3);

                return datetimeoffset{num_to_ymd(n - jan1900), time_t(0), 0};
            }

            case sql_type::TIME: {
                uint64_t ticks = 0;

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length()));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return datetimeoffset{chrono::year_month_day{1900y, chrono::January, 1d}, time_t(ticks), 0};
            }

            case sql_type::DATETIME: {
                auto v = *(int32_t*)d.data();
                auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                return datetimeoffset{num_to_ymd(v), dur, 0};
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto v = *(uint16_t*)d.data();
                        auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                        auto dur = chrono::minutes(t);

                        return datetimeoffset{num_to_ymd(v), dur, 0};
                    }

                    case 8: {
                        auto v = *(int32_t*)d.data();
                        auto t = *(uint32_t*)(d.data() + sizeof(int32_t));
                        auto dur = chrono::duration<int64_t, ratio<1, 300>>(t);

                        return datetimeoffset{num_to_ymd(v), dur, 0};
                    }

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4: {
                auto v = *(uint16_t*)d.data();
                auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));
                auto dur = chrono::minutes(t);

                return datetimeoffset{num_to_ymd(v), dur, 0};
            }

            case sql_type::DATETIME2: {
                uint32_t n = 0;
                uint64_t ticks = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                return datetimeoffset{num_to_ymd((int32_t)n - jan1900), time_t(ticks), 0};
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;
                uint64_t ticks = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                memcpy(&ticks, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (unsigned int n = 0; n < 7 - max_length2; n++) {
                    ticks *= 10;
                }

                auto offset = *(int16_t*)&d[d.length() - sizeof(int16_t)];

                return datetimeoffset{num_to_ymd((int32_t)n - jan1900), time_t(ticks), offset};
            }

            // MSSQL doesn't allow conversion to DATETIME2 for integers, floats, or BIT

            default:
                throw formatted_error("Cannot convert {} to datetimeoffset", type2);
        }
    }

    value::operator double() const {
        auto type2 = type;
        auto max_length2 = max_length;
        string_view d = val;

        if (is_null)
            return 0;

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1);

            switch (type2) {
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    max_length2 = d[0];
                    break;

                default:
                    break;
            }

            d = d.substr(propbytes);
        }

        switch (type2) {
            case sql_type::TINYINT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::BIGINT:
            case sql_type::INTN:
            case sql_type::BITN:
            case sql_type::BIT:
                return (double)operator int64_t();

            case sql_type::REAL:
                return *(float*)d.data();

            case sql_type::FLOAT:
                return *(double*)d.data();

            case sql_type::FLTN:
                switch (d.length()) {
                    case sizeof(float):
                        return *(float*)d.data();

                    case sizeof(double):
                        return *(double*)d.data();

                    default:
                        throw formatted_error("FLTN has unexpected length {}", d.length());
                }

            case sql_type::VARCHAR:
            case sql_type::CHAR:
            case sql_type::TEXT:
            {
                if (d.empty())
                    return 0.0;

                // from_chars not implemented for double yet as of mingw gcc 11.1
#if 0
                double res;

                auto [p, ec] = from_chars(d.data(), d.data() + d.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error("Cannot convert string \"{}\" to float", d);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error("String \"{}\" was too large to convert to float.", d);

                return res;
#else
                try {
                    return stod(string(d));
                } catch (...) {
                    throw formatted_error("Cannot convert string \"{}\" to float", d);
                }
#endif
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            case sql_type::NTEXT:
            {
                if (d.empty())
                    return 0.0;

                u16string_view v((char16_t*)d.data(), d.length() / sizeof(char16_t));
                string s;

                s.reserve(v.length());

                for (auto c : v) {
                    s += (char)c;
                }

                // from_chars not implemented for double yet as of mingw gcc 11.1
#if 0
                double res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error("Cannot convert string \"{}\" to float", s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error("String \"{}\" was too large to convert to float.", s);

                return res;
#else
                try {
                    return stod(s);
                } catch (...) {
                    throw formatted_error("Cannot convert string \"{}\" to float", s);
                }
#endif
            }

            case sql_type::DATETIME: {
                auto dt = *(int32_t*)d.data();
                auto t = *(uint32_t*)(d.data() + sizeof(int32_t));

                return (double)dt + ((double)t / 25920000.0);
            }

            case sql_type::DATETIME2: {
                uint32_t n = 0;
                uint64_t secs = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                memcpy(&secs, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (auto n = max_length2; n > 0; n--) {
                    secs /= 10;
                }

                return (double)(n - jan1900) + ((double)secs / 86400.0);
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;
                uint64_t secs = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                memcpy(&secs, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (auto n = max_length2; n > 0; n--) {
                    secs /= 10;
                }

                return (double)(n - jan1900) + ((double)secs / 86400.0);
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto dt = *(uint16_t*)d.data();
                        auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));

                        return (double)dt + ((double)t / 1440.0);
                    }

                    case 8: {
                        auto dt = *(int32_t*)d.data();
                        auto t = *(uint32_t*)(d.data() + sizeof(int32_t));

                        return (double)dt + ((double)t / 25920000.0);
                    }

                    default:
                        throw formatted_error("DATETIMN has invalid length {}", d.length());
                }

            case sql_type::DATETIM4: {
                auto dt = *(uint16_t*)d.data();
                auto t = *(uint16_t*)(d.data() + sizeof(uint16_t));

                return (double)dt + ((double)t / 1440.0);
            }

            case sql_type::NUMERIC:
            case sql_type::DECIMAL: {
                auto s = (string)*this;

                try {
                    return stod(s);
                } catch (...) {
                    throw formatted_error("Cannot convert {} to float", s);
                }
            }

            case sql_type::MONEYN:
                switch (d.length()) {
                    case sizeof(int64_t): {
                        auto v = *(int64_t*)d.data();

                        v = (v >> 32) | ((v & 0xffffffff) << 32);

                        return (double)v / 10000.0;
                    }

                    case sizeof(int32_t): {
                        auto v = *(int32_t*)d.data();

                        return (double)v / 10000.0;
                    }

                    default:
                        throw formatted_error("MONEYN has unexpected length {}", d.length());
                }

            case sql_type::MONEY: {
                auto v = *(int64_t*)d.data();

                v = (v >> 32) | ((v & 0xffffffff) << 32);

                return (double)v / 10000.0;
            }

            case sql_type::SMALLMONEY:  {
                auto v = *(int32_t*)d.data();

                return (double)v / 10000.0;
            }

            // MSSQL doesn't allow conversion to FLOAT for DATE, TIME, DATETIME2, DATETIMEOFFSET, or VARBINARY

            default:
                throw formatted_error("Cannot convert {} to float", type2);
        }
    }

    static unsigned int coll_to_cp(const collation& coll) {
        if (coll.sort_id == 0) { // Windows collations
            switch (coll.lcid & 0xffff) {
                case 1054: // th-TH
                    return 874;

                case 1041: // ja-JP
                    return 932;

                case 2052: // zh-CN
                    return 936;

                case 1042: // ko-KR
                    return 949;

                case 1028: // zh-TW
                case 3076: // zh-HK
                case 5124: // zh-MO
                    return 950;

                case 1029: // cs-CZ
                case 1038: // hu-HU
                case 1045: // pl-PL
                case 1048: // ro-RO
                case 1050: // hr-HR
                case 1051: // sk-SK
                case 1052: // sq-AL
                case 1060: // sl-SI
                case 1090: // tk-TM
                case 2074: // sr-Latn-CS
                case 5146: // bs-Latn-BA
                    return 1250;

                case 1049: // ru-RU
                case 1058: // uk-UA
                case 1071: // mk-MK
                case 1087: // kk-KZ
                case 1092: // tt-RU
                case 1133: // ba-RU
                case 1157: // sah-RU
                case 2092: // az-Cyrl-AZ
                case 3098: // sr-Cyrl-CS
                case 8218: // bs-Cyrl-BA
                    return 1251;

                case 1030: // da-DK
                case 1031: // de-DE
                case 1033: // en-US
                case 1034: // es-ES_tradnl
                case 1035: // fi-FI
                case 1036: // fr-FR
                case 1039: // is-IS
                case 1047: // rm-CH
                case 1044: // nb-NO
                case 1070: // hsb-DE
                case 1079: // ka-GE
                case 1083: // se-NO
                case 1106: // cy-GB
                case 1122: // fy-NL
                case 1146: // arn-CL
                case 1148: // moh-CA
                case 1150: // br-FR
                case 1155: // co-FR
                case 2107: // se-SE
                case 2143: // tzm-Latn-DZ
                case 3082: // es-ES
                    return 1252;

                case 1032: // el-GR
                    return 1253;

                case 1055: // tr-TR
                case 1068: // az-Latn-AZ
                case 1091: // uz-Latn-UZ
                    return 1254;

                case 1037: // he-IL
                    return 1255;

                case 1025: // ar-SA
                case 1056: // ur-PK
                case 1065: // fa-IR
                case 1152: // ug-CN
                case 1164: // prs-AF
                    return 1256;

                case 1061: // et-EE
                case 1062: // lv-LV
                case 1063: // lt-LT
                    return 1257;

                case 1066: // vi-VN
                    return 1258;

                default:
                    throw formatted_error("Could not map LCID {} to codepage.", coll.lcid);
            }
        } else { // SQL collations
            switch (coll.sort_id) {
                case 30:
                case 31:
                case 32:
                case 33:
                case 34:
                    return 437;

                case 40:
                case 41:
                case 42:
                case 44:
                case 49:
                case 55:
                case 56:
                case 57:
                case 58:
                case 59:
                case 60:
                case 61:
                    return 850;

                case 80:
                case 81:
                case 82:
                case 83:
                case 84:
                case 85:
                case 86:
                case 87:
                case 88:
                case 89:
                case 90:
                case 91:
                case 92:
                case 93:
                case 94:
                case 95:
                case 96:
                    return 1250;

                case 104:
                case 105:
                case 106:
                case 107:
                case 108:
                    return 1251;

                case 51:
                case 52:
                case 53:
                case 54:
                case 183:
                case 184:
                case 185:
                case 186:
                    return 1252;

                case 112:
                case 113:
                case 114:
                case 121:
                case 124:
                    return 1253;

                case 128:
                case 129:
                case 130:
                    return 1254;

                case 136:
                case 137:
                case 138:
                    return 1255;

                case 144:
                case 145:
                case 146:
                    return 1256;

                case 152:
                case 153:
                case 154:
                case 155:
                case 156:
                case 157:
                case 158:
                case 159:
                case 160:
                    return 1257;

                default:
                    throw formatted_error("Could not map sort ID {} to codepage.", coll.sort_id);
            }
        }
    }

    static string decode_charset(const string_view& s, unsigned int codepage) {
        string ret;

        if (s.empty())
            return "";

        u16string us;

#ifdef _WIN32
        auto len = MultiByteToWideChar(codepage, 0, s.data(), (int)s.length(), nullptr, 0);

        if (len == 0)
            throw runtime_error("MultiByteToWideChar 1 failed.");

        us.resize(len);

        len = MultiByteToWideChar(codepage, 0, s.data(), (int)s.length(), (wchar_t*)us.data(), len);

        if (len == 0)
            throw runtime_error("MultiByteToWideChar 2 failed.");
#else
        UErrorCode status = U_ZERO_ERROR;
        const char* cp;

        switch (codepage) {
            case 437:
                cp = "ibm-437_P100-1995";
                break;

            case 850:
                cp = "ibm-850_P100-1995";
                break;

            case 874:
                cp = "windows-874-2000";
                break;

            case 932:
                cp = "ibm-942_P12A-1999";
                break;

            case 936:
                cp = "ibm-1386_P100-2001";
                break;

            case 949:
                cp = "windows-949-2000";
                break;

            case 950:
                cp = "windows-950-2000";
                break;

            case 1250:
                cp = "ibm-1250_P100-1995";
                break;

            case 1251:
                cp = "ibm-1251_P100-1995";
                break;

            case 1252:
                cp = "ibm-5348_P100-1997";
                break;

            case 1253:
                cp = "ibm-1253_P100-1995";
                break;

            case 1254:
                cp = "ibm-1254_P100-1995";
                break;

            case 1255:
                cp = "ibm-1255_P100-1995";
                break;

            case 1256:
                cp = "ibm-1256_P110-1997";
                break;

            case 1257:
                cp = "ibm-1257_P100-1995";
                break;

            case 1258:
                cp = "ibm-1258_P100-1997";
                break;

            default:
                throw formatted_error("Could not find ICU name for Windows code page {}.", codepage);
        }

        UConverter* conv = ucnv_open(cp, &status);

        if (U_FAILURE(status))
            throw formatted_error("ucnv_open failed for code page {} ({})", cp, u_errorName(status));

        us.resize(s.length() * 2); // sic - each input byte might expand to 2 char16_ts

        auto len = ucnv_toUChars(conv, us.data(), (int32_t)us.length() / sizeof(char16_t), s.data(), (int32_t)s.length(), &status);

        if (us.length() > (uint32_t)len)
            us = us.substr(0, (uint32_t)len);

        ucnv_close(conv);
#endif

        return utf16_to_utf8(us);
    }

    static void value_cp_to_utf8(value& v, const collation& coll) {
        auto cp = coll_to_cp(coll);

        if (cp == CP_UTF8)
            return;

        auto str = decode_charset(v.val, cp);

        v.val = str;
    }

    static void handle_row_col(value& col, enum sql_type type, unsigned int max_length, const collation& coll, string_view& sv) {
        switch (type) {
            case sql_type::SQL_NULL:
            case sql_type::TINYINT:
            case sql_type::BIT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::DATETIM4:
            case sql_type::REAL:
            case sql_type::MONEY:
            case sql_type::DATETIME:
            case sql_type::FLOAT:
            case sql_type::SMALLMONEY:
            case sql_type::BIGINT:
            {
                auto len = fixed_len_size(type);

                col.val.resize(len);

                if (sv.length() < len)
                    throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), len);

                memcpy(col.val.data(), sv.data(), len);

                sv = sv.substr(len);

                break;
            }

            case sql_type::UNIQUEIDENTIFIER:
            case sql_type::INTN:
            case sql_type::DECIMAL:
            case sql_type::NUMERIC:
            case sql_type::BITN:
            case sql_type::FLTN:
            case sql_type::MONEYN:
            case sql_type::DATETIMN:
            case sql_type::DATE:
            case sql_type::TIME:
            case sql_type::DATETIME2:
            case sql_type::DATETIMEOFFSET:
            {
                if (sv.length() < sizeof(uint8_t))
                    throw formatted_error("Short ROW message ({} bytes left, expected at least 1).", sv.length());

                auto len = *(uint8_t*)sv.data();

                sv = sv.substr(1);

                col.val.resize(len);
                col.is_null = len == 0;

                if (sv.length() < len)
                    throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), len);

                memcpy(col.val.data(), sv.data(), len);
                sv = sv.substr(len);

                break;
            }

            case sql_type::VARCHAR:
            case sql_type::NVARCHAR:
            case sql_type::VARBINARY:
            case sql_type::CHAR:
            case sql_type::NCHAR:
            case sql_type::BINARY:
            case sql_type::XML:
                if (max_length == 0xffff || type == sql_type::XML) {
                    if (sv.length() < sizeof(uint64_t))
                        throw formatted_error("Short ROW message ({} bytes left, expected at least 8).", sv.length());

                    auto len = *(uint64_t*)sv.data();

                    sv = sv.substr(sizeof(uint64_t));

                    col.val.clear();

                    if (len == 0xffffffffffffffff) {
                        col.is_null = true;
                        return;
                    }

                    col.is_null = false;

                    if (len != 0xfffffffffffffffe) // unknown length
                        col.val.reserve(len);

                    do {
                        if (sv.length() < sizeof(uint32_t))
                            throw formatted_error("Short ROW message ({} bytes left, expected at least 4).", sv.length());

                        auto chunk_len = *(uint32_t*)sv.data();

                        sv = sv.substr(sizeof(uint32_t));

                        if (chunk_len == 0)
                            break;

                        if (sv.length() < chunk_len)
                            throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), chunk_len);

                        col.val += sv.substr(0, chunk_len);
                        sv = sv.substr(chunk_len);
                    } while (true);
                } else {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short ROW message ({} bytes left, expected at least 2).", sv.length());

                    auto len = *(uint16_t*)sv.data();

                    sv = sv.substr(sizeof(uint16_t));

                    if (len == 0xffff) {
                        col.is_null = true;
                        return;
                    }

                    col.val.resize(len);
                    col.is_null = false;

                    if (sv.length() < len)
                        throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), len);

                    memcpy(col.val.data(), sv.data(), len);
                    sv = sv.substr(len);
                }

                if ((type == sql_type::VARCHAR || type == sql_type::CHAR)) {
                    if (coll.utf8)
                        col.utf8 = true;
                    else
                        value_cp_to_utf8(col, coll);
                }

                break;

            case sql_type::SQL_VARIANT:
            {
                if (sv.length() < sizeof(uint32_t))
                    throw formatted_error("Short ROW message ({} bytes left, expected at least 4).", sv.length());

                auto len = *(uint32_t*)sv.data();

                sv = sv.substr(sizeof(uint32_t));

                col.val.resize(len);
                col.is_null = len == 0xffffffff;

                if (!col.is_null) {
                    if (sv.length() < len)
                        throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), len);

                    memcpy(col.val.data(), sv.data(), len);
                    sv = sv.substr(len);
                }

                break;
            }

            case sql_type::IMAGE:
            case sql_type::NTEXT:
            case sql_type::TEXT:
            {
                // text pointer

                if (sv.length() < sizeof(uint8_t))
                    throw formatted_error("Short ROW message ({} bytes left, expected at least 1).", sv.length());

                auto textptrlen = (uint8_t)sv[0];

                sv = sv.substr(1);

                if (sv.length() < textptrlen)
                    throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), textptrlen);

                sv = sv.substr(textptrlen);

                col.is_null = textptrlen == 0;

                if (!col.is_null) {
                    // timestamp

                    if (sv.length() < 8)
                        throw formatted_error("Short ROW message ({} bytes left, expected at least 8).", sv.length());

                    sv = sv.substr(8);

                    // data

                    if (sv.length() < sizeof(uint32_t))
                        throw formatted_error("Short ROW message ({} bytes left, expected at least 4).", sv.length());

                    auto len = *(uint32_t*)sv.data();

                    sv = sv.substr(sizeof(uint32_t));

                    col.val.resize(len);
                    col.is_null = len == 0xffffffff;

                    if (!col.is_null) {
                        if (sv.length() < len)
                            throw formatted_error("Short ROW message ({} bytes left, expected at least {}).", sv.length(), len);

                        memcpy(col.val.data(), sv.data(), len);
                        sv = sv.substr(len);
                    }
                }

                break;
            }

            default:
                throw formatted_error("Unhandled type {} in ROW message.", type);
        }
    }

    void rpc::do_rpc(tds& conn, const string_view& name) {
        do_rpc(conn, utf8_to_utf16(name));
    }

    void rpc::do_rpc(tds& conn, const u16string_view& name) {
        size_t bufsize;

        this->name = name;

        bufsize = sizeof(tds_all_headers) + sizeof(uint16_t) + (name.length() * sizeof(uint16_t)) + sizeof(uint16_t);

        for (const auto& p : params) {
            switch (p.type) {
                case sql_type::SQL_NULL:
                case sql_type::TINYINT:
                case sql_type::BIT:
                case sql_type::SMALLINT:
                case sql_type::INT:
                case sql_type::DATETIM4:
                case sql_type::REAL:
                case sql_type::MONEY:
                case sql_type::DATETIME:
                case sql_type::FLOAT:
                case sql_type::SMALLMONEY:
                case sql_type::BIGINT:
                    bufsize += sizeof(tds_param_header) + fixed_len_size(p.type);
                    break;

                case sql_type::DATETIMN:
                case sql_type::DATE:
                    bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length());
                    break;

                case sql_type::UNIQUEIDENTIFIER:
                case sql_type::MONEYN:
                    bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length());
                    break;

                case sql_type::INTN:
                case sql_type::FLTN:
                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                case sql_type::BITN:
                    bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length()) + sizeof(uint8_t);
                    break;

                case sql_type::NVARCHAR:
                    if (p.is_null)
                        bufsize += sizeof(tds_VARCHAR_param);
                    else if (p.val.length() > 8000) // MAX
                        bufsize += sizeof(tds_VARCHAR_MAX_param) + p.val.length() + sizeof(uint32_t);
                    else
                        bufsize += sizeof(tds_VARCHAR_param) + p.val.length();

                    break;

                case sql_type::VARCHAR:
                    if (p.is_null)
                        bufsize += sizeof(tds_VARCHAR_param);
                    else if (p.utf8 && !conn.impl->has_utf8) {
                        auto s = utf8_to_utf16(p.val);

                        if ((s.length() * sizeof(char16_t)) > 8000) // MAX
                            bufsize += sizeof(tds_VARCHAR_MAX_param) + (s.length() * sizeof(char16_t)) + sizeof(uint32_t);
                        else
                            bufsize += sizeof(tds_VARCHAR_param) + (s.length() * sizeof(char16_t));
                    } else if (p.val.length() > 8000) // MAX
                        bufsize += sizeof(tds_VARCHAR_MAX_param) + p.val.length() + sizeof(uint32_t);
                    else
                        bufsize += sizeof(tds_VARCHAR_param) + p.val.length();

                    break;

                case sql_type::VARBINARY:
                    if (!p.is_null && p.val.length() > 8000) // MAX
                        bufsize += sizeof(tds_VARBINARY_MAX_param) + p.val.length() + sizeof(uint32_t);
                    else
                        bufsize += sizeof(tds_VARBINARY_param) + (p.is_null ? 0 : p.val.length());

                    break;

                case sql_type::XML:
                    if (p.is_null)
                        bufsize += offsetof(tds_XML_param, chunk_length);
                    else
                        bufsize += sizeof(tds_XML_param) + p.val.length() + sizeof(uint32_t);
                break;

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    bufsize += sizeof(tds_param_header) + 4;

                    if (!p.is_null)
                        bufsize += p.val.length();
                break;

                case sql_type::IMAGE:
                    bufsize += sizeof(tds_param_header) + sizeof(uint32_t) + sizeof(uint32_t);

                    if (!p.is_null)
                        bufsize += p.val.length();
                break;

                case sql_type::TEXT:
                case sql_type::NTEXT:
                    bufsize += sizeof(tds_param_header) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(collation);

                    if (!p.is_null)
                        bufsize += p.val.length();
                break;

                default:
                    throw formatted_error("Unhandled type {} in RPC params.", p.type);
            }
        }

        vector<uint8_t> buf(bufsize);

        auto all_headers = (tds_all_headers*)&buf[0];

        all_headers->total_size = sizeof(tds_all_headers);
        all_headers->size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
        all_headers->trans_desc.type = 2; // transaction descriptor
        all_headers->trans_desc.descriptor = conn.impl->trans_id;
        all_headers->trans_desc.outstanding = 1;

        auto ptr = (uint8_t*)&all_headers[1];

        *(uint16_t*)ptr = (uint16_t)name.length();
        ptr += sizeof(uint16_t);

        memcpy(ptr, name.data(), name.length() * sizeof(char16_t));
        ptr += name.length() * sizeof(char16_t);

        *(uint16_t*)ptr = 0; // flags
        ptr += sizeof(uint16_t);

        for (const auto& p : params) {
            auto h = (tds_param_header*)ptr;

            h->name_len = 0;
            h->flags = p.is_output ? 1 : 0;
            h->type = p.type;

            ptr += sizeof(tds_param_header);

            switch (p.type) {
                case sql_type::SQL_NULL:
                case sql_type::TINYINT:
                case sql_type::BIT:
                case sql_type::SMALLINT:
                case sql_type::INT:
                case sql_type::DATETIM4:
                case sql_type::REAL:
                case sql_type::MONEY:
                case sql_type::DATETIME:
                case sql_type::FLOAT:
                case sql_type::SMALLMONEY:
                case sql_type::BIGINT:
                    memcpy(ptr, p.val.data(), p.val.length());

                    ptr += p.val.length();

                    break;

                case sql_type::INTN:
                case sql_type::FLTN:
                case sql_type::BITN:
                    *ptr = (uint8_t)p.val.length();
                    ptr++;

                    if (p.is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)p.val.length();
                        ptr++;
                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }

                    break;

                case sql_type::TIME:
                case sql_type::DATETIME2:
                case sql_type::DATETIMEOFFSET:
                    *ptr = (uint8_t)p.max_length;
                    ptr++;

                    if (p.is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)p.val.length();
                        ptr++;
                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }

                    break;

                case sql_type::DATETIMN:
                case sql_type::DATE:
                    if (p.is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)p.val.length();
                        ptr++;
                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }

                    break;

                case sql_type::UNIQUEIDENTIFIER:
                case sql_type::MONEYN:
                    *ptr = (uint8_t)p.max_length;
                    ptr++;

                    if (p.is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)p.val.length();
                        ptr++;
                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }

                    break;

                case sql_type::NVARCHAR:
                {
                    auto h2 = (tds_VARCHAR_param*)h;

                    if (p.is_null || p.val.empty())
                        h2->max_length = sizeof(char16_t);
                    else if (p.val.length() > 8000) // MAX
                        h2->max_length = 0xffff;
                    else
                        h2->max_length = (uint16_t)p.val.length();

                    h2->collation.lcid = 0x0409; // en-US
                    h2->collation.ignore_case = 1;
                    h2->collation.ignore_accent = 0;
                    h2->collation.ignore_width = 1;
                    h2->collation.ignore_kana = 1;
                    h2->collation.binary = 0;
                    h2->collation.binary2 = 0;
                    h2->collation.utf8 = 0;
                    h2->collation.reserved = 0;
                    h2->collation.version = 0;
                    h2->collation.sort_id = 52; // nocase.iso

                    if (!p.is_null && p.val.length() > 8000) { // MAX
                        auto h3 = (tds_VARCHAR_MAX_param*)h2;

                        h3->length = h3->chunk_length = (uint32_t)p.val.length();

                        ptr += sizeof(tds_VARCHAR_MAX_param) - sizeof(tds_param_header);

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();

                        *(uint32_t*)ptr = 0; // last chunk
                        ptr += sizeof(uint32_t);
                    } else {
                        h2->length = (uint16_t)(p.is_null ? 0xffff : p.val.length());

                        ptr += sizeof(tds_VARCHAR_param) - sizeof(tds_param_header);

                        if (!p.is_null) {
                            memcpy(ptr, p.val.data(), h2->length);
                            ptr += h2->length;
                        }
                    }

                    break;
                }

                case sql_type::VARCHAR:
                {
                    auto h2 = (tds_VARCHAR_param*)h;
                    string_view sv = p.val;
                    u16string tmp;

                    if (!p.is_null && !p.val.empty() && p.utf8 && !conn.impl->has_utf8) {
                        h->type = sql_type::NVARCHAR;
                        tmp = utf8_to_utf16(p.val);
                        sv = string_view((char*)tmp.data(), tmp.length() * sizeof(char16_t));
                    }

                    if (p.is_null || p.val.empty())
                        h2->max_length = sizeof(char16_t);
                    else if (sv.length() > 8000) // MAX
                        h2->max_length = 0xffff;
                    else
                        h2->max_length = (uint16_t)sv.length();

                    h2->collation.lcid = 0x0409; // en-US
                    h2->collation.ignore_case = 1;
                    h2->collation.ignore_accent = 0;
                    h2->collation.ignore_width = 1;
                    h2->collation.ignore_kana = 1;
                    h2->collation.binary = 0;
                    h2->collation.binary2 = 0;
                    h2->collation.utf8 = p.utf8 && conn.impl->has_utf8 ? 1 : 0;
                    h2->collation.reserved = 0;
                    h2->collation.version = 2;
                    h2->collation.sort_id = 0;

                    if (!p.is_null && sv.length() > 8000) { // MAX
                        auto h3 = (tds_VARCHAR_MAX_param*)h2;

                        h3->length = h3->chunk_length = (uint32_t)sv.length();

                        ptr += sizeof(tds_VARCHAR_MAX_param) - sizeof(tds_param_header);

                        memcpy(ptr, sv.data(), sv.length());
                        ptr += sv.length();

                        *(uint32_t*)ptr = 0; // last chunk
                        ptr += sizeof(uint32_t);
                    } else {
                        h2->length = (uint16_t)(p.is_null ? 0xffff : sv.length());

                        ptr += sizeof(tds_VARCHAR_param) - sizeof(tds_param_header);

                        if (!p.is_null) {
                            memcpy(ptr, sv.data(), h2->length);
                            ptr += h2->length;
                        }
                    }

                    break;
                }

                case sql_type::VARBINARY: {
                    auto h2 = (tds_VARBINARY_param*)h;

                    if (p.is_null || p.val.empty())
                        h2->max_length = 1;
                    else if (p.val.length() > 8000) // MAX
                        h2->max_length = 0xffff;
                    else
                        h2->max_length = (uint16_t)p.val.length();

                    if (!p.is_null && p.val.length() > 8000) { // MAX
                        auto h3 = (tds_VARBINARY_MAX_param*)h2;

                        h3->length = h3->chunk_length = (uint32_t)p.val.length();

                        ptr += sizeof(tds_VARBINARY_MAX_param) - sizeof(tds_param_header);

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();

                        *(uint32_t*)ptr = 0; // last chunk
                        ptr += sizeof(uint32_t);
                    } else {
                        h2->length = (uint16_t)(p.is_null ? 0xffff : p.val.length());

                        ptr += sizeof(tds_VARBINARY_param) - sizeof(tds_param_header);

                        if (!p.is_null) {
                            memcpy(ptr, p.val.data(), h2->length);
                            ptr += h2->length;
                        }
                    }

                    break;
                }

                case sql_type::XML: {
                    auto h2 = (tds_XML_param*)h;

                    h2->flags = 0;

                    if (p.is_null)
                        h2->length = 0xffffffffffffffff;
                    else {
                        h2->length = h2->chunk_length = (uint32_t)p.val.length();

                        ptr += sizeof(tds_XML_param) - sizeof(tds_param_header);

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();

                        *(uint32_t*)ptr = 0; // last chunk
                        ptr += sizeof(uint32_t);
                    }

                    break;
                }

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    *ptr = (uint8_t)p.max_length; ptr++;
                    *ptr = p.precision; ptr++;
                    *ptr = p.scale; ptr++;

                    if (p.is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)p.val.length();
                        ptr++;

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }
                break;

                case sql_type::IMAGE:
                    *(uint32_t*)ptr = 0x7fffffff;
                    ptr += sizeof(uint32_t);

                    if (p.is_null) {
                        *(uint32_t*)ptr = 0xffffffff;
                        ptr += sizeof(uint32_t);
                    } else {
                        *(uint32_t*)ptr = (uint32_t)p.val.length();
                        ptr += sizeof(uint32_t);

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }
                break;

                case sql_type::TEXT:
                case sql_type::NTEXT:
                {
                    *(uint32_t*)ptr = 0x7fffffff;
                    ptr += sizeof(uint32_t);

                    auto col = (collation*)ptr;

                    col->lcid = 0x0409; // en-US
                    col->ignore_case = 1;
                    col->ignore_accent = 0;
                    col->ignore_width = 1;
                    col->ignore_kana = 1;
                    col->binary = 0;
                    col->binary2 = 0;
                    col->utf8 = 0;
                    col->reserved = 0;
                    col->version = 0;
                    col->sort_id = 52; // nocase.iso

                    ptr += sizeof(collation);

                    if (p.is_null) {
                        *(uint32_t*)ptr = 0xffffffff;
                        ptr += sizeof(uint32_t);
                    } else {
                        *(uint32_t*)ptr = (uint32_t)p.val.length();
                        ptr += sizeof(uint32_t);

                        memcpy(ptr, p.val.data(), p.val.length());
                        ptr += p.val.length();
                    }

                    break;
                }

                default:
                    throw formatted_error("Unhandled type {} in RPC params.", p.type);
            }
        }

        conn.impl->send_msg(tds_msg::rpc, string_view((char*)buf.data(), buf.size()));

        wait_for_packet();
    }

    rpc::~rpc() {
        if (finished)
            return;

        try {
            conn.impl->send_msg(tds_msg::attention_signal, string_view());

            while (!finished) {
                wait_for_packet();
            }

            // wait for attention acknowledgement

            bool ack = false;

            do {
                enum tds_msg type;
                string payload;

                conn.impl->wait_for_msg(type, payload);
                // FIXME - timeout

                if (type != tds_msg::tabular_result)
                    continue;

                auto sv = string_view(payload);
                parse_tokens(sv, tokens, buf_columns);

                while (!tokens.empty()) {
                    auto t = move(tokens.front());

                    tokens.pop_front();

                    auto type = (token)t[0];

                    switch (type) {
                        case token::DONE:
                        case token::DONEINPROC:
                        case token::DONEPROC: {
                            auto m = (tds_done_msg*)&t[1];

                            if (m->status & 0x20)
                                ack = true;

                            break;
                        }

                        default:
                            break;
                    }
                }
            } while (!ack);
        } catch (...) {
            // can't throw in destructor
        }
    }

    void rpc::wait_for_packet() {
        enum tds_msg type;
        string payload;
        bool last_packet;

        conn.impl->wait_for_msg(type, payload, &last_packet);
        // FIXME - timeout

        if (type != tds_msg::tabular_result)
            throw formatted_error("Received message type {}, expected tabular_result", (int)type);

        buf += payload;

        {
            string_view sv = buf;

            parse_tokens(sv, tokens, buf_columns);

            buf = sv;
        }

        if (last_packet && !buf.empty())
            throw formatted_error("Data remaining in buffer");

        while (!tokens.empty()) {
            auto t = move(tokens.front());

            tokens.pop_front();

            string_view sv = t;

            auto type = (token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case token::DONE:
                case token::DONEINPROC:
                case token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                    if (conn.impl->count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            conn.impl->count_handler(msg->rowcount, msg->curcmd);
                    }

                    // FIXME - handle RPCs that return multiple row sets?
                break;

                case token::INFO:
                case token::TDS_ERROR:
                case token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                    if (type == token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);
                        else
                            throw formatted_error("RPC {} failed: {}", utf16_to_utf8(name), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    break;
                }

                case token::RETURNSTATUS:
                {
                    if (sv.length() < sizeof(int32_t))
                        throw formatted_error("Short RETURNSTATUS message ({} bytes, expected 4).", sv.length());

                    return_status = *(int32_t*)&sv[0];

                    break;
                }

                case token::COLMETADATA:
                {
                    if (sv.length() < 4)
                        throw formatted_error("Short COLMETADATA message ({} bytes, expected at least 4).", sv.length());

                    auto num_columns = *(uint16_t*)&sv[0];

                    if (num_columns == 0)
                        break;

                    cols.clear();
                    cols.reserve(num_columns);

                    size_t len = sizeof(uint16_t);
                    string_view sv2 = sv;

                    sv2 = sv2.substr(sizeof(uint16_t));

                    for (unsigned int i = 0; i < num_columns; i++) {
                        if (sv2.length() < sizeof(tds_colmetadata_col))
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(tds_colmetadata_col));

                        auto& c = *(tds_colmetadata_col*)&sv2[0];

                        len += sizeof(tds_colmetadata_col);
                        sv2 = sv2.substr(sizeof(tds_colmetadata_col));

                        cols.emplace_back();

                        auto& col = cols.back();

                        col.nullable = c.flags & 1;

                        col.type = c.type;

                        switch (c.type) {
                            case sql_type::SQL_NULL:
                            case sql_type::TINYINT:
                            case sql_type::BIT:
                            case sql_type::SMALLINT:
                            case sql_type::INT:
                            case sql_type::DATETIM4:
                            case sql_type::REAL:
                            case sql_type::MONEY:
                            case sql_type::DATETIME:
                            case sql_type::FLOAT:
                            case sql_type::SMALLMONEY:
                            case sql_type::BIGINT:
                            case sql_type::DATE:
                                // nop
                                break;

                            case sql_type::INTN:
                            case sql_type::FLTN:
                            case sql_type::TIME:
                            case sql_type::DATETIME2:
                            case sql_type::DATETIMN:
                            case sql_type::DATETIMEOFFSET:
                            case sql_type::BITN:
                            case sql_type::MONEYN:
                            case sql_type::UNIQUEIDENTIFIER:
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                                col.max_length = *(uint8_t*)sv2.data();

                                len++;
                                sv2 = sv2.substr(1);
                                break;

                            case sql_type::VARCHAR:
                            case sql_type::NVARCHAR:
                            case sql_type::CHAR:
                            case sql_type::NCHAR: {
                                if (sv2.length() < sizeof(uint16_t) + sizeof(collation))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(uint16_t) + sizeof(collation));

                                col.max_length = *(uint16_t*)sv2.data();

                                col.coll = *(collation*)(sv2.data() + sizeof(uint16_t));

                                if ((c.type == sql_type::CHAR || c.type == sql_type::VARCHAR) && conn.impl->has_utf8)
                                    col.utf8 = col.coll.utf8;

                                len += sizeof(uint16_t) + sizeof(collation);
                                sv2 = sv2.substr(sizeof(uint16_t) + sizeof(collation));
                                break;
                            }

                            case sql_type::VARBINARY:
                            case sql_type::BINARY:
                                if (sv2.length() < sizeof(uint16_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(uint16_t));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t);
                                sv2 = sv2.substr(sizeof(uint16_t));
                                break;

                            case sql_type::XML:
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                                len += sizeof(uint8_t);
                                sv2 = sv2.substr(sizeof(uint8_t));
                                break;

                            case sql_type::DECIMAL:
                            case sql_type::NUMERIC:
                                if (sv2.length() < 3)
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 3).", sv2.length(), 3);

                                col.max_length = (uint8_t)sv2[0];
                                col.precision = (uint8_t)sv2[1];
                                col.scale = (uint8_t)sv2[2];

                                len += 3;
                                sv2 = sv2.substr(3);

                                break;

                            case sql_type::SQL_VARIANT:
                                if (sv2.length() < sizeof(uint32_t))
                                    return;

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));
                                break;

                            case sql_type::IMAGE:
                            case sql_type::TEXT:
                            case sql_type::NTEXT:
                            {
                                if (sv2.length() < sizeof(uint32_t))
                                    return;

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));

                                if (c.type == sql_type::TEXT || c.type == sql_type::NTEXT) {
                                    if (sv2.length() < sizeof(collation))
                                        return;

                                    sv2 = sv2.substr(sizeof(collation));
                                }

                                if (sv2.length() < 1)
                                    return;

                                auto num_parts = (uint8_t)sv2[0];

                                sv2 = sv2.substr(1);

                                for (uint8_t j = 0; j < num_parts; j++) {
                                    if (sv2.length() < sizeof(uint16_t))
                                        return;

                                    auto partlen = *(uint16_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint16_t));

                                    if (sv2.length() < partlen * sizeof(char16_t))
                                        return;

                                    sv2 = sv2.substr(partlen * sizeof(char16_t));
                                }

                                break;
                            }

                            default:
                                throw formatted_error("Unhandled type {} in COLMETADATA message.", c.type);
                        }

                        if (sv2.length() < 1)
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                        auto name_len = *(uint8_t*)&sv2[0];

                        sv2 = sv2.substr(1);
                        len++;

                        if (sv2.length() < name_len * sizeof(char16_t))
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), name_len * sizeof(char16_t));

                        col.name = u16string_view((char16_t*)sv2.data(), name_len);

                        sv2 = sv2.substr(name_len * sizeof(char16_t));
                        len += name_len * sizeof(char16_t);
                    }

                    break;
                }

                case token::RETURNVALUE:
                {
                    auto h = (tds_return_value*)&sv[0];

                    if (sv.length() < sizeof(tds_return_value))
                        throw formatted_error("Short RETURNVALUE message ({} bytes, expected at least {}).", sv.length(), sizeof(tds_return_value));

                    // FIXME - param name

                    if (is_byte_len_type(h->type)) {
                        uint8_t len;

                        if (sv.length() < sizeof(tds_return_value) + 2)
                            throw formatted_error("Short RETURNVALUE message ({} bytes, expected at least {}).", sv.length(), sizeof(tds_return_value) + 2);

                        len = *((uint8_t*)&sv[0] + sizeof(tds_return_value) + 1);

                        if (sv.length() < sizeof(tds_return_value) + 2 + len)
                            throw formatted_error("Short RETURNVALUE message ({} bytes, expected {}).", sv.length(), sizeof(tds_return_value) + 2 + len);

                        if (output_params.count(h->param_ordinal) != 0) {
                            value& out = *output_params.at(h->param_ordinal);

                            if (len == 0)
                                out.is_null = true;
                            else {
                                out.is_null = false;

                                // FIXME - make sure not unexpected size?

                                out.val.resize(len);
                                memcpy(out.val.data(), (uint8_t*)&sv[0] + sizeof(tds_return_value) + 2, len);
                            }
                        }
                    } else
                        throw formatted_error("Unhandled type {} in RETURNVALUE message.", h->type);

                    break;
                }

                case token::ROW:
                {
                    vector<value> row;

                    row.resize(cols.size());

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        handle_row_col(col, cols[i].type, cols[i].max_length, cols[i].coll, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case token::NBCROW:
                {
                    if (cols.empty())
                        break;

                    vector<value> row;

                    row.resize(cols.size());

                    auto bitset_length = (cols.size() + 7) / 8;

                    if (sv.length() < bitset_length)
                        throw formatted_error("Short NBCROW message ({} bytes, expected at least {}).", sv.length(), bitset_length);

                    string_view bitset(sv.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv = sv.substr(bitset_length);

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        if (i != 0) {
                            if ((i & 7) == 0) {
                                bitset = bitset.substr(1);
                                bsv = (uint8_t)bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (bsv & 1) // NULL
                            col.is_null = true;
                        else
                            handle_row_col(col, cols[i].type, cols[i].max_length, cols[i].coll, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case token::ORDER:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short ORDER message ({} bytes, expected at least {}).", sv.length(), sizeof(uint16_t));

                    auto len = *(uint16_t*)sv.data();
                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short ORDER message ({} bytes, expected {}).", sv.length(), len);

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} while executing RPC.", type);
            }
        }

        if (last_packet)
            finished = true;
    }

    bool rpc::fetch_row() {
        while (!rows.empty() || !finished) {
            if (!rows.empty()) {
                auto r = move(rows.front());

                rows.pop_front();

                for (unsigned int i = 0; i < r.size(); i++) {
                    cols[i].is_null = r[i].is_null;

                    if (!cols[i].is_null)
                        cols[i].val = move(r[i].val);
                }

                return true;
            }

            if (finished)
                return false;

            wait_for_packet();
        }

        return false;
    }

    static u16string to_u16string(uint64_t num) {
        char16_t s[22], *p;

        if (num == 0)
            return u"0";

        s[21] = 0;
        p = &s[21];

        while (num != 0) {
            p = &p[-1];

            *p = (char16_t)((num % 10) + '0');

            num /= 10;
        }

        return p;
    }

    // FIXME - can we do static assert if no. of question marks different from no. of parameters?
    void query::do_query(tds& conn, const u16string_view& q) {
        if (!params.empty()) {
            u16string q2;
            bool in_quotes = false;
            unsigned int param_num = 1;

            // replace ? in q with parameters

            q2.reserve(q.length());

            for (unsigned int i = 0; i < q.length(); i++) {
                if (q[i] == '\'')
                    in_quotes = !in_quotes;

                if (q[i] == '?' && !in_quotes) {
                    q2 += u"@P" + to_u16string(param_num);
                    param_num++;
                } else
                    q2 += q[i];
            }

            rpc r1(conn, u"sp_prepare", handle, create_params_string(), q2, 1); // 1 means return metadata

            while (r1.fetch_row()) { }

            cols = r1.cols;
        } else {
            rpc r1(conn, u"sp_prepare", handle, u"", q, 1); // 1 means return metadata

            while (r1.fetch_row()) { }

            cols = r1.cols;
        }

        if (handle.is_null)
            throw runtime_error("sp_prepare failed.");

        r2.reset(new rpc(conn, u"sp_execute", static_cast<value>(handle), params));
    }

    void query::do_query(tds& conn, const string_view& q) {
        do_query(conn, utf8_to_utf16(q));
    }

    uint16_t query::num_columns() const {
        return (uint16_t)r2->cols.size();
    }

    const column& query::operator[](uint16_t i) const {
        return r2->cols[i];
    }

    bool query::fetch_row() {
        return r2->fetch_row();
    }

    query::~query() {
        try {
            r2.reset(nullptr);

            // FIXME
            rpc r(conn, u"sp_unprepare", static_cast<value>(handle));

            while (r.fetch_row()) { }
        } catch (...) {
            // can't throw inside destructor
        }
    }

    u16string type_to_string(enum sql_type type, size_t length, uint8_t precision, uint8_t scale, const u16string_view& collation) {
        switch (type) {
            case sql_type::TINYINT:
                return u"TINYINT";

            case sql_type::SMALLINT:
                return u"SMALLINT";

            case sql_type::INT:
                return u"INT";

            case sql_type::BIGINT:
                return u"BIGINT";

            case sql_type::INTN:
                switch (length) {
                    case sizeof(uint8_t):
                        return u"TINYINT";

                    case sizeof(int16_t):
                        return u"SMALLINT";

                    case sizeof(int32_t):
                        return u"INT";

                    case sizeof(int64_t):
                        return u"BIGINT";

                    default:
                        throw formatted_error("INTN has invalid length {}.", length);
                }

            case sql_type::NVARCHAR:
                if (length > 8000)
                    return u"NVARCHAR(MAX)";
                else
                    return u"NVARCHAR(" + to_u16string(length == 0 ? 1 : (length / sizeof(char16_t))) + u")";

            case sql_type::NCHAR:
                return u"NCHAR(" + to_u16string(length == 0 ? 1 : (length / sizeof(char16_t))) + u")";

            case sql_type::VARCHAR:
                if (collation.empty()) {
                    if (length > 8000)
                        return u"VARCHAR(MAX)";
                    else
                        return u"VARCHAR(" + to_u16string(length == 0 ? 1 : length) + u")";
                } else {
                    if (length > 8000)
                        return u"VARCHAR(MAX) COLLATE " + u16string(collation);
                    else
                        return u"VARCHAR(" + to_u16string(length == 0 ? 1 : length) + u") COLLATE " + u16string(collation);
                }

            case sql_type::CHAR:
                return u"CHAR(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::FLTN:
                switch (length) {
                    case 4:
                        return u"REAL";

                    case 8:
                        return u"FLOAT";

                    default:
                        throw formatted_error("FLTN has invalid length {}.", length);
                }

            case sql_type::DATE:
                return u"DATE";

            case sql_type::TIME:
                return u"TIME(" + to_u16string(scale) + u")";

            case sql_type::DATETIME:
                return u"DATETIME";

            case sql_type::DATETIME2:
                return u"DATETIME2(" + to_u16string(scale) + u")";

            case sql_type::DATETIMEOFFSET:
                return u"DATETIMEOFFSET(" + to_u16string(scale) + u")";

            case sql_type::VARBINARY:
                if (length > 8000)
                    return u"VARBINARY(MAX)";
                else
                    return u"VARBINARY(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::BINARY:
                return u"BINARY(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::BITN:
                return u"BIT";

            case sql_type::DATETIM4:
                return u"SMALLDATETIME";

            case sql_type::DATETIMN:
                switch (length) {
                    case 4:
                        return u"SMALLDATETIME";

                    case 8:
                        return u"DATETIME";

                    default:
                        throw formatted_error("DATETIMN has invalid length {}.", length);
                }

            case sql_type::FLOAT:
                return u"FLOAT";

            case sql_type::REAL:
                return u"REAL";

            case sql_type::BIT:
                return u"BIT";

            case sql_type::DECIMAL:
            case sql_type::NUMERIC:
                return u"NUMERIC(" + to_u16string(precision) + u"," + to_u16string(scale) + u")";

            case sql_type::TEXT:
                return u"TEXT";

            case sql_type::NTEXT:
                return u"NTEXT";

            case sql_type::IMAGE:
                return u"IMAGE";

            case sql_type::MONEYN:
                switch (length) {
                    case 4:
                        return u"SMALLMONEY";

                    case 8:
                        return u"MONEY";

                    default:
                        throw formatted_error("MONEYN has invalid length {}.", length);
                }

            case sql_type::MONEY:
                return u"MONEY";

            case sql_type::SMALLMONEY:
                return u"SMALLMONEY";

            case sql_type::UNIQUEIDENTIFIER:
                return u"UNIQUEIDENTIFIER";

            case sql_type::XML:
                return u"XML";

            default:
                throw formatted_error("Could not get type string for {}.", type);
        }
    }

    u16string query::create_params_string() {
        unsigned int num = 1;
        u16string s;

        for (const auto& p : params) {
            if (!s.empty())
                s += u", ";

            s += u"@P" + to_u16string(num) + u" ";
            s += type_to_string(p.type, p.val.length(), p.precision, p.scale, u"");

            num++;
        }

        return s;
    }

    u16string sql_escape(const u16string_view& sv) {
        u16string s;

        s.reserve(sv.length() + 2);

        s = u"[";

        for (auto c : sv) {
            if (c == u']')
                s += u"]]";
            else
                s += c;
        }

        s += u"]";

        return s;
    }

    map<u16string, col_info> get_col_info(tds& tds, const u16string_view& table, const u16string_view& db) {
        map<u16string, col_info> info;

        {
            unique_ptr<query> sq2;

            if (db.empty())
                sq2.reset(new query(tds, u"SELECT name, system_type_id, max_length, precision, scale, collation_name, is_nullable, COLLATIONPROPERTY(collation_name, 'CodePage') FROM sys.columns WHERE object_id = OBJECT_ID(?)", table));
            else
                sq2.reset(new query(tds, u"SELECT name, system_type_id, max_length, precision, scale, collation_name, is_nullable, COLLATIONPROPERTY(collation_name, 'CodePage') FROM " + u16string(db) + u".sys.columns WHERE object_id = OBJECT_ID(?)", u16string(db) + u"." + u16string(table)));

            auto& sq = *sq2;

            while (sq.fetch_row()) {
                auto type = (sql_type)(unsigned int)sq[1];
                auto nullable = (unsigned int)sq[6] != 0;

                if (nullable) {
                    switch (type) {
                        case sql_type::TINYINT:
                        case sql_type::SMALLINT:
                        case sql_type::INT:
                        case sql_type::BIGINT:
                            type = sql_type::INTN;
                            break;

                        case sql_type::REAL:
                        case sql_type::FLOAT:
                            type = sql_type::FLTN;
                            break;

                        case sql_type::DATETIME:
                        case sql_type::DATETIM4:
                            type = sql_type::DATETIMN;
                            break;

                        case sql_type::MONEY:
                        case sql_type::SMALLMONEY:
                            type = sql_type::MONEYN;
                            break;

                        default:
                            break;
                    }
                }

                info.emplace(sq[0], col_info(type, (int16_t)sq[2], (uint8_t)(unsigned int)sq[3],
                                             (uint8_t)(unsigned int)sq[4], (u16string)sq[5], nullable,
                                             (unsigned int)sq[7]));
            }
        }

        return info;
    }

    template<unsigned N>
    static void double_to_int(double d, uint8_t* scratch) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
        auto v = *(uint64_t*)&d;
#pragma GCC diagnostic pop
        uint64_t exp = v >> 52;
        uint64_t frac = v & 0xfffffffffffff;

        // d is always positive

        frac |= 0x10000000000000; // add implicit leading bit

        // copy frac to buffer

        if constexpr (N < sizeof(uint64_t))
            memcpy(scratch, &frac, N);
        else {
            memcpy(scratch, &frac, sizeof(uint64_t));
            memset(scratch + sizeof(uint64_t), 0, N - sizeof(uint64_t));
        }

        // bitshift buffer according to exp

        while (exp > 0x433) {
            buf_lshift<N>(scratch);
            exp--;
        }

        while (exp < 0x433) {
            buf_rshift<N>(scratch);
            exp++;
        }
    }

    static string encode_charset(const u16string_view& s, unsigned int codepage) {
        string ret;

        if (s.empty())
            return "";

#ifdef _WIN32
        auto len = WideCharToMultiByte(codepage, 0, (const wchar_t*)s.data(), (int)s.length(), nullptr, 0,
                                       nullptr, nullptr);

        if (len == 0)
            throw runtime_error("WideCharToMultiByte 1 failed.");

        ret.resize(len);

        len = WideCharToMultiByte(codepage, 0, (const wchar_t*)s.data(), (int)s.length(), ret.data(), len,
                                  nullptr, nullptr);

        if (len == 0)
            throw runtime_error("WideCharToMultiByte 2 failed.");
#else
        UErrorCode status = U_ZERO_ERROR;
        const char* cp;

        switch (codepage) {
            case 437:
                cp = "ibm-437_P100-1995";
                break;

            case 850:
                cp = "ibm-850_P100-1995";
                break;

            case 874:
                cp = "windows-874-2000";
                break;

            case 932:
                cp = "ibm-942_P12A-1999";
                break;

            case 936:
                cp = "ibm-1386_P100-2001";
                break;

            case 949:
                cp = "windows-949-2000";
                break;

            case 950:
                cp = "windows-950-2000";
                break;

            case 1250:
                cp = "ibm-1250_P100-1995";
                break;

            case 1251:
                cp = "ibm-1251_P100-1995";
                break;

            case 1252:
                cp = "ibm-5348_P100-1997";
                break;

            case 1253:
                cp = "ibm-1253_P100-1995";
                break;

            case 1254:
                cp = "ibm-1254_P100-1995";
                break;

            case 1255:
                cp = "ibm-1255_P100-1995";
                break;

            case 1256:
                cp = "ibm-1256_P110-1997";
                break;

            case 1257:
                cp = "ibm-1257_P100-1995";
                break;

            case 1258:
                cp = "ibm-1258_P100-1997";
                break;

            default:
                throw formatted_error("Could not find ICU name for Windows code page {}.", codepage);
        }

        UConverter* conv = ucnv_open(cp, &status);

        if (U_FAILURE(status))
            throw formatted_error("ucnv_open failed for code page {} ({})", cp, u_errorName(status));

        ret.resize((size_t)UCNV_GET_MAX_BYTES_FOR_STRING(s.length(), ucnv_getMaxCharSize(conv)));

        auto len = ucnv_fromUChars(conv, ret.data(), (int32_t)ret.length(), s.data(), (int32_t)s.length(), &status);

        if (ret.length() > (uint32_t)len)
            ret = ret.substr(0, (size_t)len);

        ucnv_close(conv);
#endif

        return ret;
    }

    size_t tds::bcp_row_size(const col_info& col, const value& vv) {
        size_t bufsize;

        switch (col.type) {
            case sql_type::INTN:
                bufsize = 1;

                if (!vv.is_null)
                    bufsize += col.max_length;
            break;

            case sql_type::VARCHAR:
            case sql_type::CHAR:
                bufsize = sizeof(uint16_t);

                if (vv.is_null) {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                } else {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                    if ((vv.type == sql_type::VARCHAR || vv.type == sql_type::CHAR) && col.codepage == CP_UTF8) {
                        bufsize += vv.val.length();

                        if (col.max_length == -1 && !vv.val.empty())
                            bufsize += sizeof(uint32_t);
                    } else if (col.codepage == CP_UTF8) {
                        auto s = (string)vv;
                        bufsize += s.length();

                        if (col.max_length == -1 && !s.empty())
                            bufsize += sizeof(uint32_t);
                    } else {
                        auto s = encode_charset((u16string)vv, col.codepage);
                        bufsize += s.length();

                        if (col.max_length == -1 && !s.empty())
                            bufsize += sizeof(uint32_t);
                    }
                }
            break;

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
                bufsize = sizeof(uint16_t);

                if (vv.is_null) {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                } else {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                    if (vv.type == sql_type::NVARCHAR || vv.type == sql_type::NCHAR) {
                        bufsize += vv.val.length();

                        if (col.max_length == -1 && !vv.val.empty())
                            bufsize += sizeof(uint32_t);
                    } else {
                        auto s = (u16string)vv;
                        bufsize += s.length() * sizeof(char16_t);

                        if (col.max_length == -1 && !s.empty())
                            bufsize += sizeof(uint32_t);
                    }
                }
            break;

            case sql_type::VARBINARY:
            case sql_type::BINARY:
                bufsize = sizeof(uint16_t);

                if (vv.is_null) {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                } else {
                    if (col.max_length == -1) // MAX
                        bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                    if (vv.type == sql_type::VARBINARY || vv.type == sql_type::BINARY) {
                        bufsize += vv.val.length();

                        if (col.max_length == -1 && !vv.val.empty())
                            bufsize += sizeof(uint32_t);
                    } else
                        throw formatted_error("Could not convert {} to {}.", vv.type, col.type);
                }
            break;

            case sql_type::DATE:
                bufsize = 1;

                if (!vv.is_null)
                    bufsize += 3;
            break;

            case sql_type::TIME:
                bufsize = 1;

                if (!vv.is_null) {
                    if (col.scale <= 2)
                        bufsize += 3;
                    else if (col.scale <= 4)
                        bufsize += 4;
                    else
                        bufsize += 5;
                }
            break;

            case sql_type::DATETIME2:
                bufsize = 1;

                if (!vv.is_null) {
                    bufsize += 3;

                    if (col.scale <= 2)
                        bufsize += 3;
                    else if (col.scale <= 4)
                        bufsize += 4;
                    else
                        bufsize += 5;
                }
            break;

            case sql_type::DATETIMEOFFSET:
                bufsize = 1;

                if (!vv.is_null) {
                    bufsize += 5;

                    if (col.scale <= 2)
                        bufsize += 3;
                    else if (col.scale <= 4)
                        bufsize += 4;
                    else
                        bufsize += 5;
                }
            break;

            case sql_type::DATETIME:
                bufsize = sizeof(int32_t) + sizeof(uint32_t);
            break;

            case sql_type::DATETIMN:
                bufsize = 1;

                if (!vv.is_null)
                    bufsize += col.max_length;
            break;

            case sql_type::FLTN:
                bufsize = 1;

                if (!vv.is_null)
                    bufsize += col.max_length;
            break;

            case sql_type::BITN:
                bufsize = 1;

                if (!vv.is_null)
                    bufsize += sizeof(uint8_t);
            break;

            case sql_type::TINYINT:
                bufsize = sizeof(uint8_t);
            break;

            case sql_type::SMALLINT:
                bufsize = sizeof(int16_t);
            break;

            case sql_type::INT:
                bufsize = sizeof(int32_t);
            break;

            case sql_type::BIGINT:
                bufsize = sizeof(int64_t);
            break;

            case sql_type::FLOAT:
                bufsize = sizeof(double);
            break;

            case sql_type::REAL:
                bufsize = sizeof(float);
            break;

            case sql_type::BIT:
                bufsize = sizeof(uint8_t);
            break;

            case sql_type::NUMERIC:
            case sql_type::DECIMAL:
                bufsize = sizeof(uint8_t);

                if (!vv.is_null) {
                    bufsize += sizeof(uint8_t);

                    if (col.precision >= 29)
                        bufsize += 16;
                    else if (col.precision >= 20)
                        bufsize += 12;
                    else if (col.precision >= 10)
                        bufsize += 8;
                    else
                        bufsize += 4;
                }
            break;

            case sql_type::MONEYN:
                bufsize = sizeof(uint8_t);

                if (!vv.is_null)
                    bufsize += col.max_length;
            break;

            case sql_type::MONEY:
                bufsize = sizeof(int64_t);
            break;

            case sql_type::SMALLMONEY:
                bufsize = sizeof(int32_t);
            break;

            default:
                throw formatted_error("Unable to send {} in BCP row.", col.type);
        }

        return bufsize;
    }

    void tds::bcp_row_data(uint8_t*& ptr, const col_info& col, const value& vv, const u16string_view& col_name) {
        switch (col.type) {
            case sql_type::INTN:
                if (vv.is_null) {
                    *ptr = 0;
                    ptr++;
                } else {
                    *ptr = (uint8_t)col.max_length;
                    ptr++;

                    int64_t n;

                    try {
                        n = (int64_t)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    switch (col.max_length) {
                        case sizeof(uint8_t):
                            if (n < numeric_limits<uint8_t>::min() || n > numeric_limits<uint8_t>::max())
                                throw formatted_error("{} is out of bounds for TINYINT column {}.", n, utf16_to_utf8(col_name));

                            *ptr = (uint8_t)n;
                            ptr++;
                        break;

                        case sizeof(int16_t):
                            if (n < numeric_limits<int16_t>::min() || n > numeric_limits<int16_t>::max())
                                throw formatted_error("{} is out of bounds for SMALLINT column {}.", n, utf16_to_utf8(col_name));

                            *(int16_t*)ptr = (int16_t)n;
                            ptr += sizeof(int16_t);
                        break;

                        case sizeof(int32_t):
                            if (n < numeric_limits<int32_t>::min() || n > numeric_limits<int32_t>::max())
                                throw formatted_error("{} is out of bounds for INT column {}.", n, utf16_to_utf8(col_name));

                            *(int32_t*)ptr = (int32_t)n;
                            ptr += sizeof(int32_t);
                        break;

                        case sizeof(int64_t):
                            *(int64_t*)ptr = n;
                            ptr += sizeof(int64_t);
                        break;

                        default:
                            throw formatted_error("Invalid INTN size {}.", col.max_length);
                    }
                }
            break;

            case sql_type::VARCHAR:
            case sql_type::CHAR:
                if (col.max_length == -1) {
                    if (vv.is_null) {
                        *(uint64_t*)ptr = 0xffffffffffffffff;
                        ptr += sizeof(uint64_t);
                    } else if ((vv.type == sql_type::VARCHAR || vv.type == sql_type::CHAR) && col.codepage == CP_UTF8) {
                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!vv.val.empty()) {
                            *(uint32_t*)ptr = (uint32_t)vv.val.length();
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, vv.val.data(), vv.val.length());
                            ptr += vv.val.length();
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    } else if (col.codepage == CP_UTF8) {
                        auto s = (string)vv;

                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!s.empty()) {
                            *(uint32_t*)ptr = (uint32_t)s.length();
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, s.data(), s.length());
                            ptr += s.length();
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    } else {
                        auto s = encode_charset((u16string)vv, col.codepage);

                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!s.empty()) {
                            *(uint32_t*)ptr = (uint32_t)s.length();
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, s.data(), s.length());
                            ptr += s.length();
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    }
                } else {
                    if (vv.is_null) {
                        *(uint16_t*)ptr = 0xffff;
                        ptr += sizeof(uint16_t);
                    } else if ((vv.type == sql_type::VARCHAR || vv.type == sql_type::CHAR) && col.codepage == CP_UTF8) {
                        if (vv.val.length() > (uint16_t)col.max_length)
                            throw formatted_error("String \"{}\" too long for column {} (maximum length {}).", vv.val, utf16_to_utf8(col_name), col.max_length);

                        *(uint16_t*)ptr = (uint16_t)vv.val.length();
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, vv.val.data(), vv.val.length());
                        ptr += vv.val.length();
                    } else if (col.codepage == CP_UTF8) {
                        auto s = (string)vv;

                        if (s.length() > (uint16_t)col.max_length)
                            throw formatted_error("String \"{}\" too long for column {} (maximum length {}).", s, utf16_to_utf8(col_name), col.max_length);

                        *(uint16_t*)ptr = (uint16_t)s.length();
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, s.data(), s.length());
                        ptr += s.length();
                    } else {
                        auto s = encode_charset((u16string)vv, col.codepage);

                        if (s.length() > (uint16_t)col.max_length)
                            throw formatted_error("String \"{}\" too long for column {} (maximum length {}).", (string)vv, utf16_to_utf8(col_name), col.max_length);

                        *(uint16_t*)ptr = (uint16_t)s.length();
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, s.data(), s.length());
                        ptr += s.length();
                    }
                }
            break;

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
                if (col.max_length == -1) {
                    if (vv.is_null) {
                        *(uint64_t*)ptr = 0xffffffffffffffff;
                        ptr += sizeof(uint64_t);
                    } else if (vv.type == sql_type::NVARCHAR || vv.type == sql_type::NCHAR) {
                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!vv.val.empty()) {
                            *(uint32_t*)ptr = (uint32_t)vv.val.length();
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, vv.val.data(), vv.val.length());
                            ptr += vv.val.length();
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    } else {
                        auto s = (u16string)vv;

                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!s.empty()) {
                            *(uint32_t*)ptr = (uint32_t)(s.length() * sizeof(char16_t));
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, s.data(), s.length() * sizeof(char16_t));
                            ptr += s.length() * sizeof(char16_t);
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    }
                } else {
                    if (vv.is_null) {
                        *(uint16_t*)ptr = 0xffff;
                        ptr += sizeof(uint16_t);
                    } else if (vv.type == sql_type::NVARCHAR || vv.type == sql_type::NCHAR) {
                        if (vv.val.length() > (uint16_t)col.max_length) {
                            throw formatted_error("String \"{}\" too long for column {} (maximum length {}).",
                                                    utf16_to_utf8(u16string_view((char16_t*)vv.val.data(), vv.val.length() / sizeof(char16_t))),
                                                    utf16_to_utf8(col_name), col.max_length / sizeof(char16_t));
                        }

                        *(uint16_t*)ptr = (uint16_t)vv.val.length();
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, vv.val.data(), vv.val.length());
                        ptr += vv.val.length();
                    } else {
                        auto s = (u16string)vv;

                        if (s.length() > (uint16_t)col.max_length) {
                            throw formatted_error("String \"{}\" too long for column {} (maximum length {}).",
                                                    utf16_to_utf8(u16string_view((char16_t*)s.data(), s.length() / sizeof(char16_t))),
                                                    utf16_to_utf8(col_name), col.max_length / sizeof(char16_t));
                        }

                        *(uint16_t*)ptr = (uint16_t)(s.length() * sizeof(char16_t));
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, s.data(), s.length() * sizeof(char16_t));
                        ptr += s.length() * sizeof(char16_t);
                    }
                }
            break;

            case sql_type::VARBINARY:
            case sql_type::BINARY:
                if (col.max_length == -1) {
                    if (vv.is_null) {
                        *(uint64_t*)ptr = 0xffffffffffffffff;
                        ptr += sizeof(uint64_t);
                    } else if (vv.type == sql_type::VARBINARY || vv.type == sql_type::BINARY) {
                        *(uint64_t*)ptr = 0xfffffffffffffffe;
                        ptr += sizeof(uint64_t);

                        if (!vv.val.empty()) {
                            *(uint32_t*)ptr = (uint32_t)vv.val.length();
                            ptr += sizeof(uint32_t);

                            memcpy(ptr, vv.val.data(), vv.val.length());
                            ptr += vv.val.length();
                        }

                        *(uint32_t*)ptr = 0;
                        ptr += sizeof(uint32_t);
                    } else
                        throw formatted_error("Could not convert {} to {}.", vv.type, col.type);
                } else {
                    if (vv.is_null) {
                        *(uint16_t*)ptr = 0xffff;
                        ptr += sizeof(uint16_t);
                    } else if (vv.type == sql_type::VARBINARY || vv.type == sql_type::BINARY) {
                        if (vv.val.length() > (uint16_t)col.max_length)
                            throw formatted_error("Binary data too long for column {} ({} bytes, maximum {}).", utf16_to_utf8(col_name), vv.val.length(), col.max_length);

                        *(uint16_t*)ptr = (uint16_t)vv.val.length();
                        ptr += sizeof(uint16_t);

                        memcpy(ptr, vv.val.data(), vv.val.length());
                        ptr += vv.val.length();
                    } else
                        throw formatted_error("Could not convert {} to {}.", vv.type, col.type);
                }
            break;

            case sql_type::DATE:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    chrono::year_month_day d;

                    try {
                        d = (chrono::year_month_day)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    uint32_t n = ymd_to_num(d) + jan1900;

                    *(uint8_t*)ptr = 3;
                    ptr++;

                    memcpy(ptr, &n, 3);
                    ptr += 3;
                }
            break;

            case sql_type::TIME:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    uint64_t ticks;

                    try {
                        ticks = time_t(vv).count();
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    for (int j = 0; j < 7 - col.scale; j++) {
                        ticks /= 10;
                    }

                    if (col.scale <= 2) {
                        *(uint8_t*)ptr = 3;
                        ptr++;

                        memcpy(ptr, &ticks, 3);
                        ptr += 3;
                    } else if (col.scale <= 4) {
                        *(uint8_t*)ptr = 4;
                        ptr++;

                        memcpy(ptr, &ticks, 4);
                        ptr += 4;
                    } else {
                        *(uint8_t*)ptr = 5;
                        ptr++;

                        memcpy(ptr, &ticks, 5);
                        ptr += 5;
                    }
                }
            break;

            case sql_type::DATETIME2:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    datetime dt;

                    try {
                        dt = (datetime)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    uint32_t n = ymd_to_num(dt.d) + jan1900;
                    auto ticks = dt.t.count();

                    for (int j = 0; j < 7 - col.scale; j++) {
                        ticks /= 10;
                    }

                    if (col.scale <= 2) {
                        *(uint8_t*)ptr = 6;
                        ptr++;

                        memcpy(ptr, &ticks, 3);
                        ptr += 3;
                    } else if (col.scale <= 4) {
                        *(uint8_t*)ptr = 7;
                        ptr++;

                        memcpy(ptr, &ticks, 4);
                        ptr += 4;
                    } else {
                        *(uint8_t*)ptr = 8;
                        ptr++;

                        memcpy(ptr, &ticks, 5);
                        ptr += 5;
                    }

                    memcpy(ptr, &n, 3);
                    ptr += 3;
                }
            break;

            case sql_type::DATETIMEOFFSET:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    datetimeoffset dto;

                    try {
                        dto = (datetimeoffset)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    uint32_t n = ymd_to_num(dto.d) + jan1900;
                    auto ticks = dto.t.count();

                    for (int j = 0; j < 7 - col.scale; j++) {
                        ticks /= 10;
                    }

                    if (col.scale <= 2) {
                        *(uint8_t*)ptr = 8;
                        ptr++;

                        memcpy(ptr, &ticks, 3);
                        ptr += 3;
                    } else if (col.scale <= 4) {
                        *(uint8_t*)ptr = 9;
                        ptr++;

                        memcpy(ptr, &ticks, 4);
                        ptr += 4;
                    } else {
                        *(uint8_t*)ptr = 10;
                        ptr++;

                        memcpy(ptr, &ticks, 5);
                        ptr += 5;
                    }

                    memcpy(ptr, &n, 3);
                    ptr += 3;

                    *(int16_t*)ptr = dto.offset;
                    ptr += sizeof(int16_t);
                }
            break;

            case sql_type::DATETIME: {
                datetime dt;

                try {
                    dt = (datetime)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                auto ticks = chrono::duration_cast<chrono::duration<int64_t, ratio<1, 300>>>(dt.t);

                *(int32_t*)ptr = ymd_to_num(dt.d);
                ptr += sizeof(int32_t);

                *(uint32_t*)ptr = (uint32_t)ticks.count();
                ptr += sizeof(uint32_t);

                break;
            }

            case sql_type::DATETIMN:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    datetime dt;

                    try {
                        dt = (datetime)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    switch (col.max_length) {
                        case 4: {
                            if (dt.d < num_to_ymd(0))
                                throw formatted_error("Datetime \"{}\" too early for SMALLDATETIME column {}.", dt, utf16_to_utf8(col_name));
                            else if (dt.d > num_to_ymd(numeric_limits<uint16_t>::max()))
                                throw formatted_error("Datetime \"{}\" too late for SMALLDATETIME column {}.", dt, utf16_to_utf8(col_name));

                            *(uint8_t*)ptr = (uint8_t)col.max_length;
                            ptr++;

                            *(uint16_t*)ptr = (uint16_t)ymd_to_num(dt.d);
                            ptr += sizeof(uint16_t);

                            *(uint16_t*)ptr = (uint16_t)chrono::duration_cast<chrono::minutes>(dt.t).count();
                            ptr += sizeof(uint16_t);

                            break;
                        }

                        case 8: {
                            auto dur = chrono::duration_cast<chrono::duration<int64_t, ratio<1, 300>>>(dt.t);

                            *(uint8_t*)ptr = (uint8_t)col.max_length;
                            ptr++;

                            *(int32_t*)ptr = ymd_to_num(dt.d);
                            ptr += sizeof(int32_t);

                            *(uint32_t*)ptr = (uint32_t)dur.count();
                            ptr += sizeof(uint32_t);

                            break;
                        }

                        default:
                            throw formatted_error("DATETIMN has invalid length {}.", col.max_length);
                    }
                }
            break;

            case sql_type::FLTN:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else {
                    double d;

                    try {
                        d = (double)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    *(uint8_t*)ptr = (uint8_t)col.max_length;
                    ptr++;

                    switch (col.max_length) {
                        case sizeof(float): {
                            auto f = (float)d;
                            memcpy(ptr, &f, sizeof(float));
                            ptr += sizeof(float);
                            break;
                        }

                        case sizeof(double):
                            memcpy(ptr, &d, sizeof(double));
                            ptr += sizeof(double);
                        break;

                        default:
                            throw formatted_error("FLTN has invalid length {}.", col.max_length);
                    }
                }
            break;

            case sql_type::BITN:
                if (vv.is_null) {
                    *(uint8_t*)ptr = 0;
                    ptr++;
                } else if (vv.type == sql_type::BIT || vv.type == sql_type::BITN) {
                    *(uint8_t*)ptr = sizeof(uint8_t);
                    ptr++;
                    *(uint8_t*)ptr = (uint8_t)vv.val[0];
                    ptr += sizeof(uint8_t);
                } else {
                    int64_t n;

                    try {
                        n = (int64_t)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    *(uint8_t*)ptr = sizeof(uint8_t);
                    ptr++;
                    *(uint8_t*)ptr = n != 0 ? 1 : 0;
                    ptr++;
                }
            break;

            case sql_type::TINYINT: {
                int64_t n;

                try {
                    n = (int64_t)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                if (n < numeric_limits<uint8_t>::min() || n > numeric_limits<uint8_t>::max())
                    throw formatted_error("Value {} is out of bounds for TINYINT column {}.", n, utf16_to_utf8(col_name));

                *(uint8_t*)ptr = (uint8_t)n;
                ptr += sizeof(uint8_t);

                break;
            }

            case sql_type::SMALLINT: {
                int64_t n;

                try {
                    n = (int64_t)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                if (n < numeric_limits<int16_t>::min() || n > numeric_limits<int16_t>::max())
                    throw formatted_error("Value {} is out of bounds for SMALLINT column {}.", n, utf16_to_utf8(col_name));

                *(int32_t*)ptr = (int16_t)n;
                ptr += sizeof(int16_t);

                break;
            }

            case sql_type::INT: {
                int64_t n;

                try {
                    n = (int64_t)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                if (n < numeric_limits<int32_t>::min() || n > numeric_limits<int32_t>::max())
                    throw formatted_error("Value {} is out of bounds for INT column {}.", n, utf16_to_utf8(col_name));

                *(int32_t*)ptr = (int32_t)n;
                ptr += sizeof(int32_t);

                break;
            }

            case sql_type::BIGINT: {
                int64_t n;

                try {
                    n = (int64_t)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                *(int64_t*)ptr = n;
                ptr += sizeof(int64_t);

                break;
            }

            case sql_type::FLOAT: {
                double n;

                try {
                    n = (double)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                *(double*)ptr = n;
                ptr += sizeof(double);

                break;
            }

            case sql_type::REAL: {
                double n;

                try {
                    n = (double)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                *(float*)ptr = (float)n;
                ptr += sizeof(float);

                break;
            }

            case sql_type::BIT: {
                if (vv.type == sql_type::BIT || vv.type == sql_type::BITN) {
                    *(uint8_t*)ptr = (uint8_t)(vv.val[0]);
                    ptr += sizeof(uint8_t);
                } else {
                    int64_t n;

                    try {
                        n = (int64_t)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    *(uint8_t*)ptr = n != 0 ? 1 : 0;
                    ptr += sizeof(uint8_t);
                }

                break;
            }

            case sql_type::NUMERIC:
            case sql_type::DECIMAL:
                if (vv.is_null) {
                    *ptr = 0;
                    ptr++;
                } else {
                    bool neg = false;
                    double d;

                    try {
                        d = (double)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    if (d < 0) {
                        neg = true;
                        d = -d;
                    }

                    for (unsigned int j = 0; j < col.scale; j++) {
                        d *= 10;
                    }

                    // FIXME - avoid doing pow every time?

                    if (d > pow(10, col.precision)) {
                        if (neg) {
                            throw formatted_error("Value {} is too small for NUMERIC({},{}) column {}.", vv, col.precision,
                                                  col.scale, utf16_to_utf8(col_name));
                        } else {
                            throw formatted_error("Value {} is too large for NUMERIC({},{}) column {}.", vv, col.precision,
                                                  col.scale, utf16_to_utf8(col_name));
                        }
                    }

                    if (col.precision < 10) { // 4 bytes
                        *ptr = 5;
                        ptr++;

                        *ptr = neg ? 0 : 1;
                        ptr++;

                        *(uint32_t*)ptr = (uint32_t)d;
                        ptr += sizeof(uint32_t);
                    } else if (col.precision < 20) { // 8 bytes
                        *ptr = 9;
                        ptr++;

                        *ptr = neg ? 0 : 1;
                        ptr++;

                        *(uint64_t*)ptr = (uint64_t)d;
                        ptr += sizeof(uint64_t);
                    } else if (col.precision < 29) { // 12 bytes
                        *ptr = 13;
                        ptr++;

                        *ptr = neg ? 0 : 1;
                        ptr++;

                        double_to_int<12>(d, ptr);
                        ptr += 12;
                    } else { // 16 bytes
                        *ptr = 17;
                        ptr++;

                        *ptr = neg ? 0 : 1;
                        ptr++;

                        double_to_int<16>(d, ptr);
                        ptr += 16;
                    }
                }
            break;

            case sql_type::MONEYN: {
                if (vv.is_null) {
                    *ptr = 0;
                    ptr++;
                } else {
                    *ptr = (uint8_t)col.max_length;
                    ptr++;

                    double val;

                    try {
                        val = (double)vv;
                    } catch (const exception& e) {
                        throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                    }

                    val *= 10000.0;

                    switch (col.max_length) {
                        case sizeof(int64_t): {
                            auto v = (int64_t)val;

                            *(int32_t*)ptr = (int32_t)(v >> 32);
                            *(int32_t*)(ptr + sizeof(int32_t)) = (int32_t)(v & 0xffffffff);
                            break;
                        }

                        case sizeof(int32_t):
                            *(int32_t*)ptr = (int32_t)val;
                        break;

                        default:
                            throw formatted_error("MONEYN column {} had invalid size {}.", utf16_to_utf8(col_name), col.max_length);

                    }

                    ptr += col.max_length;
                }

                break;
            }

            case sql_type::MONEY: {
                double val;

                try {
                    val = (double)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                val *= 10000.0;

                auto v = (int64_t)val;

                *(int32_t*)ptr = (int32_t)(v >> 32);
                *(int32_t*)(ptr + sizeof(int32_t)) = (int32_t)(v & 0xffffffff);

                ptr += sizeof(int64_t);

                break;
            }

            case sql_type::SMALLMONEY: {
                double val;

                try {
                    val = (double)vv;
                } catch (const exception& e) {
                    throw formatted_error("{} (column {})", e.what(), utf16_to_utf8(col_name));
                }

                val *= 10000.0;

                *(int32_t*)ptr = (int32_t)val;
                ptr += sizeof(int32_t);

                break;
            }

            default:
                throw formatted_error("Unable to send {} in BCP row.", col.type);
        }
    }

    void tds::bcp_sendmsg(const string_view& data) {
        impl->send_msg(tds_msg::bulk_load_data, data);

        enum tds_msg type;
        string payload;

        impl->wait_for_msg(type, payload);
        // FIXME - timeout

        if (type != tds_msg::tabular_result)
            throw formatted_error("Received message type {}, expected tabular_result", (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (token)sv[0];
            sv = sv.substr(1);

            // FIXME - parse unknowns according to numeric value of type

            switch (type) {
                case token::DONE:
                case token::DONEINPROC:
                case token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                    if (impl->count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            impl->count_handler(msg->rowcount, msg->curcmd);
                    }

                    sv = sv.substr(sizeof(tds_done_msg));

                    break;

                case token::INFO:
                case token::TDS_ERROR:
                case token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                    if (type == token::INFO) {
                        if (impl->message_handler)
                            impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == token::TDS_ERROR) {
                        if (impl->message_handler)
                            impl->handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error("BCP failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == token::ENVCHANGE)
                        impl->handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} in BCP response.", type);
            }
        }
    }

    size_t bcp_colmetadata_size(const col_info& col) {
        switch (col.type) {
            case sql_type::SQL_NULL:
            case sql_type::TINYINT:
            case sql_type::BIT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::DATETIM4:
            case sql_type::REAL:
            case sql_type::MONEY:
            case sql_type::DATETIME:
            case sql_type::FLOAT:
            case sql_type::SMALLMONEY:
            case sql_type::BIGINT:
            case sql_type::UNIQUEIDENTIFIER:
            case sql_type::DATE:
                return 0;

            case sql_type::INTN:
            case sql_type::FLTN:
            case sql_type::TIME:
            case sql_type::DATETIME2:
            case sql_type::DATETIMN:
            case sql_type::DATETIMEOFFSET:
            case sql_type::BITN:
            case sql_type::MONEYN:
                return 1;

            case sql_type::VARCHAR:
            case sql_type::NVARCHAR:
            case sql_type::CHAR:
            case sql_type::NCHAR:
                return sizeof(uint16_t) + sizeof(collation);

            case sql_type::VARBINARY:
            case sql_type::BINARY:
                return sizeof(uint16_t);

            case sql_type::DECIMAL:
            case sql_type::NUMERIC:
                return 3;

            default:
                throw formatted_error("Unhandled type {} when creating COLMETADATA token.", col.type);
        }
    }

    void bcp_colmetadata_data(uint8_t*& ptr, const col_info& col, const u16string_view& name) {
        auto c = (tds_colmetadata_col*)ptr;

        c->user_type = 0;
        c->flags = 8; // read/write

        if (col.nullable)
            c->flags |= 1;

        c->type = col.type;

        ptr += sizeof(tds_colmetadata_col);

        switch (col.type) {
            case sql_type::SQL_NULL:
            case sql_type::TINYINT:
            case sql_type::BIT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::DATETIM4:
            case sql_type::REAL:
            case sql_type::MONEY:
            case sql_type::DATETIME:
            case sql_type::FLOAT:
            case sql_type::SMALLMONEY:
            case sql_type::BIGINT:
            case sql_type::UNIQUEIDENTIFIER:
            case sql_type::DATE:
                // nop
            break;

            case sql_type::INTN:
            case sql_type::FLTN:
            case sql_type::BITN:
            case sql_type::MONEYN:
                *(uint8_t*)ptr = (uint8_t)col.max_length;
                ptr++;
            break;

            case sql_type::TIME:
            case sql_type::DATETIME2:
            case sql_type::DATETIMN:
            case sql_type::DATETIMEOFFSET:
                *(uint8_t*)ptr = col.scale;
                ptr++;
            break;

            case sql_type::VARCHAR:
            case sql_type::NVARCHAR:
            case sql_type::CHAR:
            case sql_type::NCHAR: {
                *(uint16_t*)ptr = (uint16_t)col.max_length;
                ptr += sizeof(uint16_t);

                auto c = (collation*)ptr;

                // collation seems to be ignored, depends on what INSERT BULK says

                c->lcid = 0;
                c->ignore_case = 0;
                c->ignore_accent = 0;
                c->ignore_width = 0;
                c->ignore_kana = 0;
                c->binary = 0;
                c->binary2 = 0;
                c->utf8 = 0;
                c->reserved = 0;
                c->version = 0;
                c->sort_id = 0;

                ptr += sizeof(collation);

                break;
            }

            case sql_type::VARBINARY:
            case sql_type::BINARY:
                *(uint16_t*)ptr = (uint16_t)col.max_length;
                ptr += sizeof(uint16_t);
            break;

            case sql_type::DECIMAL:
            case sql_type::NUMERIC:
                if (col.precision >= 29)
                    *(uint8_t*)ptr = 17;
                else if (col.precision >= 20)
                    *(uint8_t*)ptr = 13;
                else if (col.precision >= 10)
                    *(uint8_t*)ptr = 9;
                else
                    *(uint8_t*)ptr = 5;

                ptr++;

                *(uint8_t*)ptr = col.precision;
                ptr++;

                *(uint8_t*)ptr = col.scale;
                ptr++;
            break;

            default:
                throw formatted_error("Unhandled type {} when creating COLMETADATA token.", col.type);
        }

        *(uint8_t*)ptr = (uint8_t)name.length();
        ptr++;

        memcpy(ptr, name.data(), name.length() * sizeof(char16_t));
        ptr += name.length() * sizeof(char16_t);
    }

    batch::batch(tds& conn, const u16string_view& q) {
        impl = new batch_impl(conn, q);
    }

    batch::batch(tds& conn, const string_view& q) {
        impl = new batch_impl(conn, utf8_to_utf16(q));
    }

    batch::~batch() {
        delete impl;
    }

    batch_impl::batch_impl(tds& conn, const u16string_view& q) : conn(conn) {
        size_t bufsize;

        bufsize = sizeof(tds_all_headers) + (q.length() * sizeof(uint16_t));

        vector<uint8_t> buf(bufsize);

        auto all_headers = (tds_all_headers*)&buf[0];

        all_headers->total_size = sizeof(tds_all_headers);
        all_headers->size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
        all_headers->trans_desc.type = 2; // transaction descriptor
        all_headers->trans_desc.descriptor = conn.impl->trans_id;
        all_headers->trans_desc.outstanding = 1;

        auto ptr = (char16_t*)&all_headers[1];

        memcpy(ptr, q.data(), q.length() * sizeof(char16_t));

        conn.impl->send_msg(tds_msg::sql_batch, string_view((char*)buf.data(), buf.size()));

        wait_for_packet();
    }

    batch_impl::~batch_impl() {
        if (finished)
            return;

        try {
            conn.impl->send_msg(tds_msg::attention_signal, string_view());

            while (!finished) {
                wait_for_packet();
            }

            // wait for attention acknowledgement

            bool ack = false;

            do {
                enum tds_msg type;
                string payload;

                conn.impl->wait_for_msg(type, payload);
                // FIXME - timeout

                if (type != tds_msg::tabular_result)
                    continue;

                auto sv = string_view(payload);
                parse_tokens(sv, tokens, buf_columns);

                while (!tokens.empty()) {
                    auto t = move(tokens.front());

                    tokens.pop_front();

                    auto type = (token)t[0];

                    switch (type) {
                        case token::DONE:
                        case token::DONEINPROC:
                        case token::DONEPROC: {
                            auto m = (tds_done_msg*)&t[1];

                            if (m->status & 0x20)
                                ack = true;

                            break;
                        }

                        default:
                            break;
                    }
                }
            } while (!ack);
        } catch (...) {
            // can't throw in destructor
        }
    }

    void batch_impl::wait_for_packet() {
        enum tds_msg type;
        string payload;
        bool last_packet;

        conn.impl->wait_for_msg(type, payload, &last_packet);
        // FIXME - timeout

        if (type != tds_msg::tabular_result)
            throw formatted_error("Received message type {}, expected tabular_result", (int)type);

        buf += payload;

        {
            string_view sv = buf;

            parse_tokens(sv, tokens, buf_columns);

            buf = sv;
        }

        if (last_packet && !buf.empty())
            throw formatted_error("Data remaining in buffer");

        while (!tokens.empty()) {
            auto t = move(tokens.front());

            tokens.pop_front();

            string_view sv = t;

            auto type = (token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case token::DONE:
                case token::DONEINPROC:
                case token::DONEPROC:
                    if (conn.impl->count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            conn.impl->count_handler(msg->rowcount, msg->curcmd);
                    }

                    break;

                case token::INFO:
                case token::TDS_ERROR:
                case token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                    if (type == token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);
                        else
                            throw formatted_error("SQL batch failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    break;
                }

                case token::COLMETADATA:
                {
                    if (sv.length() < 4)
                        throw formatted_error("Short COLMETADATA message ({} bytes, expected at least 4).", sv.length());

                    auto num_columns = *(uint16_t*)&sv[0];

                    cols.clear();
                    cols.reserve(num_columns);

                    if (num_columns == 0)
                        break;

                    size_t len = sizeof(uint16_t);
                    string_view sv2 = sv;

                    sv2 = sv2.substr(sizeof(uint16_t));

                    for (unsigned int i = 0; i < num_columns; i++) {
                        if (sv2.length() < sizeof(tds_colmetadata_col))
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(tds_colmetadata_col));

                        auto& c = *(tds_colmetadata_col*)&sv2[0];

                        len += sizeof(tds_colmetadata_col);
                        sv2 = sv2.substr(sizeof(tds_colmetadata_col));

                        cols.emplace_back();

                        auto& col = cols.back();

                        col.type = c.type;

                        switch (c.type) {
                            case sql_type::SQL_NULL:
                            case sql_type::TINYINT:
                            case sql_type::BIT:
                            case sql_type::SMALLINT:
                            case sql_type::INT:
                            case sql_type::DATETIM4:
                            case sql_type::REAL:
                            case sql_type::MONEY:
                            case sql_type::DATETIME:
                            case sql_type::FLOAT:
                            case sql_type::SMALLMONEY:
                            case sql_type::BIGINT:
                            case sql_type::DATE:
                                // nop
                                break;

                            case sql_type::INTN:
                            case sql_type::FLTN:
                            case sql_type::TIME:
                            case sql_type::DATETIME2:
                            case sql_type::DATETIMN:
                            case sql_type::DATETIMEOFFSET:
                            case sql_type::BITN:
                            case sql_type::MONEYN:
                            case sql_type::UNIQUEIDENTIFIER:
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                                col.max_length = *(uint8_t*)sv2.data();

                                len++;
                                sv2 = sv2.substr(1);
                                break;

                            case sql_type::VARCHAR:
                            case sql_type::NVARCHAR:
                            case sql_type::CHAR:
                            case sql_type::NCHAR: {
                                if (sv2.length() < sizeof(uint16_t) + sizeof(collation))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(uint16_t) + sizeof(collation));

                                col.max_length = *(uint16_t*)sv2.data();

                                col.coll = *(collation*)(sv2.data() + sizeof(uint16_t));

                                if ((c.type == sql_type::CHAR || c.type == sql_type::VARCHAR) && conn.impl->has_utf8)
                                    col.utf8 = col.coll.utf8;

                                len += sizeof(uint16_t) + sizeof(collation);
                                sv2 = sv2.substr(sizeof(uint16_t) + sizeof(collation));
                                break;
                            }

                            case sql_type::VARBINARY:
                            case sql_type::BINARY:
                                if (sv2.length() < sizeof(uint16_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), sizeof(uint16_t));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t);
                                sv2 = sv2.substr(sizeof(uint16_t));
                                break;

                            case sql_type::XML:
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                                len += sizeof(uint8_t);
                                sv2 = sv2.substr(sizeof(uint8_t));
                                break;

                            case sql_type::DECIMAL:
                            case sql_type::NUMERIC:
                                if (sv2.length() < 3)
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 3).", sv2.length());

                                col.max_length = (uint8_t)sv2[0];
                                col.precision = (uint8_t)sv2[1];
                                col.scale = (uint8_t)sv2[2];

                                len += 3;
                                sv2 = sv2.substr(3);

                                break;

                            case sql_type::SQL_VARIANT:
                                if (sv2.length() < sizeof(uint32_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 4).", sv2.length());

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));
                                break;

                            case sql_type::IMAGE:
                            case sql_type::NTEXT:
                            case sql_type::TEXT:
                            {
                                if (sv2.length() < sizeof(uint32_t))
                                    throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 4).", sv2.length());

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));

                                if (c.type == sql_type::TEXT || c.type == sql_type::NTEXT) {
                                    if (sv2.length() < sizeof(collation))
                                        throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 5).", sv2.length());

                                    sv2 = sv2.substr(sizeof(collation));
                                }

                                if (sv2.length() < 1)
                                    return;

                                auto num_parts = (uint8_t)sv2[0];

                                sv2 = sv2.substr(1);

                                for (uint8_t j = 0; j < num_parts; j++) {
                                    if (sv2.length() < sizeof(uint16_t))
                                        return;

                                    auto partlen = *(uint16_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint16_t));

                                    if (sv2.length() < partlen * sizeof(char16_t))
                                        return;

                                    sv2 = sv2.substr(partlen * sizeof(char16_t));
                                }

                                break;
                            }

                            default:
                                throw formatted_error("Unhandled type {} in COLMETADATA message.", c.type);
                        }

                        if (sv2.length() < 1)
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least 1).", sv2.length());

                        auto name_len = *(uint8_t*)&sv2[0];

                        sv2 = sv2.substr(1);
                        len++;

                        if (sv2.length() < name_len * sizeof(char16_t))
                            throw formatted_error("Short COLMETADATA message ({} bytes left, expected at least {}).", sv2.length(), name_len * sizeof(char16_t));

                        col.name = u16string_view((char16_t*)sv2.data(), name_len);

                        sv2 = sv2.substr(name_len * sizeof(char16_t));
                        len += name_len * sizeof(char16_t);
                    }

                    break;
                }

                case token::ROW:
                {
                    vector<value> row;

                    row.resize(cols.size());

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        handle_row_col(col, cols[i].type, cols[i].max_length, cols[i].coll, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case token::NBCROW:
                {
                    if (cols.empty())
                        break;

                    vector<value> row;

                    row.resize(cols.size());

                    auto bitset_length = (cols.size() + 7) / 8;

                    if (sv.length() < bitset_length)
                        throw formatted_error("Short NBCROW message ({} bytes, expected at least {}).", sv.length(), bitset_length);

                    string_view bitset(sv.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv = sv.substr(bitset_length);

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        if (i != 0) {
                            if ((i & 7) == 0) {
                                bitset = bitset.substr(1);
                                bsv = (uint8_t)bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (bsv & 1) // NULL
                            col.is_null = true;
                        else
                            handle_row_col(col, cols[i].type, cols[i].max_length, cols[i].coll, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case token::ORDER:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short ORDER message ({} bytes, expected at least {}).", sv.length(), sizeof(uint16_t));

                    auto len = *(uint16_t*)sv.data();
                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short ORDER message ({} bytes, expected {}).", sv.length(), len);

                    break;
                }

                case token::RETURNSTATUS:
                {
                    if (sv.length() < sizeof(int32_t))
                        throw formatted_error("Short RETURNSTATUS message ({} bytes, expected 4).", sv.length());

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} while executing SQL batch.", type);
            }
        }

        if (last_packet)
            finished = true;
    }

    bool batch_impl::fetch_row() {
        while (!rows.empty() || !finished) {
            if (!rows.empty()) {
                auto r = move(rows.front());

                rows.pop_front();

                for (unsigned int i = 0; i < r.size(); i++) {
                    cols[i].is_null = r[i].is_null;

                    if (!cols[i].is_null)
                        cols[i].val = move(r[i].val);
                }

                return true;
            }

            if (finished)
                return false;

            wait_for_packet();
        }

        return false;
    }

    bool batch::fetch_row() {
        return impl->fetch_row();
    }

    uint16_t batch::num_columns() const {
        return (uint16_t)impl->cols.size();
    }

    const column& batch::operator[](uint16_t i) const {
        return impl->cols[i];
    }

    void tds_impl::handle_envchange_msg(const string_view& sv) {
        auto ec = (tds_envchange*)(sv.data() - offsetof(tds_envchange, type));

        switch (ec->type) {
            case tds_envchange_type::begin_trans: {
                if (sv.length() < sizeof(tds_envchange_begin_trans) - offsetof(tds_envchange_begin_trans, header.type))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", sv.length());

                auto tebt = (tds_envchange_begin_trans*)ec;

                if (tebt->header.length < offsetof(tds_envchange_begin_trans, new_len))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", tebt->header.length);

                if (tebt->new_len != 8)
                    throw formatted_error("Unexpected transaction ID length ({} bytes, expected 8).", tebt->new_len);

                trans_id = tebt->trans_id;

                break;
            }

            case tds_envchange_type::rollback_trans: {
                if (sv.length() < sizeof(tds_envchange_rollback_trans) - offsetof(tds_envchange_rollback_trans, header.type))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", sv.length());

                auto tert = (tds_envchange_rollback_trans*)ec;

                if (tert->header.length < offsetof(tds_envchange_rollback_trans, new_len))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", tert->header.length);

                trans_id = 0;

                break;
            }

            case tds_envchange_type::commit_trans: {
                if (sv.length() < sizeof(tds_envchange_commit_trans) - offsetof(tds_envchange_begin_trans, header.type))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", sv.length());

                auto tect = (tds_envchange_commit_trans*)ec;

                if (tect->header.length < offsetof(tds_envchange_begin_trans, new_len))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected 11).", tect->header.length);

                trans_id = 0;

                break;
            }

            case tds_envchange_type::packet_size: {
                if (sv.length() < sizeof(tds_envchange_packet_size) - offsetof(tds_envchange_packet_size, header.type))
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected at least 2).", sv.length());

                auto teps = (tds_envchange_packet_size*)ec;

                if (teps->header.length < sizeof(tds_envchange_packet_size) + (teps->new_len * sizeof(char16_t))) {
                    throw formatted_error("Short ENVCHANGE message ({} bytes, expected at least {}).",
                                          teps->header.length, sizeof(tds_envchange_packet_size) + (teps->new_len * sizeof(char16_t)));
                }

                u16string_view s((char16_t*)&teps[1], teps->new_len);
                uint32_t v = 0;

                for (auto c : s) {
                    if (c >= '0' && c <= '9') {
                        v *= 10;
                        v += c - '0';
                    } else
                        throw formatted_error("Server returned invalid packet size \"{}\".", utf16_to_utf8(s));
                }

                packet_size = v;

                break;
            }

            default:
            break;
        }
    }

    trans::trans(tds& conn) : conn(conn) {
        tds_tm_begin msg;

        // FIXME - give transactions names, so that ROLLBACK works as expected?

        msg.header.all_headers.total_size = sizeof(tds_all_headers);
        msg.header.all_headers.size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
        msg.header.all_headers.trans_desc.type = 2; // transaction descriptor
        msg.header.all_headers.trans_desc.descriptor = conn.impl->trans_id;
        msg.header.all_headers.trans_desc.outstanding = 1;
        msg.header.type = tds_tm_type::TM_BEGIN_XACT;
        msg.isolation_level = 0;
        msg.name_len = 0;

        conn.impl->send_msg(tds_msg::trans_man_req, string_view((char*)&msg, sizeof(msg)));

        enum tds_msg type;
        string payload;

        // FIXME - timeout
        conn.impl->wait_for_msg(type, payload);

        if (type != tds_msg::tabular_result)
            throw formatted_error("Received message type {}, expected tabular_result", (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case token::DONE:
                case token::DONEINPROC:
                case token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                    sv = sv.substr(sizeof(tds_done_msg));
                break;

                case token::INFO:
                case token::TDS_ERROR:
                case token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                    if (type == token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error("TM_BEGIN_XACT request failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} in transaction manager response.", type);
            }
        }
    }

    trans::~trans() {
        if (committed)
            return;

        if (conn.impl->trans_id == 0)
            return;

        try {
            tds_tm_rollback msg;

            msg.header.all_headers.total_size = sizeof(tds_all_headers);
            msg.header.all_headers.size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
            msg.header.all_headers.trans_desc.type = 2; // transaction descriptor
            msg.header.all_headers.trans_desc.descriptor = conn.impl->trans_id;
            msg.header.all_headers.trans_desc.outstanding = 1;
            msg.header.type = tds_tm_type::TM_ROLLBACK_XACT;
            msg.name_len = 0;
            msg.flags = 0;

            conn.impl->send_msg(tds_msg::trans_man_req, string_view((char*)&msg, sizeof(msg)));

            enum tds_msg type;
            string payload;

            // FIXME - timeout
            conn.impl->wait_for_msg(type, payload);

            if (type != tds_msg::tabular_result)
                throw formatted_error("Received message type {}, expected tabular_result", (int)type);

            string_view sv = payload;

            while (!sv.empty()) {
                auto type = (token)sv[0];
                sv = sv.substr(1);

                switch (type) {
                    case token::DONE:
                    case token::DONEINPROC:
                    case token::DONEPROC:
                        if (sv.length() < sizeof(tds_done_msg))
                            throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                        sv = sv.substr(sizeof(tds_done_msg));
                        break;

                    case token::INFO:
                    case token::TDS_ERROR:
                    case token::ENVCHANGE:
                    {
                        if (sv.length() < sizeof(uint16_t))
                            throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                        auto len = *(uint16_t*)&sv[0];

                        sv = sv.substr(sizeof(uint16_t));

                        if (sv.length() < len)
                            throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                        if (type == token::INFO) {
                            if (conn.impl->message_handler) {
                                try {
                                    conn.impl->handle_info_msg(sv.substr(0, len), false);
                                } catch (...) {
                                }
                            }

                        } else if (type == token::TDS_ERROR) {
                            if (conn.impl->message_handler) {
                                try {
                                    conn.impl->handle_info_msg(sv.substr(0, len), true);
                                } catch (...) {
                                }
                            }

                            throw formatted_error("TM_ROLLBACK_XACT request failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                        } else if (type == token::ENVCHANGE)
                            conn.impl->handle_envchange_msg(sv.substr(0, len));

                        sv = sv.substr(len);

                        break;
                    }

                    default:
                        throw formatted_error("Unhandled token type {} in transaction manager response.", type);
                }
            }
        } catch (...) {
            // can't throw in destructor
        }
    }

    void trans::commit() {
        tds_tm_commit msg;

        msg.header.all_headers.total_size = sizeof(tds_all_headers);
        msg.header.all_headers.size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
        msg.header.all_headers.trans_desc.type = 2; // transaction descriptor
        msg.header.all_headers.trans_desc.descriptor = conn.impl->trans_id;
        msg.header.all_headers.trans_desc.outstanding = 1;
        msg.header.type = tds_tm_type::TM_COMMIT_XACT;
        msg.name_len = 0;
        msg.flags = 0;

        conn.impl->send_msg(tds_msg::trans_man_req, string_view((char*)&msg, sizeof(msg)));

        enum tds_msg type;
        string payload;

        // FIXME - timeout
        conn.impl->wait_for_msg(type, payload);

        if (type != tds_msg::tabular_result)
            throw formatted_error("Received message type {}, expected tabular_result", (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case token::DONE:
                case token::DONEINPROC:
                case token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), sizeof(tds_done_msg));

                    sv = sv.substr(sizeof(tds_done_msg));
                break;

                case token::INFO:
                case token::TDS_ERROR:
                case token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error("Short {} message ({} bytes, expected at least 2).", type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error("Short {} message ({} bytes, expected {}).", type, sv.length(), len);

                    if (type == token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error("TM_COMMIT_XACT request failed: {}", utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error("Unhandled token type {} in transaction manager response.", type);
            }
        }

        committed = true;
    }

    void TDSCPP to_json(nlohmann::json& j, const value& v) {
        auto type2 = v.type;
        string_view val = v.val;

        if (v.is_null) {
            j = nlohmann::json(nullptr);
            return;
        }

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)val[0];

            val = val.substr(1);

            auto propbytes = (uint8_t)val[0];

            val = val.substr(1 + propbytes);
        }

        switch (type2) {
            case sql_type::INTN:
            case sql_type::TINYINT:
            case sql_type::SMALLINT:
            case sql_type::INT:
            case sql_type::BIGINT:
                j = nlohmann::json((int64_t)v);
                break;

            case sql_type::NUMERIC:
            case sql_type::DECIMAL:
            case sql_type::FLOAT:
            case sql_type::REAL:
            case sql_type::MONEYN:
            case sql_type::MONEY:
            case sql_type::SMALLMONEY:
                j = nlohmann::json((double)v);
                break;

            case sql_type::BITN:
            case sql_type::BIT:
                j = nlohmann::json(val[0] != 0);
                break;

            default:
                j = nlohmann::json((string)v);
        }
    }

    uint16_t rpc::num_columns() const {
        return (uint16_t)cols.size();
    }

    const column& rpc::operator[](uint16_t i) const {
        return cols[i];
    }

    uint16_t tds::spid() const {
        return impl->spid;
    }

    static uint16_t parse_instance_string(string_view s, const string_view& instance) {
        vector<string_view> instance_list;

        while (!s.empty()) {
            auto ds = s.find(";;");
            string_view t;
            bool this_instance = false;

            if (ds == string::npos) {
                t = s;
                s = "";
            } else {
                t = s.substr(0, ds);
                s = s.substr(ds + 2);
            }

            vector<string_view> el;

            while (!t.empty()) {
                auto sc = t.find(";");

                if (sc == string::npos) {
                    el.emplace_back(t.data(), t.length());
                    break;
                } else {
                    el.emplace_back(t.data(), sc);
                    t = t.substr(sc + 1);
                }
            }

            for (size_t i = 0; i < el.size(); i++) {
                if (el[i] == "InstanceName" && i < el.size() - 1) {
                    this_instance = el[i+1] == instance; // FIXME - should be case-insensitive?

                    if (!this_instance) {
                        instance_list.push_back(el[i+1]);
                        break;
                    }
                } else if (el[i] == "tcp" && i < el.size() - 1 && this_instance) {
                    uint16_t ret;

                    auto fc = from_chars(el[i+1].data(), el[i+1].data() + el[i+1].length() - 1, ret);

                    if (fc.ec == errc::invalid_argument)
                        throw formatted_error("Could not convert port \"{}\" to integer.", el[i+1]);
                    else if (fc.ec == errc::result_out_of_range)
                        throw formatted_error("Port \"{}\" was too large to convert to 16-bit integer.", el[i+1]);

                    return ret;
                }
            }
        }

        auto exc = fmt::format("{} not found in instance list (found ", instance);

        for (unsigned int i = 0; i < instance_list.size(); i++) {
            if (i > 0)
                exc += ", ";

            exc += instance_list[i];
        }

        exc += ")";

        throw runtime_error(exc);
    }

    uint16_t get_instance_port(const string& server, const string_view& instance) {
        struct addrinfo hints;
        struct addrinfo* res;
        struct addrinfo* orig_res;
        uint8_t msg_type;
        uint16_t msg_len, port;
#ifdef _WIN32
        WSADATA wsa_data;
        SOCKET sock = INVALID_SOCKET;
#else
        int sock = 0;
#endif

#ifdef _WIN32

        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
            throw runtime_error("WSAStartup failed.");
#endif

        // connect to port 1434 via UDP

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = /*AF_UNSPEC*/AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        auto ret = (int)getaddrinfo(server.c_str(), nullptr, &hints, &res);

        if (ret != 0)
            throw formatted_error("getaddrinfo returned {}", ret);

        orig_res = res;
#ifdef _WIN32
        sock = INVALID_SOCKET;
#else
        sock = 0;
#endif

        do {
            sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

#ifdef _WIN32
            if (sock == INVALID_SOCKET)
                continue;
#else
            if (sock < 0)
                continue;
#endif

            if (res->ai_family == AF_INET)
                ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(BROWSER_PORT);
            else if (res->ai_family == AF_INET6)
                ((struct sockaddr_in6*)res->ai_addr)->sin6_port = htons(BROWSER_PORT);
            else {
#ifdef _WIN32
                closesocket(sock);
                sock = INVALID_SOCKET;
#else
                close(sock);
                sock = 0;
#endif
                continue;
            }

            if (::connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
#ifdef _WIN32
                closesocket(sock);
                sock = INVALID_SOCKET;
#else
                close(sock);
                sock = 0;
#endif
                continue;
            }

            break;
        } while ((res = res->ai_next));

        freeaddrinfo(orig_res);

#ifdef _WIN32
        if (sock == INVALID_SOCKET)
            throw formatted_error("Could not connect to {}:{}.", server, BROWSER_PORT);
#else
        if (sock <= 0)
            throw formatted_error("Could not connect to {}:{}.", server, BROWSER_PORT);
#endif

        try {
            ret = (int)send(sock, "\x03", 1, 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error("send failed (error {})", WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error("send failed (error {})", errno);
#endif

            // FIXME - 1 second timeout

            // wait for reply

            ret = (int)recv(sock, (char*)&msg_type, 1, 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error("recv failed (error {})", WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error("recv failed (error {})", errno);
#endif

            if (msg_type != 0x05)
                throw formatted_error("response message type was {:02x}, expected 05", msg_type);

            ret = (int)recv(sock, (char*)&msg_len, sizeof(msg_len), 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error("recv failed (error {})", WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error("recv failed (error {})", errno);
#endif

            string resp(msg_len, 0);

            ret = (int)recv(sock, resp.data(), (int)resp.length(), 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error("recv failed (error {})", WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error("recv failed (error {})", errno);
#endif

            port = parse_instance_string(resp, instance);
        } catch (...) {
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            throw;
        }

#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif

        return port;
    }

    datetimeoffset datetimeoffset::now() {
        auto n = chrono::system_clock::now();
        auto secs = chrono::duration_cast<chrono::seconds>(n.time_since_epoch()).count();
        struct tm t;
        int offset;

        // FIXME - use zoned_time for this, when it's better supported?

#ifdef WIN32
        localtime_s(&t, &secs);

        offset = (int)(_mkgmtime(&t) - secs);
#else
        localtime_r(&secs, &t);

        offset = (int)t.tm_gmtoff;
#endif

        n += chrono::seconds(offset);

        return {n, (int16_t)(offset / 60)};
    }
};
