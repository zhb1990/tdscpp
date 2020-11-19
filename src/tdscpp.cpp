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

using namespace std;

static const uint32_t tds_74_version = 0x4000074;

template<>
struct fmt::formatter<enum tds_token> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum tds_token t, format_context& ctx) {
        switch (t) {
            case tds_token::OFFSET:
                return format_to(ctx.out(), "OFFSET");

            case tds_token::RETURNSTATUS:
                return format_to(ctx.out(), "RETURNSTATUS");

            case tds_token::COLMETADATA:
                return format_to(ctx.out(), "COLMETADATA");

            case tds_token::ALTMETADATA:
                return format_to(ctx.out(), "ALTMETADATA");

            case tds_token::DATACLASSIFICATION:
                return format_to(ctx.out(), "DATACLASSIFICATION");

            case tds_token::TABNAME:
                return format_to(ctx.out(), "TABNAME");

            case tds_token::COLINFO:
                return format_to(ctx.out(), "COLINFO");

            case tds_token::ORDER:
                return format_to(ctx.out(), "ORDER");

            case tds_token::TDS_ERROR:
                return format_to(ctx.out(), "ERROR");

            case tds_token::INFO:
                return format_to(ctx.out(), "INFO");

            case tds_token::RETURNVALUE:
                return format_to(ctx.out(), "RETURNVALUE");

            case tds_token::LOGINACK:
                return format_to(ctx.out(), "LOGINACK");

            case tds_token::FEATUREEXTACK:
                return format_to(ctx.out(), "FEATUREEXTACK");

            case tds_token::ROW:
                return format_to(ctx.out(), "ROW");

            case tds_token::NBCROW:
                return format_to(ctx.out(), "NBCROW");

            case tds_token::ALTROW:
                return format_to(ctx.out(), "ALTROW");

            case tds_token::ENVCHANGE:
                return format_to(ctx.out(), "ENVCHANGE");

            case tds_token::SESSIONSTATE:
                return format_to(ctx.out(), "SESSIONSTATE");

            case tds_token::SSPI:
                return format_to(ctx.out(), "SSPI");

            case tds_token::FEDAUTHINFO:
                return format_to(ctx.out(), "FEDAUTHINFO");

            case tds_token::DONE:
                return format_to(ctx.out(), "DONE");

            case tds_token::DONEPROC:
                return format_to(ctx.out(), "DONEPROC");

            case tds_token::DONEINPROC:
                return format_to(ctx.out(), "DONEINPROC");

            default:
                return format_to(ctx.out(), "{:x}", (uint8_t)t);
        }
    }
};

static u16string utf8_to_utf16(const string_view& sv) {
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

static string utf16_to_utf8(const u16string_view& sv) {
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

#ifdef HAVE_GSSAPI
class gss_error : public exception {
public:
    gss_error(const string& func, OM_uint32 major, OM_uint32 minor) {
        OM_uint32 message_context = 0;
        OM_uint32 min_status;
        gss_buffer_desc status_string;
        bool first = true;

        msg = fmt::format(FMT_STRING("{} failed (minor {}): "), func, minor);

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
            throw formatted_error(FMT_STRING("getaddrinfo returned {}"), ret);

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
            throw formatted_error(FMT_STRING("Could not connect to {}:{}."), server, port);
#else
        if (sock <= 0)
            throw formatted_error(FMT_STRING("Could not connect to {}:{}."), server, port);
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
                throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

            // FIXME - parse payload for anything we care about (in particular, what server says about encryption)
        }
    }

    void tds_impl::send_login_msg(const string_view& user, const string_view& password, const string_view& server,
                                  const string_view& app_name) {
        enum tds_msg type;
        string payload, sspi;
        u16string spn;
#ifdef _WIN32
        CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
        CtxtHandle ctx_handle;
#elif defined(HAVE_GSSAPI)
        gss_cred_id_t cred_handle = 0;
        gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
#endif

        auto user_u16 = utf8_to_utf16(user);
        auto password_u16 = utf8_to_utf16(password);

        if (user.empty()) {
            if (fqdn.empty())
                throw runtime_error("Could not do SSPI authentication as could not find server FQDN.");

            spn = u"MSSQLSvc/" + utf8_to_utf16(fqdn);

#ifdef _WIN32
            SECURITY_STATUS sec_status;
            TimeStamp timestamp;
            SecBuffer outbuf;
            SecBufferDesc out;
            unsigned long context_attr;

            if (!SecIsValidHandle(&cred_handle)) {
                sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)L"Negotiate", SECPKG_CRED_OUTBOUND, nullptr,
                                                       nullptr, nullptr, nullptr, &cred_handle, &timestamp);
                if (FAILED(sec_status))
                    throw formatted_error(FMT_STRING("AcquireCredentialsHandle returned {:08x}"), (uint32_t)sec_status);
            }

            outbuf.cbBuffer = 0;
            outbuf.BufferType = SECBUFFER_TOKEN;
            outbuf.pvBuffer = nullptr;

            out.ulVersion = SECBUFFER_VERSION;
            out.cBuffers = 1;
            out.pBuffers = &outbuf;

            sec_status = InitializeSecurityContextW(&cred_handle, nullptr, (SEC_WCHAR*)spn.c_str(),
                                                    ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, nullptr, 0,
                                                    &ctx_handle, &out, &context_attr, &timestamp);
            if (FAILED(sec_status))
                throw formatted_error(FMT_STRING("InitializeSecurityContext returned {:08x}"), (uint32_t)sec_status);

            // FIXME - free ctx_handle eventually

//             ctx_handle_set = true;

            sspi = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

            if (outbuf.pvBuffer)
                FreeContextBuffer(outbuf.pvBuffer);

            if (sec_status != SEC_I_CONTINUE_NEEDED && sec_status != SEC_I_COMPLETE_AND_CONTINUE && sec_status != SEC_E_OK)
                throw formatted_error(FMT_STRING("InitializeSecurityContext returned unexpected status {:08x}"), (uint32_t)sec_status);
#elif defined(HAVE_GSSAPI)
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
            if (major_status != GSS_S_COMPLETE)
                throw gss_error("gss_import_name", major_status, minor_status);

            recv_tok.length = 0;
            recv_tok.value = nullptr;

            major_status = gss_init_sec_context(&minor_status, cred_handle, &ctx_handle, gss_name, GSS_C_NO_OID,
                                                GSS_C_DELEG_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                                &recv_tok, nullptr, &send_tok, nullptr, nullptr);

            if (major_status != GSS_S_CONTINUE_NEEDED && major_status != GSS_S_COMPLETE)
                throw gss_error("gss_init_sec_context", major_status, minor_status);

            if (send_tok.length != 0) {
                sspi = string((char*)send_tok.value, send_tok.length);

                gss_release_buffer(&minor_status, &send_tok);
            }
#else
            throw runtime_error("No username given and Kerberos support not compiled in.");
#endif
        }

        u16string client_name;

        {
            char s[255];

            if (gethostname(s, sizeof(s)) != 0) {
#ifdef _WIN32
                throw formatted_error(FMT_STRING("gethostname failed (error {})"), WSAGetLastError());
#else
                throw formatted_error(FMT_STRING("gethostname failed (error {})"), errno);
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

        bool received_loginack, go_again;

        do {
            wait_for_msg(type, payload);
            // FIXME - timeout

            if (type != tds_msg::tabular_result)
                throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

            string_view sv = payload;

            received_loginack = false;
            go_again = false;

            while (!sv.empty()) {
                auto type = (tds_token)sv[0];
                sv = sv.substr(1);

                switch (type) {
                    case tds_token::DONE:
                    case tds_token::DONEINPROC:
                    case tds_token::DONEPROC:
                        if (sv.length() < sizeof(tds_done_msg))
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                        sv = sv.substr(sizeof(tds_done_msg));

                        break;

                    case tds_token::LOGINACK:
                    case tds_token::INFO:
                    case tds_token::TDS_ERROR:
                    case tds_token::ENVCHANGE:
                    {
                        if (sv.length() < sizeof(uint16_t))
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                        auto len = *(uint16_t*)&sv[0];

                        sv = sv.substr(sizeof(uint16_t));

                        if (sv.length() < len)
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                        if (type == tds_token::LOGINACK) {
                            handle_loginack_msg(sv.substr(0, len));
                            received_loginack = true;
                        } else if (type == tds_token::INFO) {
                            if (message_handler)
                                handle_info_msg(sv.substr(0, len), false);
                        } else if (type == tds_token::TDS_ERROR) {
                            if (message_handler)
                                handle_info_msg(sv.substr(0, len), true);
                        } else if (type == tds_token::ENVCHANGE)
                            handle_envchange_msg(sv.substr(0, len));

                        sv = sv.substr(len);

                        break;
                    }

#ifdef _WIN32
                    case tds_token::SSPI: // FIXME - handle doing this with GSSAPI
                    {
                        if (sv.length() < sizeof(uint16_t))
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                        auto len = *(uint16_t*)&sv[0];

                        sv = sv.substr(sizeof(uint16_t));

                        if (sv.length() < len)
                            throw formatted_error(FMT_STRING("Short SSPI token ({} bytes, expected {})."), type, sv.length(), len);

                        send_sspi_msg(&cred_handle, &ctx_handle, spn, sv.substr(0, len));

                        sv = sv.substr(len);

                        go_again = true;

                        break;
                    }
#endif

                    default:
                        throw formatted_error(FMT_STRING("Unhandled token type {} while logging in."), type);
                }
            }
        } while (go_again);

        if (!received_loginack)
            throw formatted_error(FMT_STRING("Did not receive LOGINACK message from server."));
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
            throw formatted_error(FMT_STRING("InitializeSecurityContext returned {:08x}"), (uint32_t)sec_status);

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

        // FIXME - send features list (UTF-8 support etc.)

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
        msg->option_flags3 = option_flags3;
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

        msg->unused_offset = 0;
        msg->unused_length = 0;

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
        }

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

            auto ret = send(sock, payload.data(), (int)payload.length(), 0);

#ifdef _WIN32
            if (ret < 0)
                throw formatted_error(FMT_STRING("send failed (error {})"), WSAGetLastError());
#else
            if (ret < 0)
                throw formatted_error(FMT_STRING("send failed (error {})"), errno);
#endif

            if ((size_t)ret < payload.length())
                throw formatted_error(FMT_STRING("send sent {} bytes, expected {}"), ret, payload.length());

            if (sv2.length() == sv.length())
                return;

            sv = sv.substr(size);
        }
    }

    void tds_impl::wait_for_msg(enum tds_msg& type, string& payload, bool* last_packet) {
        tds_header h;

        auto ret = recv(sock, (char*)&h, sizeof(tds_header), MSG_WAITALL);

#ifdef _WIN32
        if (ret < 0)
            throw formatted_error(FMT_STRING("recv failed (error {})"), WSAGetLastError());
#else
        if (ret < 0)
            throw formatted_error(FMT_STRING("recv failed (error {})"), errno);
#endif

        if (ret == 0)
            throw formatted_error(FMT_STRING("Disconnected."));

        if ((size_t)ret < sizeof(h))
            throw formatted_error(FMT_STRING("recv received {} bytes, expected {}"), ret, sizeof(h));

        if (htons(h.length) < sizeof(tds_header)) {
            throw formatted_error(FMT_STRING("message length was {}, expected at least {}"),
                                    htons(h.length), sizeof(tds_header));
        }

        type = h.type;

        if (htons(h.length) > sizeof(tds_header)) {
            auto len = htons(h.length) - sizeof(tds_header);

            payload.resize(len);

            ret = recv(sock, payload.data(), (int)len, MSG_WAITALL);

            if (ret < 0)
                throw formatted_error(FMT_STRING("recv failed (error {})"), errno);

            if (ret == 0)
                throw formatted_error(FMT_STRING("Disconnected."));

            if ((unsigned int)ret < len)
                throw formatted_error(FMT_STRING("recv received {} bytes, expected {}"), ret, len);
        } else
            payload.clear();

        if (last_packet)
            *last_packet = h.status & 1;
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
            throw formatted_error(FMT_STRING("Server not using TDS 7.4. Version was {:x}, expected {:x}."), tds_version, tds_74_version);
    }

    void tds_impl::handle_info_msg(const string_view& sv, bool error) {
        uint16_t msg_len;
        uint8_t server_name_len, proc_name_len, state, severity;
        u16string_view msg, server_name, proc_name;
        int32_t msgno, line_number;

        if (sv.length() < 14)
            throw formatted_error(FMT_STRING("Short INFO message ({} bytes, expected at least 14)."), sv.length());

        msg_len = *(uint16_t*)&sv[6];

        if (sv.length() < 14 + (msg_len * sizeof(char16_t))) {
            throw formatted_error(FMT_STRING("Short INFO message ({} bytes, expected at least {})."),
                                    sv.length(), 14 + (msg_len * sizeof(char16_t)));
        }

        server_name_len = (uint8_t)sv[8 + (msg_len * sizeof(char16_t))];

        if (sv.length() < 14 + ((msg_len + server_name_len) * sizeof(char16_t))) {
            throw formatted_error(FMT_STRING("Short INFO message ({} bytes, expected at least {})."),
                                    sv.length(), 14 + ((msg_len + server_name_len) * sizeof(char16_t)));
        }

        proc_name_len = (uint8_t)sv[8 + ((msg_len + server_name_len) * sizeof(char16_t))];

        if (sv.length() < 14 + ((msg_len + server_name_len + proc_name_len) * sizeof(char16_t))) {
            throw formatted_error(FMT_STRING("Short INFO message ({} bytes, expected at least {})."),
                                    sv.length(), 14 + ((msg_len + server_name_len + proc_name_len) * sizeof(char16_t)));
        }

        msgno = *(int32_t*)&sv[0];
        state = (uint8_t)sv[4];
        severity = (uint8_t)sv[5];
        msg = u16string_view((char16_t*)&sv[8], msg_len);
        server_name = u16string_view((char16_t*)&sv[9 + (msg_len * sizeof(char16_t))], server_name_len);
        proc_name = u16string_view((char16_t*)&sv[10 + ((msg_len + server_name_len) * sizeof(char16_t))], proc_name_len);
        line_number = *(int32_t*)&sv[10 + ((msg_len + server_name_len + proc_name_len) * sizeof(char16_t))];

        message_handler(utf16_to_utf8(server_name), utf16_to_utf8(msg), utf16_to_utf8(proc_name), msgno, line_number, state,
                        severity, error);
    }

    date::date(int32_t num) : num(num) {
        signed long long j, e, f, g, h;

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
    }

    date::date(uint16_t year, uint8_t month, uint8_t day) : year(year), month(month), day(day) {
        int m2 = ((int)month - 14) / 12;
        long long n;

        n = (1461 * ((int)year + 4800 + m2)) / 4;
        n += (367 * ((int)month - 2 - (12 * m2))) / 12;
        n -= (3 * (((int)year + 4900 + m2)/100)) / 4;
        n += day;
        n -= 2447096;

        num = static_cast<int>(n);
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
        auto s = utf8_to_utf16(string_view((char*)sv.data(), sv.length()));

        type = sql_type::NVARCHAR;
        val.resize(s.length() * sizeof(char16_t));
        memcpy(val.data(), s.data(), val.length());
    }

    value::value(const u8string& sv) : value(u8string_view(sv)) {
    }

    value::value(const char8_t* sv) : value(u8string_view(sv)) {
    }

    value::value(const optional<u8string_view>& sv) {
        type = sql_type::NVARCHAR;

        if (!sv.has_value())
            is_null = true;
        else {
            auto s = utf8_to_utf16(string_view((char*)sv.value().data(), sv.value().length()));

            val.resize(s.length() * sizeof(char16_t));
            memcpy(val.data(), s.data(), s.length());
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

    value::value(const date& d) {
        int32_t n;

        type = sql_type::DATE;
        val.resize(3);

        n = d.num + 693595;
        memcpy(val.data(), &n, 3);
    }

    value::value(const optional<date>& d) {
        type = sql_type::DATE;

        if (!d.has_value())
            is_null = true;
        else {
            int32_t n = d.value().num + 693595;
            val.resize(3);
            memcpy(val.data(), &n, 3);
        }
    }

    value::value(const time& t) {
        uint32_t secs;

        secs = (unsigned int)t.hour * 3600;
        secs += (unsigned int)t.minute * 60;
        secs += t.second;

        type = sql_type::TIME;
        max_length = 0; // TIME(0)

        val.resize(3);
        memcpy(val.data(), &secs, val.length());
    }

    value::value(const optional<time>& t) {
        type = sql_type::TIME;
        max_length = 0; // TIME(0)

        if (!t.has_value())
            is_null = true;
        else {
            uint32_t secs;

            secs = (unsigned int)t.value().hour * 3600;
            secs += (unsigned int)t.value().minute * 60;
            secs += t.value().second;

            val.resize(3);
            memcpy(val.data(), &secs, val.length());
        }
    }

    value::value(const datetime& dt) {
        int32_t n;
        uint32_t secs;

        type = sql_type::DATETIME2;
        val.resize(6);
        max_length = 0; // DATETIME2(0)

        secs = (unsigned int)dt.t.hour * 3600;
        secs += (unsigned int)dt.t.minute * 60;
        secs += dt.t.second;

        memcpy(val.data(), &secs, 3);

        n = dt.d.num + 693595;
        memcpy(val.data() + 3, &n, 3);
    }

    value::value(const optional<datetime>& dt) {
        type = sql_type::DATETIME2;
        val.resize(6);
        max_length = 0; // DATETIME2(0)

        if (!dt.has_value())
            is_null = true;
        else {
            int32_t n;
            uint32_t secs;

            secs = (unsigned int)dt.value().t.hour * 3600;
            secs += (unsigned int)dt.value().t.minute * 60;
            secs += dt.value().t.second;

            memcpy(val.data(), &secs, 3);

            n = dt.value().d.num + 693595;
            memcpy(val.data() + 3, &n, 3);
        }
    }

    value::value(const datetimeoffset& dto) {
        int32_t n;
        uint32_t secs;

        type = sql_type::DATETIMEOFFSET;
        val.resize(8);
        max_length = 0; // DATETIMEOFFSET(0)

        secs = (unsigned int)dto.t.hour * 3600;
        secs += (unsigned int)dto.t.minute * 60;
        secs += dto.t.second;

        memcpy(val.data(), &secs, 3);

        n = dto.d.num + 693595;
        memcpy(val.data() + 3, &n, 3);

        *(int16_t*)(val.data() + 6) = dto.offset;
    }

    value::value(const optional<datetimeoffset>& dto) {
        type = sql_type::DATETIMEOFFSET;
        val.resize(8);
        max_length = 0; // DATETIMEOFFSET(0)

        if (!dto.has_value())
            is_null = true;
        else {
            int32_t n;
            uint32_t secs;

            secs = (unsigned int)dto.value().t.hour * 3600;
            secs += (unsigned int)dto.value().t.minute * 60;
            secs += dto.value().t.second;

            memcpy(val.data(), &secs, 3);

            n = dto.value().d.num + 693595;
            memcpy(val.data() + 3, &n, 3);

            *(int16_t*)(val.data() + 6) = dto.value().offset;
        }
    }

    value::value(const vector<std::byte>& bin) {
        // FIXME - std::optional version of this too

        type = sql_type::VARBINARY;
        val.resize(bin.size());
        memcpy(val.data(), bin.data(), bin.size());
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

    value::operator const string() const {
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
                        throw formatted_error(FMT_STRING("INTN has unexpected length {}."), d.length());
                }
            break;

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            {
                u16string_view sv((char16_t*)d.data(), d.length() / sizeof(char16_t));
                auto s = utf16_to_utf8(sv);

                return fmt::format(FMT_STRING("{}"), s);
            }

            case sql_type::VARCHAR:
            case sql_type::CHAR:
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
                        throw formatted_error(FMT_STRING("FLTN has unexpected length {}."), d.length());
                }
            break;

            case sql_type::DATE: {
                uint32_t v;

                memcpy(&v, d.data(), 3);
                v &= 0xffffff;

                date d(v - 693595);

                return fmt::format(FMT_STRING("{}"), d);
            }

            case sql_type::TIME: {
                uint64_t secs = 0;

                memcpy(&secs, d.data(), min(sizeof(uint64_t), d.length()));

                for (auto n = max_length2; n > 0; n--) {
                    secs /= 10;
                }

                time t((uint32_t)secs);

                return fmt::format(FMT_STRING("{}"), t);
            }

            case sql_type::DATETIME2: {
                uint64_t secs = 0;
                uint32_t v;

                memcpy(&secs, d.data(), min(sizeof(uint64_t), d.length() - 3));

                for (auto n = max_length2; n > 0; n--) {
                    secs /= 10;
                }

                memcpy(&v, d.data() + d.length() - 3, 3);
                v &= 0xffffff;

                datetime dt(v - 693595, (uint32_t)secs);

                return fmt::format(FMT_STRING("{}"), dt);
            }

            case sql_type::DATETIME: {
                auto v = *(int32_t*)d.data();
                auto secs = *(uint32_t*)(d.data() + sizeof(int32_t));

                secs /= 300;

                datetime dt(v, secs);

                return fmt::format(FMT_STRING("{}"), dt);
            }

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4: {
                        auto v = *(uint16_t*)d.data();
                        auto mins = *(uint16_t*)(d.data() + sizeof(uint16_t));

                        datetime dt(v, mins * 60);

                        return fmt::format(FMT_STRING("{}"), dt);
                    }

                    case 8: {
                        auto v = *(int32_t*)d.data();
                        auto secs = *(uint32_t*)(d.data() + sizeof(int32_t));

                        secs /= 300;

                        datetime dt(v, secs);

                        return fmt::format(FMT_STRING("{}"), dt);
                    }

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), d.length());
                }

            case sql_type::DATETIMEOFFSET: {
                uint64_t secs = 0;
                uint32_t v;

                memcpy(&secs, d.data(), min(sizeof(uint64_t), d.length() - 5));

                for (auto n = max_length2; n > 0; n--) {
                    secs /= 10;
                }

                memcpy(&v, d.data() + d.length() - 5, 3);
                v &= 0xffffff;

                datetimeoffset dto(v - 693595, (uint32_t)secs, *(int16_t*)(d.data() + d.length() - sizeof(int16_t)));

                return fmt::format(FMT_STRING("{}"), dto);
            }

            case sql_type::VARBINARY:
            case sql_type::BINARY:
            {
                string s = "0x";

                for (auto c : val) {
                    s += fmt::format(FMT_STRING("{:02x}"), (uint8_t)c);
                }

                return fmt::format(FMT_STRING("{}"), s);
            }

            case sql_type::BITN:
            case sql_type::BIT:
                return fmt::format(FMT_STRING("{}"), val[0] != 0);

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

                return fmt::format(FMT_STRING("{}{}"), val[0] == 0 ? "-" : "", p);
            }


            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to string."), type);
        }
    }

    value::operator const u16string() const {
        if (type == sql_type::NVARCHAR || type == sql_type::NCHAR)
            return u16string(u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t)));
        else
            return utf8_to_utf16(operator const string()); // FIXME - VARCHARs might not be valid UTF-8
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
                        throw formatted_error(FMT_STRING("INTN has unexpected length {}."), d.length());
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
                        throw formatted_error(FMT_STRING("FLTN has unexpected length {}."), d.length());
                }

            case sql_type::BITN:
            case sql_type::BIT:
                return val[0] != 0 ? 1 : 0;

            case sql_type::VARCHAR:
            case sql_type::CHAR:
            {
                if (d.empty())
                    return 0;

                bool first = true;

                for (auto c : val) {
                    if (c == '-') {
                        if (!first)
                            throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), val);
                    } else if (c < '0' || c > '9')
                        throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), val);

                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(d.data(), d.data() + d.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), val);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error(FMT_STRING("String \"{}\" was too large to convert to BIGINT."), val);

                return res;
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
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
                            throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), utf16_to_utf8(v));
                    } else if (c < u'0' || c > u'9')
                        throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), utf16_to_utf8(v));

                    s += (char)c;
                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to integer."), s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error(FMT_STRING("String \"{}\" was too large to convert to BIGINT."), s);

                return res;
            }

            case sql_type::DATETIME:
                return *(int32_t*)d.data(); // MSSQL adds 1 if after midday

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4:
                        return *(uint16_t*)d.data(); // MSSQL adds 1 if after midday

                    case 8:
                        return *(int32_t*)d.data(); // MSSQL adds 1 if after midday

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), d.length());
                }

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
                            throw formatted_error(FMT_STRING("Cannot convert {} to integer."), s);
                    } else if (c == '.')
                        break;
                    else if (c < '0' || c > '9')
                        throw formatted_error(FMT_STRING("Cannot convert {} to integer."), s);

                    first = false;
                }

                int64_t res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error(FMT_STRING("Cannot convert {} to integer."), s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error(FMT_STRING("{} was too large to convert to BIGINT."), s);

                return res;
            }

            // MSSQL doesn't allow conversion to INT for DATE, TIME, DATETIME2, or DATETIMEOFFSET

            // Not allowing VARBINARY even though MSSQL does

            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to integer."), type2);
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

        s = s.substr(rm[0].length());

        return true;
    }

    static bool parse_time(const string_view& t, uint8_t& h, uint8_t& m, uint8_t& s) {
        cmatch rm;
        static const regex r1("^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(\\.([0-9]+))?$");
        static const regex r2("^([0-9]{1,2}):([0-9]{1,2})$");
        static const regex r3("^([0-9]{1,2})( *)([AaPp])[Mm]$");
        static const regex r4("^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(\\.([0-9]+))?( *)([AaPp])[Mm]$");
        static const regex r5("^([0-9]{1,2}):([0-9]{1,2})( *)([AaPp])[Mm]$");

        if (regex_match(&t[0], t.data() + t.length(), rm, r1)) { // hh:mm:ss.s
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), s);
        } else if (regex_match(&t[0], t.data() + t.length(), rm, r2)) { // hh:mm
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            s = 0;
        } else if (regex_match(&t[0], t.data() + t.length(), rm, r3)) { // hh am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            m = 0;
            s = 0;

            auto ap = rm[3].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;
        } else if (regex_match(&t[0], t.data() + t.length(), rm, r4)) { // hh:mm:ss.s am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), s);

            auto ap = rm[7].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;
        } else if (regex_match(&t[0], t.data() + t.length(), rm, r5)) { // hh:mm am
            from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), h);
            from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), m);
            s = 0;

            auto ap = rm[4].str().front();

            if (ap == 'P' || ap == 'p')
                h += 12;
        } else
            return false;

        return true;
    }

    static bool parse_datetime(string_view t, uint16_t& y, uint8_t& mon, uint8_t& d, uint8_t& h, uint8_t& min, uint8_t& s) {
        {
            cmatch rm;
            static const regex iso_date("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\\.([0-9]+))?(Z|([+\\-][0-9]{2}:[0-9]{2}))?$");

            if (regex_match(&t[0], t.data() + t.length(), rm, iso_date)) {
                from_chars(rm[1].str().data(), rm[1].str().data() + rm[1].length(), y);
                from_chars(rm[2].str().data(), rm[2].str().data() + rm[2].length(), mon);
                from_chars(rm[3].str().data(), rm[3].str().data() + rm[3].length(), d);
                from_chars(rm[4].str().data(), rm[4].str().data() + rm[4].length(), h);
                from_chars(rm[5].str().data(), rm[5].str().data() + rm[5].length(), min);
                from_chars(rm[6].str().data(), rm[6].str().data() + rm[6].length(), s);

                if (!is_valid_date(y, mon, d) || h >= 60 || min >= 60 || s >= 60)
                    return false;

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

            if (!parse_time(t, h, min, s) || h >= 60 || min >= 60 || s >= 60)
                return false;

            return true;
        }

        // try to parse solo time

        if (!parse_time(t, h, min, s) || h >= 60 || min >= 60 || s >= 60)
            return false;

        y = 1900;
        mon = 1;
        d = 1;

        return true;
    }

    value::operator const date() const {
        auto type2 = type;
        string_view d = val;

        if (is_null)
            return date{1900, 1, 1};

        if (type2 == sql_type::SQL_VARIANT) {
            type2 = (sql_type)d[0];

            d = d.substr(1);

            auto propbytes = (uint8_t)d[0];

            d = d.substr(1 + propbytes);
        }

        switch (type2) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            {
                uint16_t y;
                uint8_t mon, day, h, min, s;

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
                    return date{1900, 1, 1};

                if (!parse_datetime(t, y, mon, day, h, min, s) || !is_valid_date(y, mon, day))
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to datetime."), d);

                return date{y, mon, day};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            {
                uint16_t y;
                uint8_t mon, day, h, min, s;

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
                    return date{1900, 1, 1};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                auto sv = string_view(t2);

                if (!parse_datetime(sv, y, mon, day, h, min, s) || !is_valid_date(y, mon, day))
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to date."), utf16_to_utf8(u16string_view((char16_t*)d.data(), d.length() / sizeof(char16_t))));

                return date{y, mon, day};
            }

            case sql_type::DATE: {
                uint32_t n = 0;

                memcpy(&n, d.data(), 3);

                return date{(int32_t)n - 693595};
            }

            case sql_type::DATETIME:
                return date{*(int32_t*)d.data()};

            case sql_type::DATETIMN:
                switch (d.length()) {
                    case 4:
                        return date{*(uint16_t*)d.data()};

                    case 8:
                        return date{*(int32_t*)d.data()};

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), d.length());
                }

            case sql_type::DATETIM4:
                return date{*(uint16_t*)d.data()};

            case sql_type::DATETIME2: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 3, 3);

                return date{(int32_t)n - 693595};
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;

                memcpy(&n, d.data() + d.length() - 5, 3);

                return date{(int32_t)n - 693595};
            }

            // MSSQL doesn't allow conversion to DATE for integers, floats, BITs, or TIME

            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to date."), type2);
        }
    }

    value::operator const time() const {
        if (is_null)
            return time{0, 0, 0};

        switch (type) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            {
                uint16_t y;
                uint8_t mon, d, h, min, s;

                auto t = string_view(val);

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1, t.length() - 1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return time{0, 0, 0};

                if (!parse_datetime(t, y, mon, d, h, min, s) || h >= 60 || min >= 60 || s >= 60)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to time."), val);

                return time{h, min, s};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            {
                uint16_t y;
                uint8_t mon, d, h, min, s;

                auto t = u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1, t.length() - 1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return time{0, 0, 0};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                if (!parse_datetime(t2, y, mon, d, h, min, s) || h >= 60 || min >= 60 || s >= 60)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to time."), utf16_to_utf8(u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t))));

                return time{h, min, s};
            }

            case sql_type::TIME: {
                uint64_t secs = 0;

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length()));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return time{(uint32_t)secs};
            }

            case sql_type::DATETIME:
                return time{*(uint32_t*)(val.data() + sizeof(int32_t)) / 300};

            case sql_type::DATETIMN:
                switch (val.length()) {
                    case 4:
                        return time{(uint32_t)(*(uint16_t*)(val.data() + sizeof(uint16_t)) * 60)};

                    case 8:
                        return time{*(uint32_t*)(val.data() + sizeof(int32_t)) / 300};

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), val.length());
                }

            case sql_type::DATETIME2: {
                uint64_t secs = 0;

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length() - 3));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return time{(uint32_t)secs};
            }

            case sql_type::DATETIMEOFFSET: {
                uint64_t secs = 0;

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length() - 5));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return time{(uint32_t)secs};
            }

            // MSSQL doesn't allow conversion to TIME for integers, floats, BITs, or DATE

            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to time."), type);
        }
    }

    value::operator const datetime() const {
        if (is_null)
            return datetime{1900, 1, 1, 0, 0, 0};

        switch (type) {
            case sql_type::VARCHAR:
            case sql_type::CHAR:
            {
                uint16_t y;
                uint8_t mon, d, h, min, s;

                auto t = string_view(val);

                // remove leading whitespace

                while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetime{1900, 1, 1, 0, 0, 0};

                if (!parse_datetime(t, y, mon, d, h, min, s))
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to datetime."), val);

                return datetime{y, mon, d, h, min, s};
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            {
                uint16_t y;
                uint8_t mon, d, h, min, s;

                auto t = u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t));

                // remove leading whitespace

                while (!t.empty() && (t.front() == u' ' || t.front() == u'\t')) {
                    t = t.substr(1);
                }

                // remove trailing whitespace

                while (!t.empty() && (t.back() == u' ' || t.back() == u'\t')) {
                    t = t.substr(0, t.length() - 1);
                }

                if (t.empty())
                    return datetime{1900, 1, 1, 0, 0, 0};

                string t2;

                t2.reserve(t.length());

                for (auto c : t) {
                    t2 += (char)c;
                }

                if (!parse_datetime(t2, y, mon, d, h, min, s))
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to datetime."), utf16_to_utf8(u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t))));

                return datetime{y, mon, d, h, min, s};
            }

            case sql_type::DATE: {
                uint32_t n = 0;

                memcpy(&n, val.data(), 3);

                return datetime{(int32_t)n - 693595, 0};
            }

            case sql_type::TIME: {
                uint64_t secs = 0;

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length()));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return datetime{0, (uint32_t)secs};
            }

            case sql_type::DATETIME:
                return datetime{*(int32_t*)val.data(), *(uint32_t*)(val.data() + sizeof(int32_t)) / 300};

            case sql_type::DATETIMN:
                switch (val.length()) {
                    case 4:
                        return datetime{*(uint16_t*)val.data(), (uint32_t)(*(uint16_t*)(val.data() + sizeof(uint16_t)) * 60)};

                    case 8:
                        return datetime{*(int32_t*)val.data(), *(uint32_t*)(val.data() + sizeof(int32_t)) / 300};

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), val.length());
                }

            case sql_type::DATETIME2: {
                uint32_t n = 0;
                uint64_t secs = 0;

                memcpy(&n, val.data() + val.length() - 3, 3);

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length() - 3));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return datetime{(int32_t)n - 693595, (uint32_t)secs};
            }

            case sql_type::DATETIMEOFFSET: {
                uint32_t n = 0;
                uint64_t secs = 0;

                memcpy(&n, val.data() + val.length() - 5, 3);

                memcpy(&secs, val.data(), min(sizeof(uint64_t), val.length() - 5));

                for (auto n = max_length; n > 0; n--) {
                    secs /= 10;
                }

                return datetime{(int32_t)n - 693595, (uint32_t)secs};
            }

            // MSSQL doesn't allow conversion to DATETIME2 for integers, floats, or BIT

            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to datetime."), type);
        }
    }

    value::operator double() const {
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
                        throw formatted_error(FMT_STRING("FLTN has unexpected length {}."), d.length());
                }

            case sql_type::VARCHAR:
            case sql_type::CHAR:
            {
                if (d.empty())
                    return 0.0;

                // from_chars not implemented for double yet on gcc
#if 0
                double res;

                auto [p, ec] = from_chars(d.data(), d.data() + d.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to float."), val);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error(FMT_STRING("String \"{}\" was too large to convert to float."), val);

                return res;
#else
                try {
                    return stod(val);
                } catch (...) {
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to float."), val);
                }
#endif
            }

            case sql_type::NVARCHAR:
            case sql_type::NCHAR:
            {
                if (d.empty())
                    return 0.0;

                u16string_view v((char16_t*)d.data(), d.length() / sizeof(char16_t));
                string s;

                s.reserve(v.length());

                for (auto c : v) {
                    s += (char)c;
                }

                // from_chars not implemented for double yet on gcc
#if 0
                double res;

                auto [p, ec] = from_chars(s.data(), s.data() + s.length(), res);

                if (ec == errc::invalid_argument)
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to float."), s);
                else if (ec == errc::result_out_of_range)
                    throw formatted_error(FMT_STRING("String \"{}\" was too large to convert to float."), s);

                return res;
#else
                try {
                    return stod(s);
                } catch (...) {
                    throw formatted_error(FMT_STRING("Cannot convert string \"{}\" to float."), s);
                }
#endif
            }

            case sql_type::DATETIME: {
                auto dt = *(int32_t*)d.data();
                auto t = *(uint32_t*)(d.data() + sizeof(int32_t));

                return (double)dt + ((double)t / 25920000.0);
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
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), d.length());
                }

            case sql_type::NUMERIC:
            case sql_type::DECIMAL: {
                auto s = (string)*this;

                try {
                    return stod(s);
                } catch (...) {
                    throw formatted_error(FMT_STRING("Cannot convert {} to float."), s);
                }
            }

            // MSSQL doesn't allow conversion to FLOAT for DATE, TIME, DATETIME2, DATETIMEOFFSET, or VARBINARY

            default:
                throw formatted_error(FMT_STRING("Cannot convert {} to float."), type2);
        }
    }

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
                throw formatted_error(FMT_STRING("FIXME - fixed_len_size for {}"), type); // FIXME

            default:
                return 0;
        }
    }

    static void handle_row_col(value& col, enum sql_type type, unsigned int max_length, string_view& sv) {
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
                    throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

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
                    throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least 1)."), sv.length());

                auto len = *(uint8_t*)sv.data();

                sv = sv.substr(1);

                col.val.resize(len);
                col.is_null = len == 0;

                if (sv.length() < len)
                    throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

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
                if (max_length == 0xffff) {
                    if (sv.length() < sizeof(uint64_t))
                        throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least 8)."), sv.length());

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
                            throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least 4)."), sv.length());

                        auto chunk_len = *(uint32_t*)sv.data();

                        sv = sv.substr(sizeof(uint32_t));

                        if (chunk_len == 0)
                            break;

                        if (sv.length() < chunk_len)
                            throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), chunk_len);

                        col.val += sv.substr(0, chunk_len);
                        sv = sv.substr(chunk_len);
                    } while (true);
                } else {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least 2)."), sv.length());

                    auto len = *(uint16_t*)sv.data();

                    sv = sv.substr(sizeof(uint16_t));

                    if (len == 0xffff) {
                        col.is_null = true;
                        return;
                    }

                    col.val.resize(len);
                    col.is_null = false;

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

                    memcpy(col.val.data(), sv.data(), len);
                    sv = sv.substr(len);
                }

                break;

            case sql_type::IMAGE:
            case sql_type::NTEXT:
            case sql_type::SQL_VARIANT:
            case sql_type::TEXT:
            {
                if (sv.length() < sizeof(uint32_t))
                    throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least 4)."), sv.length());

                auto len = *(uint32_t*)sv.data();

                sv = sv.substr(sizeof(uint32_t));

                col.val.resize(len);
                col.is_null = len == 0xffffffff;

                if (!col.is_null) {
                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

                    memcpy(col.val.data(), sv.data(), len);
                    sv = sv.substr(len);
                }

                break;
            }

            default:
                throw formatted_error(FMT_STRING("Unhandled type {} in ROW message."), type);
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
                if (max_length == 0xffff) {
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

            case sql_type::IMAGE:
            case sql_type::NTEXT:
            case sql_type::SQL_VARIANT:
            case sql_type::TEXT:
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

            default:
                throw formatted_error(FMT_STRING("Unhandled type {} in ROW message."), type);
        }

        return true;
    }

    void rpc::do_rpc(tds& conn, const u16string_view& name) {
        size_t bufsize;

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

                case sql_type::UNIQUEIDENTIFIER:
                case sql_type::MONEYN:
                case sql_type::DATETIMN:
                case sql_type::DATE:
                    bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length());
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
                case sql_type::VARCHAR:
                    if (!p.is_null && p.val.length() > 8000) // MAX
                        bufsize += sizeof(tds_VARCHAR_MAX_param) + p.val.length() + sizeof(uint32_t);
                    else
                        bufsize += sizeof(tds_VARCHAR_param) + (p.is_null ? 0 : p.val.length());

                    break;

                case sql_type::VARBINARY:
                    if (!p.is_null && p.val.length() > 8000) // MAX
                        bufsize += sizeof(tds_VARBINARY_MAX_param) + p.val.length() + sizeof(uint32_t);
                    else
                        bufsize += sizeof(tds_VARBINARY_param) + (p.is_null ? 0 : p.val.length());

                    break;

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    bufsize += sizeof(tds_param_header) + 4;

                    if (!p.is_null)
                        bufsize += p.val.length();
                break;

                default:
                    throw formatted_error(FMT_STRING("Unhandled type {} in RPC params."), p.type);
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

                case sql_type::UNIQUEIDENTIFIER:
                case sql_type::MONEYN:
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

                case sql_type::NVARCHAR:
                case sql_type::VARCHAR:
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

                        h3->length = h3->chunk_length = (uint16_t)p.val.length();

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

                        h3->length = h3->chunk_length = (uint16_t)p.val.length();

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

                default:
                    throw formatted_error(FMT_STRING("Unhandled type {} in RPC params."), p.type);
            }
        }

        conn.impl->send_msg(tds_msg::rpc, string_view((char*)buf.data(), buf.size()));

        wait_for_packet();
    }

    static void parse_tokens(string_view& sv, list<string>& tokens, vector<column>& buf_columns) {
        while (!sv.empty()) {
            auto type = (tds_token)sv[0];

            if (((uint8_t)type & 0x30) == 0x20 && type != tds_token::RETURNVALUE) { // variable-length token
                if (sv.length() < 1 + sizeof(uint16_t))
                    return;

                auto len = *(uint16_t*)&sv[1];

                if (sv.length() < (size_t)(1 + sizeof(uint16_t) + len))
                    return;

                tokens.emplace_back(sv.substr(0, 1 + sizeof(uint16_t) + len));
                sv = sv.substr(1 + sizeof(uint16_t) + len);
            } else {
                switch (type) {
                    case tds_token::DONE:
                    case tds_token::DONEPROC:
                    case tds_token::DONEINPROC:
                        if (sv.length() < 1 + sizeof(tds_done_msg))
                            return;

                        tokens.emplace_back(sv.substr(0, 1 + sizeof(tds_done_msg)));
                        sv = sv.substr(1 + sizeof(tds_done_msg));
                    break;

                    case tds_token::COLMETADATA: {
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
                                case sql_type::UNIQUEIDENTIFIER:
                                case sql_type::MONEYN:
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
                                    if (sv2.length() < sizeof(uint8_t))
                                        return;

                                    col.max_length = *(uint8_t*)sv2.data();

                                    sv2 = sv2.substr(1);
                                break;

                                case sql_type::VARCHAR:
                                case sql_type::NVARCHAR:
                                case sql_type::CHAR:
                                case sql_type::NCHAR:
                                    if (sv2.length() < sizeof(uint16_t) + sizeof(tds_collation))
                                        return;

                                    col.max_length = *(uint16_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint16_t) + sizeof(tds_collation));
                                break;

                                case sql_type::VARBINARY:
                                case sql_type::BINARY:
                                    if (sv2.length() < sizeof(uint16_t))
                                        return;

                                    col.max_length = *(uint16_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint16_t));
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

                                case sql_type::IMAGE:
                                case sql_type::NTEXT:
                                case sql_type::SQL_VARIANT:
                                case sql_type::TEXT:
                                    if (sv2.length() < sizeof(uint32_t))
                                        return;

                                    col.max_length = *(uint32_t*)sv2.data();

                                    sv2 = sv2.substr(sizeof(uint32_t));
                                break;

                                default:
                                    throw formatted_error(FMT_STRING("Unhandled type {} in COLMETADATA message."), c.type);
                            }

                            if (sv2.length() < 1)
                                return;

                            auto name_len = *(uint8_t*)&sv2[0];

                            sv2 = sv2.substr(1);

                            if (sv2.length() < name_len * sizeof(char16_t))
                                return;

                            sv2 = sv2.substr(name_len * sizeof(char16_t));
                        }

                        auto len = sv2.data() - sv.data();

                        tokens.emplace_back(sv.substr(0, len));
                        sv = sv.substr(len);

                        buf_columns = cols;

                        break;
                    }

                    case tds_token::ROW: {
                        auto sv2 = sv.substr(1);

                        for (unsigned int i = 0; i < buf_columns.size(); i++) {
                            if (!parse_row_col(buf_columns[i].type, buf_columns[i].max_length, sv2))
                                return;
                        }

                        auto len = sv2.data() - sv.data();

                        tokens.emplace_back(sv.substr(0, len));
                        sv = sv.substr(len);

                        break;
                    }

                    case tds_token::NBCROW:
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
                                    bsv = bitset[0];
                                } else
                                    bsv >>= 1;
                            }

                            if (!(bsv & 1)) { // not NULL
                                if (!parse_row_col(buf_columns[i].type, buf_columns[i].max_length, sv2))
                                    return;
                            }
                        }

                        auto len = sv2.data() - sv.data();

                        tokens.emplace_back(sv.substr(0, len));
                        sv = sv.substr(len);

                        break;
                    }

                    case tds_token::RETURNSTATUS:
                    {
                        if (sv.length() < 1 + sizeof(int32_t))
                            return;

                        tokens.emplace_back(sv.substr(0, 1 + sizeof(int32_t)));
                        sv = sv.substr(1 + sizeof(int32_t));

                        break;
                    }

                    case tds_token::RETURNVALUE:
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
                            throw formatted_error(FMT_STRING("Unhandled type {} in RETURNVALUE message."), h->type);

                        break;
                    }

                    default:
                        throw formatted_error(FMT_STRING("Unhandled token type {} while parsing tokens."), type);
                }
            }
        }
    }

    rpc::~rpc() {
        if (finished)
            return;

        conn.impl->send_msg(tds_msg::attention_signal, string_view());

        while (!finished) {
            wait_for_packet();
        }

        // wait for attention acknowledgement

        try {
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

                    auto type = (tds_token)t[0];

                    switch (type) {
                        case tds_token::DONE:
                        case tds_token::DONEINPROC:
                        case tds_token::DONEPROC: {
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

    static u16string_view extract_message(const string_view& sv) {
        return u16string_view((char16_t*)&sv[8], *(uint16_t*)&sv[6]);
    }

    void rpc::wait_for_packet() {
        enum tds_msg type;
        string payload;
        bool last_packet;

        conn.impl->wait_for_msg(type, payload, &last_packet);
        // FIXME - timeout

        if (type != tds_msg::tabular_result)
            throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

        buf += payload;

        {
            string_view sv = buf;

            parse_tokens(sv, tokens, buf_columns);

            buf = sv;
        }

        if (last_packet && !buf.empty())
            throw formatted_error(FMT_STRING("Data remaining in buffer"));

        while (!tokens.empty()) {
            auto t = move(tokens.front());

            tokens.pop_front();

            string_view sv = t;

            auto type = (tds_token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case tds_token::DONE:
                case tds_token::DONEINPROC:
                case tds_token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                    if (conn.impl->count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            conn.impl->count_handler(msg->rowcount, msg->curcmd);
                    }

                    // FIXME - handle RPCs that return multiple row sets?
                break;

                case tds_token::INFO:
                case tds_token::TDS_ERROR:
                case tds_token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                    if (type == tds_token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == tds_token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);
                        else
                            throw formatted_error(FMT_STRING("RPC {} failed: {}"), utf16_to_utf8(name), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == tds_token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    break;
                }

                case tds_token::RETURNSTATUS:
                {
                    if (sv.length() < sizeof(int32_t))
                        throw formatted_error(FMT_STRING("Short RETURNSTATUS message ({} bytes, expected 4)."), sv.length());

                    return_status = *(int32_t*)&sv[0];

                    break;
                }

                case tds_token::COLMETADATA:
                {
                    if (sv.length() < 4)
                        throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes, expected at least 4)."), sv.length());

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
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(tds_colmetadata_col));

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
                            case sql_type::UNIQUEIDENTIFIER:
                            case sql_type::MONEYN:
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
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                                col.max_length = *(uint8_t*)sv2.data();

                                len++;
                                sv2 = sv2.substr(1);
                                break;

                            case sql_type::VARCHAR:
                            case sql_type::NVARCHAR:
                            case sql_type::CHAR:
                            case sql_type::NCHAR:
                                if (sv2.length() < sizeof(uint16_t) + sizeof(tds_collation))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t) + sizeof(tds_collation));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t) + sizeof(tds_collation);
                                sv2 = sv2.substr(sizeof(uint16_t) + sizeof(tds_collation));
                                break;

                            case sql_type::VARBINARY:
                            case sql_type::BINARY:
                                if (sv2.length() < sizeof(uint16_t))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t);
                                sv2 = sv2.substr(sizeof(uint16_t));
                                break;

                            case sql_type::DECIMAL:
                            case sql_type::NUMERIC:
                                if (sv2.length() < 3)
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 3)."), sv2.length(), 3);

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

                            default:
                                throw formatted_error(FMT_STRING("Unhandled type {} in COLMETADATA message."), c.type);
                        }

                        if (sv2.length() < 1)
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                        auto name_len = *(uint8_t*)&sv2[0];

                        sv2 = sv2.substr(1);
                        len++;

                        if (sv2.length() < name_len * sizeof(char16_t))
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), name_len * sizeof(char16_t));

                        col.name = u16string_view((char16_t*)sv2.data(), name_len);

                        sv2 = sv2.substr(name_len * sizeof(char16_t));
                        len += name_len * sizeof(char16_t);
                    }

                    break;
                }

                case tds_token::RETURNVALUE:
                {
                    auto h = (tds_return_value*)&sv[0];

                    if (sv.length() < sizeof(tds_return_value))
                        throw formatted_error(FMT_STRING("Short RETURNVALUE message ({} bytes, expected at least {})."), sv.length(), sizeof(tds_return_value));

                    // FIXME - param name

                    if (is_byte_len_type(h->type)) {
                        uint8_t len;

                        if (sv.length() < sizeof(tds_return_value) + 2)
                            throw formatted_error(FMT_STRING("Short RETURNVALUE message ({} bytes, expected at least {})."), sv.length(), sizeof(tds_return_value) + 2);

                        len = *((uint8_t*)&sv[0] + sizeof(tds_return_value) + 1);

                        if (sv.length() < sizeof(tds_return_value) + 2 + len)
                            throw formatted_error(FMT_STRING("Short RETURNVALUE message ({} bytes, expected {})."), sv.length(), sizeof(tds_return_value) + 2 + len);

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
                        throw formatted_error(FMT_STRING("Unhandled type {} in RETURNVALUE message."), h->type);

                    break;
                }

                case tds_token::ROW:
                {
                    vector<value> row;

                    row.resize(cols.size());

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        handle_row_col(col, cols[i].type, cols[i].max_length, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case tds_token::NBCROW:
                {
                    if (cols.empty())
                        break;

                    vector<value> row;

                    row.resize(cols.size());

                    auto bitset_length = (cols.size() + 7) / 8;

                    if (sv.length() < bitset_length)
                        throw formatted_error(FMT_STRING("Short NBCROW message ({} bytes, expected at least {})."), sv.length(), bitset_length);

                    string_view bitset(sv.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv = sv.substr(bitset_length);

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        if (i != 0) {
                            if ((i & 7) == 0) {
                                bitset = bitset.substr(1);
                                bsv = bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (bsv & 1) // NULL
                            col.is_null = true;
                        else
                            handle_row_col(col, cols[i].type, cols[i].max_length, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case tds_token::ORDER:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short ORDER message ({} bytes, expected at least {})."), sv.length(), sizeof(uint16_t));

                    auto len = *(uint16_t*)sv.data();
                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short ORDER message ({} bytes, expected {})."), sv.length(), len);

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} while executing RPC."), type);
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
        output_param<int32_t> handle;

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

        r2.reset(new rpc(conn, u"sp_execute", static_cast<value>(handle), params));

        // FIXME - sp_unprepare (is this necessary?)
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

    u16string type_to_string(enum sql_type type, size_t length, uint8_t precision, uint8_t scale) {
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
                        throw formatted_error(FMT_STRING("INTN has invalid length {}."), length);
                }

            case sql_type::NVARCHAR:
                if (length > 8000)
                    return u"NVARCHAR(MAX)";
                else
                    return u"NVARCHAR(" + to_u16string(length == 0 ? 1 : (length / sizeof(char16_t))) + u")";

            case sql_type::NCHAR:
                return u"NCHAR(" + to_u16string(length == 0 ? 1 : (length / sizeof(char16_t))) + u")";

            case sql_type::VARCHAR:
                if (length > 8000)
                    return u"VARCHAR(MAX)";
                else
                    return u"VARCHAR(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::CHAR:
                return u"CHAR(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::FLTN:
                switch (length) {
                    case 4:
                        return u"REAL";

                    case 8:
                        return u"FLOAT";

                    default:
                        throw formatted_error(FMT_STRING("FLTN has invalid length {}."), length);
                }

            case sql_type::DATE:
                return u"DATE";

            case sql_type::TIME:
                return u"TIME";

            case sql_type::DATETIME:
                return u"DATETIME";

            case sql_type::DATETIME2:
                return u"DATETIME2";

            case sql_type::DATETIMEOFFSET:
                return u"DATETIMEOFFSET";

            case sql_type::VARBINARY:
                if (length > 8000)
                    return u"VARBINARY(MAX)";
                else
                    return u"VARBINARY(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::BINARY:
                return u"BINARY(" + to_u16string(length == 0 ? 1 : length) + u")";

            case sql_type::BITN:
                return u"BIT";

            case sql_type::DATETIMN:
                switch (length) {
                    case 4:
                        return u"SMALLDATETIME";

                    case 8:
                        return u"DATETIME";

                    default:
                        throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), length);
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

            default:
                throw formatted_error(FMT_STRING("Could not get type string for {}."), type);
        }
    }

    u16string query::create_params_string() {
        unsigned int num = 1;
        u16string s;

        for (const auto& p : params) {
            if (!s.empty())
                s += u", ";

            s += u"@P" + to_u16string(num) + u" ";
            s += type_to_string(p.type, p.val.length(), p.precision, p.scale);

            num++;
        }

        return s;
    }

    static u16string sql_escape(const u16string_view& sv) {
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

    void tds::bcp(const u16string_view& table, const vector<u16string>& np, const vector<vector<value>>& vp) {
        vector<column> cols;

        if (np.empty())
            throw runtime_error("List of columns not supplied.");

        // FIXME - do we need to make sure no duplicates in np?

        {
            output_param<int32_t> handle;
            bool first = true;

            u16string q = u"SELECT TOP 0 ";

            for (const auto& n : np) {
                if (!first)
                    q += u", ";

                q += sql_escape(n);
                first = false;
            }

            q += u" FROM "s + u16string(table); // FIXME - escape schema name and table name

            {
                rpc r1(*this, u"sp_prepare", handle, u"", q, 1);

                while (r1.fetch_row()) { }

                cols = r1.cols; // get column types
            }

            rpc r2(*this, u"sp_unprepare", static_cast<value>(handle));
        }

        {
            u16string q = u"INSERT BULK " + u16string(table) + u"(";
            bool first = true;

            for (unsigned int i = 0; i < cols.size(); i++) {
                if (!first)
                    q += u", ";

                q += sql_escape(np[i]) + u" ";
                q += type_to_string(cols[i].type, cols[i].max_length, cols[i].precision, cols[i].scale);

                first = false;
            }

            q += u")";

            batch b(*this, q);
        }

        // FIXME - handle INT NULLs and VARCHAR NULLs

        // send COLMETADATA for rows
        auto buf = impl->bcp_colmetadata(cols);

        for (const auto& v : vp) {
            auto buf2 = impl->bcp_row(v, cols);

            // FIXME - if buf full, send packet (maximum packet size is 4096?)

            auto oldlen = buf.size();
            buf.resize(oldlen + buf2.size());
            memcpy(&buf[oldlen], buf2.data(), buf2.size());
        }

        impl->bcp_sendmsg(string_view((char*)buf.data(), buf.size()));
    }

    void tds::bcp(const string_view& table, const vector<string>& np, const vector<vector<value>>& vp) {
        vector<u16string> np2;

        for (const auto& s : np) {
            np2.emplace_back(utf8_to_utf16(s));
        }

        bcp(utf8_to_utf16(table), np2, vp);
    }

    template<unsigned N>
    static void double_to_int(double d, uint8_t* scratch) {
        auto v = *(uint64_t*)&d;
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

    vector<uint8_t> tds_impl::bcp_row(const vector<value>& v, const vector<column>& cols) {
        size_t bufsize = sizeof(uint8_t);

        for (unsigned int i = 0; i < v.size(); i++) {
            if (v[i].is_null && !cols[i].nullable)
                throw formatted_error(FMT_STRING("Cannot insert NULL into column {} marked NOT NULL."), utf16_to_utf8(cols[i].name));

            switch (cols[i].type) {
                case sql_type::INTN:
                    bufsize++;

                    if (!v[i].is_null)
                        bufsize += cols[i].max_length;
                break;

                case sql_type::VARCHAR:
                case sql_type::CHAR:
                    bufsize += sizeof(uint16_t);

                    if (v[i].is_null) {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                    } else {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                        if (v[i].type == sql_type::VARCHAR || v[i].type == sql_type::CHAR) {
                            bufsize += v[i].val.length();

                            if (cols[i].max_length == 0xffff && !v[i].val.empty())
                                bufsize += sizeof(uint32_t);
                        } else {
                            auto s = (string)v[i];
                            bufsize += s.length();

                            if (cols[i].max_length == 0xffff && !s.empty())
                                bufsize += sizeof(uint32_t);
                        }
                    }
                break;

                case sql_type::NVARCHAR:
                case sql_type::NCHAR:
                    bufsize += sizeof(uint16_t);

                    if (v[i].is_null) {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                    } else {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                        if (v[i].type == sql_type::NVARCHAR || v[i].type == sql_type::NCHAR) {
                            bufsize += v[i].val.length();

                            if (cols[i].max_length == 0xffff && !v[i].val.empty())
                                bufsize += sizeof(uint32_t);
                        } else {
                            auto s = (u16string)v[i];
                            bufsize += s.length() * sizeof(char16_t);

                            if (cols[i].max_length == 0xffff && !s.empty())
                                bufsize += sizeof(uint32_t);
                        }
                    }
                break;

                case sql_type::VARBINARY:
                case sql_type::BINARY:
                    bufsize += sizeof(uint16_t);

                    if (v[i].is_null) {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) - sizeof(uint16_t);
                    } else {
                        if (cols[i].max_length == 0xffff) // MAX
                            bufsize += sizeof(uint64_t) + sizeof(uint32_t) - sizeof(uint16_t);

                        if (v[i].type == sql_type::VARBINARY || v[i].type == sql_type::BINARY) {
                            bufsize += v[i].val.length();

                            if (cols[i].max_length == 0xffff && !v[i].val.empty())
                                bufsize += sizeof(uint32_t);
                        } else
                            throw formatted_error(FMT_STRING("Could not convert {} to {}."), v[i].type, cols[i].type);
                    }
                break;

                case sql_type::DATE:
                    bufsize++;

                    if (!v[i].is_null)
                        bufsize += 3;
                break;

                case sql_type::TIME:
                    bufsize++;

                    if (!v[i].is_null) {
                        if (cols[i].max_length <= 2)
                            bufsize += 3;
                        else if (cols[i].max_length <= 4)
                            bufsize += 4;
                        else
                            bufsize += 5;
                    }
                break;

                case sql_type::DATETIME2:
                    bufsize++;

                    if (!v[i].is_null) {
                        bufsize += 3;

                        if (cols[i].max_length <= 2)
                            bufsize += 3;
                        else if (cols[i].max_length <= 4)
                            bufsize += 4;
                        else
                            bufsize += 5;
                    }
                break;

                case sql_type::DATETIMEOFFSET:
                    bufsize++;

                    if (!v[i].is_null) {
                        bufsize += 5;

                        if (cols[i].max_length <= 2)
                            bufsize += 3;
                        else if (cols[i].max_length <= 4)
                            bufsize += 4;
                        else
                            bufsize += 5;
                    }
                break;

                case sql_type::DATETIME:
                    bufsize += sizeof(int32_t) + sizeof(uint32_t);
                break;

                case sql_type::DATETIMN:
                    bufsize++;

                    if (!v[i].is_null)
                        bufsize += cols[i].max_length;
                break;

                case sql_type::FLTN:
                    bufsize++;

                    if (!v[i].is_null)
                        bufsize += cols[i].max_length;
                break;

                case sql_type::BITN:
                    bufsize++;

                    if (!v[i].is_null)
                        bufsize += sizeof(uint8_t);
                break;

                case sql_type::TINYINT:
                    bufsize += sizeof(uint8_t);
                break;

                case sql_type::SMALLINT:
                    bufsize += sizeof(int16_t);
                break;

                case sql_type::INT:
                    bufsize += sizeof(int32_t);
                break;

                case sql_type::BIGINT:
                    bufsize += sizeof(int64_t);
                break;

                case sql_type::FLOAT:
                    bufsize += sizeof(double);
                break;

                case sql_type::REAL:
                    bufsize += sizeof(float);
                break;

                case sql_type::BIT:
                    bufsize += sizeof(uint8_t);
                break;

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    bufsize += sizeof(uint8_t);

                    if (!v[i].is_null) {
                        bufsize += sizeof(uint8_t);

                        if (cols[i].precision >= 29)
                            bufsize += 16;
                        else if (cols[i].precision >= 20)
                            bufsize += 12;
                        else if (cols[i].precision >= 10)
                            bufsize += 8;
                        else
                            bufsize += 4;
                    }
                break;

                default:
                    throw formatted_error(FMT_STRING("Unable to send {} in BCP row."), cols[i].type);
            }
        }

        vector<uint8_t> buf(bufsize);
        uint8_t* ptr = buf.data();

        *(tds_token*)ptr = tds_token::ROW;
        ptr++;

        for (unsigned int i = 0; i < v.size(); i++) {
            switch (cols[i].type) {
                case sql_type::INTN:
                    if (v[i].is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        *ptr = (uint8_t)cols[i].max_length;
                        ptr++;

                        auto n = (int64_t)v[i];

                        switch (cols[i].max_length) {
                            case sizeof(uint8_t):
                                if (n < numeric_limits<uint8_t>::min() || n > numeric_limits<uint8_t>::max())
                                    throw formatted_error(FMT_STRING("{} is out of bounds for TINYINT column {}."), n, utf16_to_utf8(cols[i].name));

                                *ptr = (uint8_t)n;
                                ptr++;
                            break;

                            case sizeof(int16_t):
                                if (n < numeric_limits<int16_t>::min() || n > numeric_limits<int16_t>::max())
                                    throw formatted_error(FMT_STRING("{} is out of bounds for SMALLINT column {}."), n, utf16_to_utf8(cols[i].name));

                                *(int16_t*)ptr = (int16_t)n;
                                ptr += sizeof(int16_t);
                            break;

                            case sizeof(int32_t):
                                if (n < numeric_limits<int32_t>::min() || n > numeric_limits<int32_t>::max())
                                    throw formatted_error(FMT_STRING("{} is out of bounds for INT column {}."), n, utf16_to_utf8(cols[i].name));

                                *(int32_t*)ptr = (int32_t)n;
                                ptr += sizeof(int32_t);
                            break;

                            case sizeof(int64_t):
                                *(int64_t*)ptr = n;
                                ptr += sizeof(int64_t);
                            break;

                            default:
                                throw formatted_error(FMT_STRING("Invalid INTN size {}."), cols[i].max_length);
                        }
                    }
                break;

                case sql_type::VARCHAR:
                case sql_type::CHAR:
                    if (cols[i].max_length == 0xffff) {
                        if (v[i].is_null) {
                            *(uint64_t*)ptr = 0xffffffffffffffff;
                            ptr += sizeof(uint64_t);
                        } else if (v[i].type == sql_type::VARCHAR || v[i].type == sql_type::CHAR) {
                            *(uint64_t*)ptr = 0xfffffffffffffffe;
                            ptr += sizeof(uint64_t);

                            if (!v[i].val.empty()) {
                                *(uint32_t*)ptr = (uint32_t)v[i].val.length();
                                ptr += sizeof(uint32_t);

                                memcpy(ptr, v[i].val.data(), v[i].val.length());
                                ptr += v[i].val.length();
                            }

                            *(uint32_t*)ptr = 0;
                            ptr += sizeof(uint32_t);
                        } else {
                            auto s = (string)v[i];

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
                        if (v[i].is_null) {
                            *(uint16_t*)ptr = 0xffff;
                            ptr += sizeof(uint16_t);
                        } else if (v[i].type == sql_type::VARCHAR || v[i].type == sql_type::CHAR) {
                            if (v[i].val.length() > cols[i].max_length)
                                throw formatted_error(FMT_STRING("String \"{}\" too long for column {} (maximum length {})."), v[i].val, utf16_to_utf8(cols[i].name), cols[i].max_length);

                            *(uint16_t*)ptr = (uint16_t)v[i].val.length();
                            ptr += sizeof(uint16_t);

                            memcpy(ptr, v[i].val.data(), v[i].val.length());
                            ptr += v[i].val.length();
                        } else {
                            auto s = (string)v[i];

                            if (s.length() > cols[i].max_length)
                                throw formatted_error(FMT_STRING("String \"{}\" too long for column {} (maximum length {})."), s, utf16_to_utf8(cols[i].name), cols[i].max_length);

                            *(uint16_t*)ptr = (uint16_t)s.length();
                            ptr += sizeof(uint16_t);

                            memcpy(ptr, s.data(), s.length());
                            ptr += s.length();
                        }
                    }
                break;

                case sql_type::NVARCHAR:
                case sql_type::NCHAR:
                    if (cols[i].max_length == 0xffff) {
                        if (v[i].is_null) {
                            *(uint64_t*)ptr = 0xffffffffffffffff;
                            ptr += sizeof(uint64_t);
                        } else if (v[i].type == sql_type::NVARCHAR || v[i].type == sql_type::NCHAR) {
                            *(uint64_t*)ptr = 0xfffffffffffffffe;
                            ptr += sizeof(uint64_t);

                            if (!v[i].val.empty()) {
                                *(uint32_t*)ptr = (uint32_t)v[i].val.length();
                                ptr += sizeof(uint32_t);

                                memcpy(ptr, v[i].val.data(), v[i].val.length());
                                ptr += v[i].val.length();
                            }

                            *(uint32_t*)ptr = 0;
                            ptr += sizeof(uint32_t);
                        } else {
                            auto s = (u16string)v[i];

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
                        if (v[i].is_null) {
                            *(uint16_t*)ptr = 0xffff;
                            ptr += sizeof(uint16_t);
                        } else if (v[i].type == sql_type::NVARCHAR || v[i].type == sql_type::NCHAR) {
                            if (v[i].val.length() > cols[i].max_length) {
                                throw formatted_error(FMT_STRING("String \"{}\" too long for column {} (maximum length {})."),
                                                      utf16_to_utf8(u16string_view((char16_t*)v[i].val.data(), v[i].val.length() / sizeof(char16_t))),
                                                      utf16_to_utf8(cols[i].name), cols[i].max_length / sizeof(char16_t));
                            }

                            *(uint16_t*)ptr = (uint16_t)v[i].val.length();
                            ptr += sizeof(uint16_t);

                            memcpy(ptr, v[i].val.data(), v[i].val.length());
                            ptr += v[i].val.length();
                        } else {
                            auto s = (u16string)v[i];

                            if (s.length() > cols[i].max_length) {
                                throw formatted_error(FMT_STRING("String \"{}\" too long for column {} (maximum length {})."),
                                                      utf16_to_utf8(u16string_view((char16_t*)s.data(), s.length() / sizeof(char16_t))),
                                                      utf16_to_utf8(cols[i].name), cols[i].max_length / sizeof(char16_t));
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
                    if (cols[i].max_length == 0xffff) {
                        if (v[i].is_null) {
                            *(uint64_t*)ptr = 0xffffffffffffffff;
                            ptr += sizeof(uint64_t);
                        } else if (v[i].type == sql_type::VARBINARY || v[i].type == sql_type::BINARY) {
                            *(uint64_t*)ptr = 0xfffffffffffffffe;
                            ptr += sizeof(uint64_t);

                            if (!v[i].val.empty()) {
                                *(uint32_t*)ptr = (uint32_t)v[i].val.length();
                                ptr += sizeof(uint32_t);

                                memcpy(ptr, v[i].val.data(), v[i].val.length());
                                ptr += v[i].val.length();
                            }

                            *(uint32_t*)ptr = 0;
                            ptr += sizeof(uint32_t);
                        } else
                            throw formatted_error(FMT_STRING("Could not convert {} to {}."), v[i].type, cols[i].type);
                    } else {
                        if (v[i].is_null) {
                            *(uint16_t*)ptr = 0xffff;
                            ptr += sizeof(uint16_t);
                        } else if (v[i].type == sql_type::VARBINARY || v[i].type == sql_type::BINARY) {
                            if (v[i].val.length() > cols[i].max_length)
                                throw formatted_error(FMT_STRING("Binary data too long for column {} ({} bytes, maximum {})."), utf16_to_utf8(cols[i].name), v[i].val.length(), cols[i].max_length);

                            *(uint16_t*)ptr = (uint16_t)v[i].val.length();
                            ptr += sizeof(uint16_t);

                            memcpy(ptr, v[i].val.data(), v[i].val.length());
                            ptr += v[i].val.length();
                        } else
                            throw formatted_error(FMT_STRING("Could not convert {} to {}."), v[i].type, cols[i].type);
                    }
                break;

                case sql_type::DATE:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto d = (date)v[i];
                        uint32_t n = d.num + 693595;

                        *(uint8_t*)ptr = 3;
                        ptr++;

                        memcpy(ptr, &n, 3);
                        ptr += 3;
                    }
                break;

                case sql_type::TIME:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto t = (time)v[i];
                        uint64_t secs = (t.hour * 3600) + (t.minute * 60) + t.second;

                        for (unsigned int j = 0; j < cols[i].max_length; j++) {
                            secs *= 10;
                        }

                        if (cols[i].max_length <= 2) {
                            *(uint8_t*)ptr = 3;
                            ptr++;

                            memcpy(ptr, &secs, 3);
                            ptr += 3;
                        } else if (cols[i].max_length <= 4) {
                            *(uint8_t*)ptr = 4;
                            ptr++;

                            memcpy(ptr, &secs, 4);
                            ptr += 4;
                        } else {
                            *(uint8_t*)ptr = 5;
                            ptr++;

                            memcpy(ptr, &secs, 5);
                            ptr += 5;
                        }
                    }
                break;

                case sql_type::DATETIME2:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto dt = (datetime)v[i];
                        uint32_t n = dt.d.num + 693595;
                        uint64_t secs = (dt.t.hour * 3600) + (dt.t.minute * 60) + dt.t.second;

                        for (unsigned int j = 0; j < cols[i].max_length; j++) {
                            secs *= 10;
                        }

                        if (cols[i].max_length <= 2) {
                            *(uint8_t*)ptr = 6;
                            ptr++;

                            memcpy(ptr, &secs, 3);
                            ptr += 3;
                        } else if (cols[i].max_length <= 4) {
                            *(uint8_t*)ptr = 7;
                            ptr++;

                            memcpy(ptr, &secs, 4);
                            ptr += 4;
                        } else {
                            *(uint8_t*)ptr = 8;
                            ptr++;

                            memcpy(ptr, &secs, 5);
                            ptr += 5;
                        }

                        memcpy(ptr, &n, 3);
                        ptr += 3;
                    }
                break;

                case sql_type::DATETIMEOFFSET:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto dto = (datetime)v[i];
                        uint32_t n = dto.d.num + 693595;
                        uint64_t secs = (dto.t.hour * 3600) + (dto.t.minute * 60) + dto.t.second;

                        for (unsigned int j = 0; j < cols[i].max_length; j++) {
                            secs *= 10;
                        }

                        if (cols[i].max_length <= 2) {
                            *(uint8_t*)ptr = 8;
                            ptr++;

                            memcpy(ptr, &secs, 3);
                            ptr += 3;
                        } else if (cols[i].max_length <= 4) {
                            *(uint8_t*)ptr = 9;
                            ptr++;

                            memcpy(ptr, &secs, 4);
                            ptr += 4;
                        } else {
                            *(uint8_t*)ptr = 10;
                            ptr++;

                            memcpy(ptr, &secs, 5);
                            ptr += 5;
                        }

                        memcpy(ptr, &n, 3);
                        ptr += 3;

                        // FIXME - get offset

                        *(int16_t*)ptr = 0;
                        ptr += sizeof(int16_t);
                    }
                break;

                case sql_type::DATETIME: {
                    auto dt = (datetime)v[i];
                    uint32_t secs = (dt.t.hour * 3600) + (dt.t.minute * 60) + dt.t.second;

                    *(int32_t*)ptr = dt.d.num;
                    ptr += sizeof(int32_t);

                    *(uint32_t*)ptr = (uint32_t)(secs * 300);
                    ptr += sizeof(uint32_t);

                    break;
                }

                case sql_type::DATETIMN:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto dt = (datetime)v[i];

                        switch (cols[i].max_length) {
                            case 4: {
                                if (dt.d.num < 0)
                                    throw formatted_error(FMT_STRING("Datetime \"{}\" too early for SMALLDATETIME column {}."), dt, utf16_to_utf8(cols[i].name));
                                else if (dt.d.num > numeric_limits<uint16_t>::max())
                                    throw formatted_error(FMT_STRING("Datetime \"{}\" too late for SMALLDATETIME column {}."), dt, utf16_to_utf8(cols[i].name));

                                *(uint8_t*)ptr = (uint8_t)cols[i].max_length;
                                ptr++;

                                *(uint16_t*)ptr = (uint16_t)dt.d.num;
                                ptr += sizeof(uint16_t);

                                *(uint16_t*)ptr = (uint16_t)((dt.t.hour * 60) + dt.t.minute);
                                ptr += sizeof(uint16_t);

                                break;
                            }

                            case 8: {
                                uint64_t secs = (dt.t.hour * 3600) + (dt.t.minute * 60) + dt.t.second;

                                *(uint8_t*)ptr = (uint8_t)cols[i].max_length;
                                ptr++;

                                *(int32_t*)ptr = dt.d.num;
                                ptr += sizeof(int32_t);

                                *(uint32_t*)ptr = (uint32_t)(secs * 300);
                                ptr += sizeof(uint32_t);

                                break;
                            }

                            default:
                                throw formatted_error(FMT_STRING("DATETIMN has invalid length {}."), cols[i].max_length);
                        }
                    }
                break;

                case sql_type::FLTN:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else {
                        auto d = (double)v[i];

                        *(uint8_t*)ptr = (uint8_t)cols[i].max_length;
                        ptr++;

                        switch (cols[i].max_length) {
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
                                throw formatted_error(FMT_STRING("FLTN has invalid length {}."), cols[i].max_length);
                        }
                    }
                break;

                case sql_type::BITN:
                    if (v[i].is_null) {
                        *(uint8_t*)ptr = 0;
                        ptr++;
                    } else if (v[i].type == sql_type::BIT || v[i].type == sql_type::BITN) {
                        *(uint8_t*)ptr = sizeof(uint8_t);
                        ptr++;
                        *(uint8_t*)ptr = v[i].val[0];
                        ptr += sizeof(uint8_t);
                    } else {
                        auto n = (int64_t)v[i];

                        *(uint8_t*)ptr = sizeof(uint8_t);
                        ptr++;
                        *(uint8_t*)ptr = n != 0 ? 1 : 0;
                        ptr++;
                    }
                break;

                case sql_type::TINYINT: {
                    auto n = (int64_t)v[i];

                    if (n < numeric_limits<uint8_t>::min() || n > numeric_limits<uint8_t>::max())
                        throw formatted_error(FMT_STRING("Value {} is out of bounds for TINYINT column {}."), n, utf16_to_utf8(cols[i].name));

                    *(uint8_t*)ptr = (uint8_t)n;
                    ptr += sizeof(uint8_t);

                    break;
                }

                case sql_type::SMALLINT: {
                    auto n = (int64_t)v[i];

                    if (n < numeric_limits<int16_t>::min() || n > numeric_limits<int16_t>::max())
                        throw formatted_error(FMT_STRING("Value {} is out of bounds for SMALLINT column {}."), n, utf16_to_utf8(cols[i].name));

                    *(int32_t*)ptr = (int16_t)n;
                    ptr += sizeof(int16_t);

                    break;
                }

                case sql_type::INT: {
                    auto n = (int64_t)v[i];

                    if (n < numeric_limits<int32_t>::min() || n > numeric_limits<int32_t>::max())
                        throw formatted_error(FMT_STRING("Value {} is out of bounds for INT column {}."), n, utf16_to_utf8(cols[i].name));

                    *(int32_t*)ptr = (int32_t)n;
                    ptr += sizeof(int32_t);

                    break;
                }

                case sql_type::BIGINT: {
                    auto n = (int64_t)v[i];

                    *(int64_t*)ptr = n;
                    ptr += sizeof(int64_t);

                    break;
                }

                case sql_type::FLOAT: {
                    auto n = (double)v[i];

                    *(double*)ptr = n;
                    ptr += sizeof(double);

                    break;
                }

                case sql_type::REAL: {
                    auto n = (double)v[i];

                    *(float*)ptr = (float)n;
                    ptr += sizeof(float);

                    break;
                }

                case sql_type::BIT: {
                    if (v[i].type == sql_type::BIT || v[i].type == sql_type::BITN) {
                        *(uint8_t*)ptr = v[i].val[0];
                        ptr += sizeof(uint8_t);
                    } else {
                        auto n = (int64_t)v[i];

                        *(uint8_t*)ptr = n != 0 ? 1 : 0;
                        ptr += sizeof(uint8_t);
                    }

                    break;
                }

                case sql_type::NUMERIC:
                case sql_type::DECIMAL:
                    if (v[i].is_null) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        bool neg = false;
                        auto d = (double)v[i];

                        if (d < 0) {
                            neg = true;
                            d = -d;
                        }

                        for (unsigned int j = 0; j < cols[i].scale; j++) {
                            d *= 10;
                        }

                        // FIXME - avoid doing pow every time?

                        if (d > pow(10, cols[i].precision)) {
                            if (neg) {
                                throw formatted_error(FMT_STRING("Value {} is too small for NUMERIC({},{}) column {}."), v[i], cols[i].precision,
                                                      cols[i].scale, utf16_to_utf8(cols[i].name));
                            } else {
                                throw formatted_error(FMT_STRING("Value {} is too large for NUMERIC({},{}) column {}."), v[i], cols[i].precision,
                                                      cols[i].scale, utf16_to_utf8(cols[i].name));
                            }
                        }

                        if (cols[i].precision < 10) { // 4 bytes
                            *ptr = 5;
                            ptr++;

                            *ptr = neg ? 0 : 1;
                            ptr++;

                            *(uint32_t*)ptr = (uint32_t)d;
                            ptr += sizeof(uint32_t);
                        } else if (cols[i].precision < 20) { // 8 bytes
                            *ptr = 9;
                            ptr++;

                            *ptr = neg ? 0 : 1;
                            ptr++;

                            *(uint64_t*)ptr = (uint64_t)d;
                            ptr += sizeof(uint64_t);
                        } else if (cols[i].precision < 29) { // 12 bytes
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

                default:
                    throw formatted_error(FMT_STRING("Unable to send {} in BCP row."), cols[i].type);
            }
        }

        return buf;
    }

    void tds_impl::bcp_sendmsg(const string_view& data) {
        send_msg(tds_msg::bulk_load_data, data);

        enum tds_msg type;
        string payload;

        wait_for_msg(type, payload);
        // FIXME - timeout

        if (type != tds_msg::tabular_result)
            throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (tds_token)sv[0];
            sv = sv.substr(1);

            // FIXME - parse unknowns according to numeric value of type

            switch (type) {
                case tds_token::DONE:
                case tds_token::DONEINPROC:
                case tds_token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                    if (count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            count_handler(msg->rowcount, msg->curcmd);
                    }

                    sv = sv.substr(sizeof(tds_done_msg));

                    break;

                case tds_token::INFO:
                case tds_token::TDS_ERROR:
                case tds_token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                    if (type == tds_token::INFO) {
                        if (message_handler)
                            handle_info_msg(sv.substr(0, len), false);
                    } else if (type == tds_token::TDS_ERROR) {
                        if (message_handler)
                            handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error(FMT_STRING("BCP failed: {}"), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == tds_token::ENVCHANGE)
                        handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} in BCP response."), type);
            }
        }
    }

    vector<uint8_t> tds_impl::bcp_colmetadata(const vector<column>& cols) {
        size_t bufsize = sizeof(uint8_t) + sizeof(uint16_t) + (cols.size() * sizeof(tds_colmetadata_col));

        for (const auto& col : cols) {
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
                case sql_type::MONEYN:
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
                    bufsize++;
                    break;

                case sql_type::VARCHAR:
                case sql_type::NVARCHAR:
                case sql_type::CHAR:
                case sql_type::NCHAR:
                    bufsize += sizeof(uint16_t) + sizeof(tds_collation);
                    break;

                case sql_type::VARBINARY:
                case sql_type::BINARY:
                    bufsize += sizeof(uint16_t);
                    break;

                case sql_type::DECIMAL:
                case sql_type::NUMERIC:
                    bufsize += 3;
                    break;

                default:
                    throw formatted_error(FMT_STRING("Unhandled type {} when creating COLMETADATA token."), col.type);
            }

            bufsize += sizeof(uint8_t) + (col.name.length() * sizeof(char16_t));
        }

        vector<uint8_t> buf(bufsize);
        auto ptr = (uint8_t*)buf.data();

        *(tds_token*)ptr = tds_token::COLMETADATA; ptr++;
        *(uint16_t*)ptr = (uint16_t)cols.size(); ptr += sizeof(uint16_t);

        for (const auto& col : cols) {
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
                case sql_type::MONEYN:
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
                    *(uint8_t*)ptr = (uint8_t)col.max_length;
                    ptr++;
                break;

                case sql_type::VARCHAR:
                case sql_type::NVARCHAR:
                case sql_type::CHAR:
                case sql_type::NCHAR: {
                    *(uint16_t*)ptr = (uint16_t)col.max_length;
                    ptr += sizeof(uint16_t);

                    auto c = (tds_collation*)ptr;

                    c->lcid = 0x0409; // en-US
                    c->ignore_case = 1;
                    c->ignore_accent = 0;
                    c->ignore_width = 1;
                    c->ignore_kana = 1;
                    c->binary = 0;
                    c->binary2 = 0;
                    c->utf8 = 0;
                    c->reserved = 0;
                    c->version = 0;
                    c->sort_id = 52; // nocase.iso

                    ptr += sizeof(tds_collation);

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
                    throw formatted_error(FMT_STRING("Unhandled type {} when creating COLMETADATA token."), col.type);
            }

            *(uint8_t*)ptr = (uint8_t)col.name.length();
            ptr++;

            memcpy(ptr, col.name.data(), col.name.length() * sizeof(char16_t));
            ptr += col.name.length() * sizeof(char16_t);
        }

        return buf;
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

                    auto type = (tds_token)t[0];

                    switch (type) {
                        case tds_token::DONE:
                        case tds_token::DONEINPROC:
                        case tds_token::DONEPROC: {
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
            throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

        buf += payload;

        {
            string_view sv = buf;

            parse_tokens(sv, tokens, buf_columns);

            buf = sv;
        }

        if (last_packet && !buf.empty())
            throw formatted_error(FMT_STRING("Data remaining in buffer"));

        while (!tokens.empty()) {
            auto t = move(tokens.front());

            tokens.pop_front();

            string_view sv = t;

            auto type = (tds_token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case tds_token::DONE:
                case tds_token::DONEINPROC:
                case tds_token::DONEPROC:
                    if (conn.impl->count_handler) {
                        auto msg = (tds_done_msg*)sv.data();

                        if (msg->status & 0x10) // row count valid
                            conn.impl->count_handler(msg->rowcount, msg->curcmd);
                    }

                    break;

                case tds_token::INFO:
                case tds_token::TDS_ERROR:
                case tds_token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                    if (type == tds_token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == tds_token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);
                        else
                            throw formatted_error(FMT_STRING("SQL batch failed: {}"), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == tds_token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    break;
                }

                case tds_token::COLMETADATA:
                {
                    if (sv.length() < 4)
                        throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes, expected at least 4)."), sv.length());

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
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(tds_colmetadata_col));

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
                            case sql_type::UNIQUEIDENTIFIER:
                            case sql_type::MONEYN:
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
                                if (sv2.length() < sizeof(uint8_t))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                                col.max_length = *(uint8_t*)sv2.data();

                                len++;
                                sv2 = sv2.substr(1);
                                break;

                            case sql_type::VARCHAR:
                            case sql_type::NVARCHAR:
                            case sql_type::CHAR:
                            case sql_type::NCHAR:
                                if (sv2.length() < sizeof(uint16_t) + sizeof(tds_collation))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t) + sizeof(tds_collation));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t) + sizeof(tds_collation);
                                sv2 = sv2.substr(sizeof(uint16_t) + sizeof(tds_collation));
                                break;

                            case sql_type::VARBINARY:
                            case sql_type::BINARY:
                                if (sv2.length() < sizeof(uint16_t))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t));

                                col.max_length = *(uint16_t*)sv2.data();

                                len += sizeof(uint16_t);
                                sv2 = sv2.substr(sizeof(uint16_t));
                                break;

                            case sql_type::DECIMAL:
                            case sql_type::NUMERIC:
                                if (sv2.length() < 3)
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 3)."), sv2.length());

                                col.max_length = (uint8_t)sv2[0];
                                col.precision = (uint8_t)sv2[1];
                                col.scale = (uint8_t)sv2[2];

                                len += 3;
                                sv2 = sv2.substr(3);

                                break;

                            case sql_type::IMAGE:
                            case sql_type::NTEXT:
                            case sql_type::SQL_VARIANT:
                            case sql_type::TEXT:
                                if (sv2.length() < sizeof(uint32_t))
                                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 4)."), sv2.length());

                                col.max_length = *(uint32_t*)sv2.data();

                                sv2 = sv2.substr(sizeof(uint32_t));
                                break;

                            default:
                                throw formatted_error(FMT_STRING("Unhandled type {} in COLMETADATA message."), c.type);
                        }

                        if (sv2.length() < 1)
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                        auto name_len = *(uint8_t*)&sv2[0];

                        sv2 = sv2.substr(1);
                        len++;

                        if (sv2.length() < name_len * sizeof(char16_t))
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), name_len * sizeof(char16_t));

                        col.name = u16string_view((char16_t*)sv2.data(), name_len);

                        sv2 = sv2.substr(name_len * sizeof(char16_t));
                        len += name_len * sizeof(char16_t);
                    }

                    break;
                }

                case tds_token::ROW:
                {
                    vector<value> row;

                    row.resize(cols.size());

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        handle_row_col(col, cols[i].type, cols[i].max_length, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case tds_token::NBCROW:
                {
                    if (cols.empty())
                        break;

                    vector<value> row;

                    row.resize(cols.size());

                    auto bitset_length = (cols.size() + 7) / 8;

                    if (sv.length() < bitset_length)
                        throw formatted_error(FMT_STRING("Short NBCROW message ({} bytes, expected at least {})."), sv.length(), bitset_length);

                    string_view bitset(sv.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv = sv.substr(bitset_length);

                    for (unsigned int i = 0; i < row.size(); i++) {
                        auto& col = row[i];

                        if (i != 0) {
                            if ((i & 7) == 0) {
                                bitset = bitset.substr(1);
                                bsv = bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (bsv & 1) // NULL
                            col.is_null = true;
                        else
                            handle_row_col(col, cols[i].type, cols[i].max_length, sv);
                    }

                    rows.push_back(row);

                    break;
                }

                case tds_token::ORDER:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short ORDER message ({} bytes, expected at least {})."), sv.length(), sizeof(uint16_t));

                    auto len = *(uint16_t*)sv.data();
                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short ORDER message ({} bytes, expected {})."), sv.length(), len);

                    break;
                }

                case tds_token::RETURNSTATUS:
                {
                    if (sv.length() < sizeof(int32_t))
                        throw formatted_error(FMT_STRING("Short RETURNSTATUS message ({} bytes, expected 4)."), sv.length());

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} while executing SQL batch."), type);
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
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), sv.length());

                auto tebt = (tds_envchange_begin_trans*)ec;

                if (tebt->header.length < offsetof(tds_envchange_begin_trans, new_len))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), tebt->header.length);

                if (tebt->new_len != 8)
                    throw formatted_error(FMT_STRING("Unexpected transaction ID length ({} bytes, expected 8)."), tebt->new_len);

                trans_id = tebt->trans_id;

                break;
            }

            case tds_envchange_type::rollback_trans: {
                if (sv.length() < sizeof(tds_envchange_rollback_trans) - offsetof(tds_envchange_rollback_trans, header.type))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), sv.length());

                auto tert = (tds_envchange_rollback_trans*)ec;

                if (tert->header.length < offsetof(tds_envchange_rollback_trans, new_len))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), tert->header.length);

                trans_id = 0;

                break;
            }

            case tds_envchange_type::commit_trans: {
                if (sv.length() < sizeof(tds_envchange_commit_trans) - offsetof(tds_envchange_begin_trans, header.type))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), sv.length());

                auto tect = (tds_envchange_commit_trans*)ec;

                if (tect->header.length < offsetof(tds_envchange_begin_trans, new_len))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected 11)."), tect->header.length);

                trans_id = 0;

                break;
            }

            case tds_envchange_type::packet_size: {
                if (sv.length() < sizeof(tds_envchange_packet_size) - offsetof(tds_envchange_packet_size, header.type))
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected at least 2)."), sv.length());

                auto teps = (tds_envchange_packet_size*)ec;

                if (teps->header.length < sizeof(tds_envchange_packet_size) + (teps->new_len * sizeof(char16_t))) {
                    throw formatted_error(FMT_STRING("Short ENVCHANGE message ({} bytes, expected at least {})."),
                                          teps->header.length, sizeof(tds_envchange_packet_size) + (teps->new_len * sizeof(char16_t)));
                }

                u16string_view s((char16_t*)&teps[1], teps->new_len);
                uint32_t v = 0;

                for (auto c : s) {
                    if (c >= '0' && c <= '9') {
                        v *= 10;
                        v += c - '0';
                    } else
                        throw formatted_error(FMT_STRING("Server returned invalid packet size \"{}\"."), utf16_to_utf8(s));
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
            throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (tds_token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case tds_token::DONE:
                case tds_token::DONEINPROC:
                case tds_token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                    sv = sv.substr(sizeof(tds_done_msg));
                break;

                case tds_token::INFO:
                case tds_token::TDS_ERROR:
                case tds_token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                    if (type == tds_token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == tds_token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error(FMT_STRING("TM_BEGIN_XACT request failed: {}"), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == tds_token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} in transaction manager response."), type);
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
                throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

            string_view sv = payload;

            while (!sv.empty()) {
                auto type = (tds_token)sv[0];
                sv = sv.substr(1);

                switch (type) {
                    case tds_token::DONE:
                    case tds_token::DONEINPROC:
                    case tds_token::DONEPROC:
                        if (sv.length() < sizeof(tds_done_msg))
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                        sv = sv.substr(sizeof(tds_done_msg));
                        break;

                    case tds_token::INFO:
                    case tds_token::TDS_ERROR:
                    case tds_token::ENVCHANGE:
                    {
                        if (sv.length() < sizeof(uint16_t))
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                        auto len = *(uint16_t*)&sv[0];

                        sv = sv.substr(sizeof(uint16_t));

                        if (sv.length() < len)
                            throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                        if (type == tds_token::INFO) {
                            if (conn.impl->message_handler) {
                                try {
                                    conn.impl->handle_info_msg(sv.substr(0, len), false);
                                } catch (...) {
                                }
                            }

                        } else if (type == tds_token::TDS_ERROR) {
                            if (conn.impl->message_handler) {
                                try {
                                    conn.impl->handle_info_msg(sv.substr(0, len), true);
                                } catch (...) {
                                }
                            }

                            throw formatted_error(FMT_STRING("TM_ROLLBACK_XACT request failed: {}"), utf16_to_utf8(extract_message(sv.substr(0, len))));
                        } else if (type == tds_token::ENVCHANGE)
                            conn.impl->handle_envchange_msg(sv.substr(0, len));

                        sv = sv.substr(len);

                        break;
                    }

                    default:
                        throw formatted_error(FMT_STRING("Unhandled token type {} in transaction manager response."), type);
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
            throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

        string_view sv = payload;

        while (!sv.empty()) {
            auto type = (tds_token)sv[0];
            sv = sv.substr(1);

            switch (type) {
                case tds_token::DONE:
                case tds_token::DONEINPROC:
                case tds_token::DONEPROC:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), sizeof(tds_done_msg));

                    sv = sv.substr(sizeof(tds_done_msg));
                break;

                case tds_token::INFO:
                case tds_token::TDS_ERROR:
                case tds_token::ENVCHANGE:
                {
                    if (sv.length() < sizeof(uint16_t))
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                    if (type == tds_token::INFO) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), false);
                    } else if (type == tds_token::TDS_ERROR) {
                        if (conn.impl->message_handler)
                            conn.impl->handle_info_msg(sv.substr(0, len), true);

                        throw formatted_error(FMT_STRING("TM_COMMIT_XACT request failed: {}"), utf16_to_utf8(extract_message(sv.substr(0, len))));
                    } else if (type == tds_token::ENVCHANGE)
                        conn.impl->handle_envchange_msg(sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} in transaction manager response."), type);
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
};
