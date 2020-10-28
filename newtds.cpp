#include "newtds.h"
#include <iostream>
#include <string>
#include <codecvt>
#include <list>
#include <span>
#include <map>
#include <fmt/format.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#define DEBUG_SHOW_MSGS

using namespace std;

static const string db_server = "luthien", db_user = "sa", db_password = "Password1$";
static const uint16_t db_port = 1433;

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

            case tds_token::ERROR:
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

template<>
struct fmt::formatter<enum tds_sql_type> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum tds_sql_type t, format_context& ctx) {
        switch (t) {
            case tds_sql_type::IMAGE:
                return format_to(ctx.out(), "IMAGE");

            case tds_sql_type::TEXT:
                return format_to(ctx.out(), "TEXT");

            case tds_sql_type::UNIQUEIDENTIFIER:
                return format_to(ctx.out(), "UNIQUEIDENTIFIER");

            case tds_sql_type::INTN:
                return format_to(ctx.out(), "INTN");

            case tds_sql_type::DATEN:
                return format_to(ctx.out(), "DATEN");

            case tds_sql_type::TIMEN:
                return format_to(ctx.out(), "TIMEN");

            case tds_sql_type::DATETIME2N:
                return format_to(ctx.out(), "DATETIME2N");

            case tds_sql_type::DATETIMEOFFSETN:
                return format_to(ctx.out(), "DATETIMEOFFSETN");

            case tds_sql_type::SQL_VARIANT:
                return format_to(ctx.out(), "SQL_VARIANT");

            case tds_sql_type::NTEXT:
                return format_to(ctx.out(), "NTEXT");

            case tds_sql_type::BITN:
                return format_to(ctx.out(), "BITN");

            case tds_sql_type::DECIMAL:
                return format_to(ctx.out(), "DECIMAL");

            case tds_sql_type::NUMERIC:
                return format_to(ctx.out(), "NUMERIC");

            case tds_sql_type::FLTN:
                return format_to(ctx.out(), "FLTN");

            case tds_sql_type::MONEYN:
                return format_to(ctx.out(), "MONEYN");

            case tds_sql_type::DATETIMN:
                return format_to(ctx.out(), "DATETIMN");

            case tds_sql_type::VARBINARY:
                return format_to(ctx.out(), "VARBINARY");

            case tds_sql_type::VARCHAR:
                return format_to(ctx.out(), "VARCHAR");

            case tds_sql_type::BINARY:
                return format_to(ctx.out(), "BINARY");

            case tds_sql_type::CHAR:
                return format_to(ctx.out(), "CHAR");

            case tds_sql_type::NVARCHAR:
                return format_to(ctx.out(), "NVARCHAR");

            case tds_sql_type::NCHAR:
                return format_to(ctx.out(), "NCHAR");

            case tds_sql_type::UDT:
                return format_to(ctx.out(), "UDT");

            case tds_sql_type::XML:
                return format_to(ctx.out(), "XML");

            case tds_sql_type::SQL_NULL:
                return format_to(ctx.out(), "NULL");

            case tds_sql_type::TINYINT:
                return format_to(ctx.out(), "TINYINT");

            case tds_sql_type::BIT:
                return format_to(ctx.out(), "BIT");

            case tds_sql_type::SMALLINT:
                return format_to(ctx.out(), "SMALLINT");

            case tds_sql_type::INT:
                return format_to(ctx.out(), "INT");

            case tds_sql_type::DATETIM4:
                return format_to(ctx.out(), "DATETIM4");

            case tds_sql_type::REAL:
                return format_to(ctx.out(), "REAL");

            case tds_sql_type::MONEY:
                return format_to(ctx.out(), "MONEY");

            case tds_sql_type::DATETIME:
                return format_to(ctx.out(), "DATETIME");

            case tds_sql_type::FLOAT:
                return format_to(ctx.out(), "FLOAT");

            case tds_sql_type::SMALLMONEY:
                return format_to(ctx.out(), "SMALLMONEY");

            case tds_sql_type::BIGINT:
                return format_to(ctx.out(), "BIGINT");

            default:
                return format_to(ctx.out(), "{:x}", (uint8_t)t);
        }
    }
};

static u16string utf8_to_utf16(const string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.from_bytes(sv.data(), sv.data() + sv.length());
}

static string utf16_to_utf8(const u16string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.to_bytes(sv.data(), sv.data() + sv.length());
}

static bool is_byte_len_type(enum tds_sql_type type) {
    switch (type) {
        case tds_sql_type::UNIQUEIDENTIFIER:
        case tds_sql_type::INTN:
        case tds_sql_type::DECIMAL:
        case tds_sql_type::NUMERIC:
        case tds_sql_type::BITN:
        case tds_sql_type::FLTN:
        case tds_sql_type::MONEYN:
        case tds_sql_type::DATETIMN:
        case tds_sql_type::DATEN:
        case tds_sql_type::TIMEN:
        case tds_sql_type::DATETIME2N:
        case tds_sql_type::DATETIMEOFFSETN:
            return true;

        default:
            return false;
    }
}

tds::tds(const string& server, uint16_t port, const string_view& user, const string_view& password,
         const msg_handler& message_handler) : message_handler(message_handler) {
    connect(server, port);

    send_prelogin_msg();

    send_login_msg(user, password);
}

tds::~tds() {
    if (sock != 0)
        close(sock);
}

void tds::connect(const string& server, uint16_t port) {
    struct addrinfo hints;
    struct addrinfo* res;
    struct addrinfo* orig_res;
    int ret;

    // FIXME - make sure this works with both IPv4 and IPv6

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ret = getaddrinfo(server.c_str(), nullptr, &hints, &res);

    if (ret != 0)
        throw formatted_error(FMT_STRING("getaddrinfo returned {}"), ret);

    orig_res = res;
    sock = 0;

    do {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if (sock < 0)
            continue;

        if (res->ai_family == AF_INET)
            ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(port);
        else if (res->ai_family == AF_INET6)
            ((struct sockaddr_in6*)res->ai_addr)->sin6_port = htons(port);
        else {
            close(sock);
            sock = 0;
            continue;
        }

        if (::connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
            close(sock);
            sock = 0;
            continue;
        }

        break;
    } while ((res = res->ai_next));

    freeaddrinfo(orig_res);

    if (sock <= 0)
        throw formatted_error(FMT_STRING("Could not connect to {}:{}."), server, port);
}

void tds::send_prelogin_msg() {
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

void tds::send_login_msg(const string_view& user, const string_view& password) {
    enum tds_msg type;
    string payload;

    // FIXME - support SSPI

    auto user_u16 = utf8_to_utf16(user);
    auto password_u16 = utf8_to_utf16(password);

    // FIXME - client PID
    // FIXME - option flags (1, 2, 3)
    // FIXME - collation
    // FIXME - client name
    // FIXME - app name
    // FIXME - server name
    // FIXME - locale name?

    send_login_msg2(0x74000004, 4096, 0xf8f28306, 0x5ab7, 0, 0xe0, 0x03, 0, 0x08, 0x436,
                    u"beren", user_u16, password_u16, u"test program", u"luthien", u"", u"us_english",
                    u"", u"", u"");

    wait_for_msg(type, payload);
    // FIXME - timeout

    if (type != tds_msg::tabular_result)
        throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

    string_view sv = payload;
    bool received_loginack = false;

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
            case tds_token::ERROR:
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
                } else if (type == tds_token::ERROR) {
                    if (message_handler)
                        handle_info_msg(sv.substr(0, len), true);
                }

                sv = sv.substr(len);

                break;
            }

            default:
                throw formatted_error(FMT_STRING("Unhandled token type {} while logging in."), type);
        }
    }

    if (!received_loginack)
        throw formatted_error(FMT_STRING("Did not receive LOGINACK message from server."));
}

void tds::send_login_msg2(uint32_t tds_version, uint32_t packet_size, uint32_t client_version, uint32_t client_pid,
                          uint32_t connexion_id, uint8_t option_flags1, uint8_t option_flags2, uint8_t sql_type_flags,
                          uint8_t option_flags3, uint32_t collation, const u16string_view& client_name,
                          const u16string_view& username, const u16string_view& password, const u16string_view& app_name,
                          const u16string_view& server_name, const u16string_view& interface_library,
                          const u16string_view& locale, const u16string_view& database, const u16string_view& attach_db,
                          const u16string_view& new_password) {
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
    msg->option_flags2 = option_flags2;
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

    // FIXME - SSPI

    msg->sspi_offset = 0;
    msg->sspi_length = 0;

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

    msg->sspi_long_offset = 0;
    msg->sspi_long_length = 0;

    send_msg(tds_msg::tds7_login, payload);
}

void tds::send_msg(enum tds_msg type, const string_view& msg) {
    string payload;

    payload.resize(msg.length() + sizeof(tds_header));

    auto h = (tds_header*)payload.data();

    h->type = type;
    h->status = 1; // last message
    h->length = htons((uint16_t)(msg.length() + sizeof(tds_header)));
    h->spid = 0;
    h->packet_id = 0; // FIXME?
    h->window = 0;

    if (!msg.empty())
        memcpy(payload.data() + sizeof(tds_header), msg.data(), msg.size());

    auto ret = send(sock, payload.data(), payload.length(), 0);

    if (ret < 0)
        throw formatted_error(FMT_STRING("send failed (error {})"), errno);

    if ((size_t)ret < payload.length())
        throw formatted_error(FMT_STRING("send sent {} bytes, expected {}"), ret, payload.length());
}

void tds::send_msg(enum tds_msg type, const span<uint8_t>& msg) {
    send_msg(type, string_view{(const char*)msg.data(), (const char*)msg.data() + msg.size()});
}

void tds::wait_for_msg(enum tds_msg& type, string& payload) {
    tds_header h;

    auto ret = recv(sock, &h, sizeof(tds_header), MSG_WAITALL);

    if (ret < 0)
        throw formatted_error(FMT_STRING("recv failed (error {})"), errno);

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

        ret = recv(sock, payload.data(), len, MSG_WAITALL);

        if (ret < 0)
            throw formatted_error(FMT_STRING("recv failed (error {})"), errno);

        if (ret == 0)
            throw formatted_error(FMT_STRING("Disconnected."));

        if ((unsigned int)ret < len)
            throw formatted_error(FMT_STRING("recv received {} bytes, expected {}"), ret, len);
    } else
        payload.clear();
}

void tds::handle_loginack_msg(string_view sv) {
    uint8_t interface, server_name_len;
    uint32_t tds_version, server_version;
    u16string_view server_name;

    if (sv.length() < 10)
        throw runtime_error("Short LOGINACK message.");

    server_name_len = (uint8_t)sv[5];

    if (sv.length() < 10 + (server_name_len * sizeof(char16_t)))
        throw runtime_error("Short LOGINACK message.");

    interface = (uint8_t)sv[0];
    tds_version = *(uint32_t*)&sv[1];
    server_name = u16string_view((char16_t*)&sv[6], server_name_len);
    server_version = *(uint32_t*)&sv[6 + (server_name_len * sizeof(char16_t))];

#ifdef DEBUG_SHOW_MSGS
    while (!server_name.empty() && server_name.back() == 0) {
        server_name = server_name.substr(0, server_name.length() - 1);
    }

    fmt::print("LOGINACK: interface = {}, TDS version = {:x}, server = {}, server version = {}.{}.{}\n",
                interface, tds_version, utf16_to_utf8(server_name), server_version & 0xff, (server_version & 0xff00) >> 8,
                ((server_version & 0xff0000) >> 8) | (server_version >> 24));
#endif

    if (tds_version != tds_74_version)
        throw formatted_error(FMT_STRING("Server not using TDS 7.4. Version was {:x}, expected {:x}."), tds_version, tds_74_version);
}

void tds::handle_info_msg(const string_view& sv, bool error) {
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

    // FIXME - get rid of unused params

    message_handler(utf16_to_utf8(server_name), utf16_to_utf8(msg), utf16_to_utf8(proc_name), "", msgno, line_number, state, 0,
                    severity, 0, error);
}

tds_date::tds_date(int32_t num) : num(num) {
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

tds_date::tds_date(uint16_t year, uint8_t month, uint8_t day) : year(year), month(month), day(day) {
    int m2 = ((int)month - 14) / 12;
    long long n;

    n = (1461 * ((int)year + 4800 + m2)) / 4;
    n += (367 * ((int)month - 2 - (12 * m2))) / 12;
    n -= (3 * (((int)year + 4900 + m2)/100)) / 4;
    n += day;
    n -= 2447096;

    num = static_cast<int>(n);
}

template<>
struct fmt::formatter<tds_date> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_date& d, format_context& ctx) {
        return format_to(ctx.out(), "{:04}-{:02}-{:02}", d.year, d.month, d.day);
    }
};

template<>
struct fmt::formatter<tds_time> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_time& t, format_context& ctx) {
        return format_to(ctx.out(), "{:02}:{:02}:{:02}", t.hour, t.minute, t.second);
    }
};

template<>
struct fmt::formatter<tds_datetime> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_datetime& dt, format_context& ctx) {
        return format_to(ctx.out(), "{} {}", dt.date, dt.time);
    }
};

template<>
struct fmt::formatter<tds_datetimeoffset> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_datetimeoffset& dto, format_context& ctx) {
        auto absoff = abs(dto.offset);

        return format_to(ctx.out(), "{} {} {}{:02}:{:02}", dto.date, dto.time,
                         dto.offset < 0 ? '-' : '+',
                         absoff / 60, absoff % 60);
    }
};

tds_param::tds_param() {
    type = tds_sql_type::SQL_NULL;
}

tds_param::tds_param(int32_t i) {
    type = tds_sql_type::INTN;

    val.resize(sizeof(int32_t));
    *(int32_t*)val.data() = i;
}

tds_param::tds_param(const optional<int32_t>& i) {
    type = tds_sql_type::INTN;

    val.resize(sizeof(int32_t));

    if (i.has_value())
        *(int32_t*)val.data() = i.value();
    else
        is_null = true;
}

tds_param::tds_param(const u16string_view& sv) {
    type = tds_sql_type::NVARCHAR;
    val.resize(sv.length() * sizeof(char16_t));
    memcpy(val.data(), sv.data(), val.length());
}

tds_param::tds_param(const u16string& sv) : tds_param(u16string_view(sv)) {
}

tds_param::tds_param(const char16_t* sv) : tds_param(u16string_view(sv)) {
}

tds_param::tds_param(const optional<u16string_view>& sv) {
    type = tds_sql_type::NVARCHAR;

    if (!sv.has_value())
        is_null = true;
    else {
        val.resize(sv.value().length() * sizeof(char16_t));
        memcpy(val.data(), sv.value().data(), sv.value().length());
    }
}

tds_param::tds_param(const string_view& sv) {
    type = tds_sql_type::VARCHAR;
    val.resize(sv.length());
    memcpy(val.data(), sv.data(), val.length());
}

tds_param::tds_param(const string& sv) : tds_param(string_view(sv)) {
}

tds_param::tds_param(const char* sv) : tds_param(string_view(sv)) {
}

tds_param::tds_param(const optional<string_view>& sv) {
    type = tds_sql_type::VARCHAR;

    if (!sv.has_value())
        is_null = true;
    else {
        val.resize(sv.value().length());
        memcpy(val.data(), sv.value().data(), sv.value().length());
    }
}

tds_param::tds_param(const u8string_view& sv) {
    auto s = utf8_to_utf16(string_view((char*)sv.data(), sv.length()));

    type = tds_sql_type::NVARCHAR;
    val.resize(s.length() * sizeof(char16_t));
    memcpy(val.data(), s.data(), val.length());
}

tds_param::tds_param(const u8string& sv) : tds_param(u8string_view(sv)) {
}

tds_param::tds_param(const char8_t* sv) : tds_param(u8string_view(sv)) {
}

tds_param::tds_param(const optional<u8string_view>& sv) {
    type = tds_sql_type::NVARCHAR;

    if (!sv.has_value())
        is_null = true;
    else {
        auto s = utf8_to_utf16(string_view((char*)sv.value().data(), sv.value().length()));

        val.resize(s.length() * sizeof(char16_t));
        memcpy(val.data(), s.data(), s.length());
    }
}

tds_param::tds_param(float f) {
    type = tds_sql_type::FLTN;

    val.resize(sizeof(float));
    memcpy(val.data(), &f, sizeof(float));
}

tds_param::tds_param(const optional<float>& f) {
    type = tds_sql_type::FLTN;
    val.resize(sizeof(float));

    if (!f.has_value())
        is_null = true;
    else {
        auto v = f.value();

        memcpy(val.data(), &v, sizeof(float));
    }
}

tds_param::tds_param(double d) {
    type = tds_sql_type::FLTN;

    val.resize(sizeof(double));
    memcpy(val.data(), &d, sizeof(double));
}

tds_param::tds_param(const optional<double>& d) {
    type = tds_sql_type::FLTN;
    val.resize(sizeof(double));

    if (!d.has_value())
        is_null = true;
    else {
        auto v = d.value();

        memcpy(val.data(), &v, sizeof(double));
    }
}

tds_param::tds_param(const tds_date& d) {
    int32_t n;

    type = tds_sql_type::DATEN;
    val.resize(3);

    n = d.num + 693595;
    memcpy(val.data(), &n, 3);
}

tds_param::tds_param(const optional<tds_date>& d) {
    type = tds_sql_type::DATEN;

    if (!d.has_value())
        is_null = true;
    else {
        int32_t n = d.value().num + 693595;
        val.resize(3);
        memcpy(val.data(), &n, 3);
    }
}

tds_param::tds_param(const tds_time& t) {
    uint32_t secs;

    secs = (unsigned int)t.hour * 3600;
    secs += (unsigned int)t.minute * 60;
    secs += t.second;

    type = tds_sql_type::TIMEN;
    max_length = 0; // TIME(0)

    val.resize(3);
    memcpy(val.data(), &secs, val.length());
}

tds_param::tds_param(const optional<tds_time>& t) {
    type = tds_sql_type::TIMEN;
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

tds_param::tds_param(const tds_datetime& dt) {
    int32_t n;
    uint32_t secs;

    type = tds_sql_type::DATETIME2N;
    val.resize(6);
    max_length = 0; // DATETIME2(0)

    secs = (unsigned int)dt.time.hour * 3600;
    secs += (unsigned int)dt.time.minute * 60;
    secs += dt.time.second;

    memcpy(val.data(), &secs, 3);

    n = dt.date.num + 693595;
    memcpy(val.data() + 3, &n, 3);
}

tds_param::tds_param(const optional<tds_datetime>& dt) {
    type = tds_sql_type::DATETIME2N;
    val.resize(6);
    max_length = 0; // DATETIME2(0)

    if (!dt.has_value())
        is_null = true;
    else {
        int32_t n;
        uint32_t secs;

        secs = (unsigned int)dt.value().time.hour * 3600;
        secs += (unsigned int)dt.value().time.minute * 60;
        secs += dt.value().time.second;

        memcpy(val.data(), &secs, 3);

        n = dt.value().date.num + 693595;
        memcpy(val.data() + 3, &n, 3);
    }
}

tds_param::tds_param(const tds_datetimeoffset& dto) {
    int32_t n;
    uint32_t secs;

    type = tds_sql_type::DATETIMEOFFSETN;
    val.resize(8);
    max_length = 0; // DATETIMEOFFSET(0)

    secs = (unsigned int)dto.time.hour * 3600;
    secs += (unsigned int)dto.time.minute * 60;
    secs += dto.time.second;

    memcpy(val.data(), &secs, 3);

    n = dto.date.num + 693595;
    memcpy(val.data() + 3, &n, 3);

    *(int16_t*)(val.data() + 6) = dto.offset;
}

tds_param::tds_param(const optional<tds_datetimeoffset>& dto) {
    type = tds_sql_type::DATETIMEOFFSETN;
    val.resize(8);
    max_length = 0; // DATETIMEOFFSET(0)

    if (!dto.has_value())
        is_null = true;
    else {
        int32_t n;
        uint32_t secs;

        secs = (unsigned int)dto.value().time.hour * 3600;
        secs += (unsigned int)dto.value().time.minute * 60;
        secs += dto.value().time.second;

        memcpy(val.data(), &secs, 3);

        n = dto.value().date.num + 693595;
        memcpy(val.data() + 3, &n, 3);

        *(int16_t*)(val.data() + 6) = dto.value().offset;
    }
}

tds_param::tds_param(const span<byte>& bin) {
    // FIXME - std::optional version of this too

    type = tds_sql_type::VARBINARY;
    val.resize(bin.size());
    memcpy(val.data(), bin.data(), bin.size());
}

tds_param::tds_param(bool b) {
    type = tds_sql_type::BITN;
    val.resize(sizeof(uint8_t));
    *(uint8_t*)val.data() = b ? 1 : 0;
}

tds_param::tds_param(const optional<bool>& b) {
    type = tds_sql_type::BITN;
    val.resize(sizeof(uint8_t));

    if (b.has_value())
        *(uint8_t*)val.data() = b ? 1 : 0;
    else
        is_null = true;
}

tds_param::operator string() const {
    return fmt::format(FMT_STRING("{}"), *this);
}

tds_param::operator u16string() const {
    if (type == tds_sql_type::NVARCHAR || type == tds_sql_type::NCHAR)
        return u16string(u16string_view((char16_t*)val.data(), val.length() / sizeof(char16_t)));
    else
        return utf8_to_utf16(operator string()); // FIXME - VARCHARs might not be valid UTF-8
}

template<>
struct fmt::formatter<tds_param> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_param& p, format_context& ctx) {
        if (p.is_null)
            return format_to(ctx.out(), "NULL");

        switch (p.type) {
            case tds_sql_type::TINYINT:
                return format_to(ctx.out(), "{}", *(uint8_t*)p.val.data());

            case tds_sql_type::SMALLINT:
                return format_to(ctx.out(), "{}", *(int16_t*)p.val.data());

            case tds_sql_type::INT:
                return format_to(ctx.out(), "{}", *(int32_t*)p.val.data());

            case tds_sql_type::BIGINT:
                return format_to(ctx.out(), "{}", *(int64_t*)p.val.data());

            case tds_sql_type::INTN:
                switch (p.val.length()) {
                    case 1:
                        return format_to(ctx.out(), "{}", *(uint8_t*)p.val.data());

                    case 2:
                        return format_to(ctx.out(), "{}", *(int16_t*)p.val.data());

                    case 4:
                        return format_to(ctx.out(), "{}", *(int32_t*)p.val.data());

                    case 8:
                        return format_to(ctx.out(), "{}", *(int64_t*)p.val.data());

                    default:
                        throw formatted_error(FMT_STRING("INTN has unexpected length {}."), p.val.length());
                }
            break;

            case tds_sql_type::NVARCHAR:
            case tds_sql_type::NCHAR:
            {
                u16string_view sv((char16_t*)p.val.data(), p.val.length() / sizeof(char16_t));
                auto s = utf16_to_utf8(sv);

                return format_to(ctx.out(), "{}", s);
            }

            case tds_sql_type::VARCHAR:
            case tds_sql_type::CHAR:
            {
                string_view sv(p.val.data(), p.val.length());

                return format_to(ctx.out(), "{}", sv);
            }

            case tds_sql_type::REAL:
                return format_to(ctx.out(), "{}", *(float*)p.val.data());

            case tds_sql_type::FLOAT:
                return format_to(ctx.out(), "{}", *(double*)p.val.data());

            case tds_sql_type::FLTN:
                switch (p.val.length()) {
                    case sizeof(float):
                        return format_to(ctx.out(), "{}", *(float*)p.val.data());

                    case sizeof(double):
                        return format_to(ctx.out(), "{}", *(double*)p.val.data());

                    default:
                        throw formatted_error(FMT_STRING("FLTN has unexpected length {}."), p.val.length());
                }
            break;

            case tds_sql_type::DATEN: {
                uint32_t v;

                memcpy(&v, p.val.data(), 3);
                v &= 0xffffff;

                tds_date d(v - 693595);

                return format_to(ctx.out(), "{}", d);
            }

            case tds_sql_type::TIMEN: {
                uint64_t secs = 0;

                memcpy(&secs, p.val.data(), min(sizeof(uint64_t), p.val.length()));

                for (auto n = p.max_length; n > 0; n--) {
                    secs /= 10;
                }

                tds_time t((uint32_t)secs);

                return format_to(ctx.out(), "{}", t);
            }

            case tds_sql_type::DATETIME2N: {
                uint64_t secs = 0;
                uint32_t v;

                memcpy(&secs, p.val.data(), min(sizeof(uint64_t), p.val.length() - 3));

                for (auto n = p.max_length; n > 0; n--) {
                    secs /= 10;
                }

                memcpy(&v, p.val.data() + p.val.length() - 3, 3);
                v &= 0xffffff;

                tds_datetime dt(v - 693595, (uint32_t)secs);

                return format_to(ctx.out(), "{}", dt);
            }

            case tds_sql_type::DATETIME: {
                auto v = *(int32_t*)p.val.data();
                auto secs = *(uint32_t*)(p.val.data() + sizeof(int32_t));

                secs /= 300;

                tds_datetime dt(v, secs);

                return format_to(ctx.out(), "{}", dt);
            }

            case tds_sql_type::DATETIMN: { // SMALLDATETIME
                auto v = *(uint16_t*)p.val.data();
                auto mins = *(uint16_t*)(p.val.data() + sizeof(uint16_t));

                tds_datetime dt(v, mins * 60);

                return format_to(ctx.out(), "{}", dt);
            }

            case tds_sql_type::DATETIMEOFFSETN: {
                uint64_t secs = 0;
                uint32_t v;

                memcpy(&secs, p.val.data(), min(sizeof(uint64_t), p.val.length() - 5));

                for (auto n = p.max_length; n > 0; n--) {
                    secs /= 10;
                }

                memcpy(&v, p.val.data() + p.val.length() - 5, 3);
                v &= 0xffffff;

                tds_datetimeoffset dto(v - 693595, (uint32_t)secs, *(int16_t*)(p.val.data() + p.val.length() - sizeof(int16_t)));

                return format_to(ctx.out(), "{}", dto);
            }

            case tds_sql_type::VARBINARY:
            case tds_sql_type::BINARY:
            {
                string s = "0x";

                for (auto c : p.val) {
                    s += fmt::format(FMT_STRING("{:02x}"), (uint8_t)c);
                }

                return format_to(ctx.out(), "{}", s);
            }

            case tds_sql_type::BITN:
                return format_to(ctx.out(), "{}", p.val[0] != 0);

            default:
                throw formatted_error(FMT_STRING("Unable to format type {} as string."), p.type);
        }
    }
};

template<typename T>
struct fmt::formatter<tds_output_param<T>> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_output_param<T>& p, format_context& ctx) {
        return format_to(ctx.out(), "{}", static_cast<tds_param>(p));
    }
};

template<>
struct fmt::formatter<tds_column> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds_column& c, format_context& ctx) {
        return format_to(ctx.out(), "{}", static_cast<tds_param>(c));
    }
};

static size_t fixed_len_size(enum tds_sql_type type) {
    switch (type) {
        case tds_sql_type::TINYINT:
            return 1;

        case tds_sql_type::SMALLINT:
            return 2;

        case tds_sql_type::INT:
            return 4;

        case tds_sql_type::BIGINT:
            return 8;

        case tds_sql_type::DATETIME:
            return 8;

        case tds_sql_type::DATETIM4:
            return 4;

        case tds_sql_type::SMALLMONEY:
            return 4;

        case tds_sql_type::MONEY:
            return 8;

        case tds_sql_type::REAL:
            return 4;

        case tds_sql_type::FLOAT:
            return 8;

        case tds_sql_type::SQL_NULL:
        case tds_sql_type::BIT:
            throw formatted_error(FMT_STRING("FIXME - fixed_len_size for {}"), type); // FIXME

        default:
            return 0;
    }
}

void rpc::do_rpc(tds& conn, const u16string_view& name) {
    size_t bufsize;

    bufsize = sizeof(tds_all_headers) + sizeof(uint16_t) + (name.length() * sizeof(uint16_t)) + sizeof(uint16_t);

    for (const auto& p : params) {
        switch (p.type) {
            case tds_sql_type::SQL_NULL:
            case tds_sql_type::TINYINT:
            case tds_sql_type::BIT:
            case tds_sql_type::SMALLINT:
            case tds_sql_type::INT:
            case tds_sql_type::DATETIM4:
            case tds_sql_type::REAL:
            case tds_sql_type::MONEY:
            case tds_sql_type::DATETIME:
            case tds_sql_type::FLOAT:
            case tds_sql_type::SMALLMONEY:
            case tds_sql_type::BIGINT:
                bufsize += sizeof(tds_param_header) + fixed_len_size(p.type);
                break;

            case tds_sql_type::UNIQUEIDENTIFIER:
            case tds_sql_type::DECIMAL:
            case tds_sql_type::NUMERIC:
            case tds_sql_type::MONEYN:
            case tds_sql_type::DATETIMN:
            case tds_sql_type::DATEN:
                bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length());
                break;

            case tds_sql_type::INTN:
            case tds_sql_type::FLTN:
            case tds_sql_type::TIMEN:
            case tds_sql_type::DATETIME2N:
            case tds_sql_type::DATETIMEOFFSETN:
            case tds_sql_type::BITN:
                bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length()) + sizeof(uint8_t);
                break;

            case tds_sql_type::NVARCHAR:
            case tds_sql_type::VARCHAR:
                if (!p.is_null && p.val.length() > 8000) // MAX
                    bufsize += sizeof(tds_VARCHAR_MAX_param) + p.val.length() + sizeof(uint32_t);
                else
                    bufsize += sizeof(tds_VARCHAR_param) + (p.is_null ? 0 : p.val.length());

                break;

            case tds_sql_type::VARBINARY:
                if (!p.is_null && p.val.length() > 8000) // MAX
                    bufsize += sizeof(tds_VARBINARY_MAX_param) + p.val.length() + sizeof(uint32_t);
                else
                    bufsize += sizeof(tds_VARBINARY_param) + (p.is_null ? 0 : p.val.length());

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
    all_headers->trans_desc.descriptor = 0;
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
            case tds_sql_type::SQL_NULL:
            case tds_sql_type::TINYINT:
            case tds_sql_type::BIT:
            case tds_sql_type::SMALLINT:
            case tds_sql_type::INT:
            case tds_sql_type::DATETIM4:
            case tds_sql_type::REAL:
            case tds_sql_type::MONEY:
            case tds_sql_type::DATETIME:
            case tds_sql_type::FLOAT:
            case tds_sql_type::SMALLMONEY:
            case tds_sql_type::BIGINT:
                memcpy(ptr, p.val.data(), p.val.length());

                ptr += p.val.length();

                break;

            case tds_sql_type::INTN:
            case tds_sql_type::FLTN:
            case tds_sql_type::BITN:
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

            case tds_sql_type::TIMEN:
            case tds_sql_type::DATETIME2N:
            case tds_sql_type::DATETIMEOFFSETN:
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

            case tds_sql_type::UNIQUEIDENTIFIER:
            case tds_sql_type::DECIMAL:
            case tds_sql_type::NUMERIC:
            case tds_sql_type::MONEYN:
            case tds_sql_type::DATETIMN:
            case tds_sql_type::DATEN:
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

            case tds_sql_type::NVARCHAR:
            case tds_sql_type::VARCHAR:
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
                    h2->length = (uint16_t)(p.is_null ? 0 : p.val.length());

                    ptr += sizeof(tds_VARCHAR_param) - sizeof(tds_param_header);

                    if (!p.is_null) {
                        memcpy(ptr, p.val.data(), h2->length);
                        ptr += h2->length;
                    }
                }

                break;
            }

            case tds_sql_type::VARBINARY: {
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
                    h2->length = (uint16_t)(p.is_null ? 0 : p.val.length());

                    ptr += sizeof(tds_VARBINARY_param) - sizeof(tds_param_header);

                    if (!p.is_null) {
                        memcpy(ptr, p.val.data(), h2->length);
                        ptr += h2->length;
                    }
                }

                break;
            }

            default:
                throw formatted_error(FMT_STRING("Unhandled type {} in RPC params."), p.type);
        }
    }

    conn.send_msg(tds_msg::rpc, buf);

    enum tds_msg type;
    string payload;

    conn.wait_for_msg(type, payload);
    // FIXME - timeout

    if (type != tds_msg::tabular_result)
        throw formatted_error(FMT_STRING("Received message type {}, expected tabular_result"), (int)type);

    string_view sv = payload;
    uint16_t num_columns = 0;

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

                sv = sv.substr(sizeof(tds_done_msg));

                // FIXME - handle RPCs that return multiple row sets?

                if (type == tds_token::DONEINPROC)
                    finished = true;

                break;

            case tds_token::INFO:
            case tds_token::ERROR:
            case tds_token::ENVCHANGE:
            {
                if (sv.length() < sizeof(uint16_t))
                    throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected at least 2)."), type, sv.length());

                auto len = *(uint16_t*)&sv[0];

                sv = sv.substr(sizeof(uint16_t));

                if (sv.length() < len)
                    throw formatted_error(FMT_STRING("Short {} message ({} bytes, expected {})."), type, sv.length(), len);

                if (type == tds_token::INFO) {
                    if (conn.message_handler)
                        conn.handle_info_msg(sv.substr(0, len), false);
                } else if (type == tds_token::ERROR) {
                    if (conn.message_handler)
                        conn.handle_info_msg(sv.substr(0, len), true);

                    throw formatted_error(FMT_STRING("RPC {} failed."), utf16_to_utf8(name));
                }

                sv = sv.substr(len);

                break;
            }

            case tds_token::RETURNSTATUS:
            {
                if (sv.length() < sizeof(int32_t))
                    throw formatted_error(FMT_STRING("Short RETURNSTATUS message ({} bytes, expected 4)."), sv.length());

                return_status = *(int32_t*)&sv[0];

                sv = sv.substr(sizeof(int32_t));

                break;
            }

            case tds_token::COLMETADATA:
            {
                if (sv.length() < 4)
                    throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes, expected at least 4)."), sv.length());

                num_columns = *(uint16_t*)&sv[0];

                if (num_columns == 0) {
                    sv = sv.substr(4);
                    break;
                }

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

                    col.type = c.type;

                    switch (c.type) {
                        case tds_sql_type::SQL_NULL:
                        case tds_sql_type::TINYINT:
                        case tds_sql_type::BIT:
                        case tds_sql_type::SMALLINT:
                        case tds_sql_type::INT:
                        case tds_sql_type::DATETIM4:
                        case tds_sql_type::REAL:
                        case tds_sql_type::MONEY:
                        case tds_sql_type::DATETIME:
                        case tds_sql_type::FLOAT:
                        case tds_sql_type::SMALLMONEY:
                        case tds_sql_type::BIGINT:
                        case tds_sql_type::UNIQUEIDENTIFIER:
                        case tds_sql_type::DECIMAL:
                        case tds_sql_type::NUMERIC:
                        case tds_sql_type::MONEYN:
                        case tds_sql_type::DATEN:
                            // nop
                            break;

                        case tds_sql_type::INTN:
                        case tds_sql_type::FLTN:
                        case tds_sql_type::TIMEN:
                        case tds_sql_type::DATETIME2N:
                        case tds_sql_type::DATETIMN:
                        case tds_sql_type::DATETIMEOFFSETN:
                        case tds_sql_type::BITN:
                            if (sv2.length() < sizeof(uint8_t))
                                throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                            col.max_length = *(uint8_t*)sv2.data();

                            len++;
                            sv2 = sv2.substr(1);
                            break;

                        case tds_sql_type::VARCHAR:
                        case tds_sql_type::NVARCHAR:
                        case tds_sql_type::CHAR:
                        case tds_sql_type::NCHAR:
                            if (sv2.length() < sizeof(uint16_t) + sizeof(tds_collation))
                                throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t) + sizeof(tds_collation));

                            col.max_length = *(uint16_t*)sv2.data();

                            len += sizeof(uint16_t) + sizeof(tds_collation);
                            sv2 = sv2.substr(sizeof(uint16_t) + sizeof(tds_collation));
                            break;

                        case tds_sql_type::VARBINARY:
                        case tds_sql_type::BINARY:
                            if (sv2.length() < sizeof(uint16_t))
                                throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t));

                            col.max_length = *(uint16_t*)sv2.data();

                            len += sizeof(uint16_t);
                            sv2 = sv2.substr(sizeof(uint16_t));
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

                    col.name = utf16_to_utf8(u16string_view((char16_t*)sv2.data(), name_len));

                    sv2 = sv2.substr(name_len * sizeof(char16_t));
                    len += name_len * sizeof(char16_t);
                }

                sv = sv.substr(len);

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
                        tds_param& out = *output_params.at(h->param_ordinal);

                        if (len == 0)
                            out.is_null = true;
                        else {
                            out.is_null = false;

                            // FIXME - make sure not unexpected size?

                            out.val.resize(len);
                            memcpy(out.val.data(), (uint8_t*)&sv[0] + sizeof(tds_return_value) + 2, len);
                        }
                    }

                    sv = sv.substr(sizeof(tds_return_value) + 2 + len);
                } else
                    throw formatted_error(FMT_STRING("Unhandled type {} in RETURNVALUE message."), h->type);

                break;
            }

            case tds_token::ROW:
            {
                vector<tds_param> row;

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

                vector<tds_param> row;

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

            default:
                throw formatted_error(FMT_STRING("Unhandled token type {} while executing RPC."), type);
        }
    }
}

bool rpc::fetch_row() {
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

    // FIXME - wait for another packet

    return false;
}

void rpc::handle_row_col(tds_param& col, enum tds_sql_type type, unsigned int max_length, string_view& sv) {
    switch (type) {
        case tds_sql_type::SQL_NULL:
        case tds_sql_type::TINYINT:
        case tds_sql_type::BIT:
        case tds_sql_type::SMALLINT:
        case tds_sql_type::INT:
        case tds_sql_type::DATETIM4:
        case tds_sql_type::REAL:
        case tds_sql_type::MONEY:
        case tds_sql_type::DATETIME:
        case tds_sql_type::FLOAT:
        case tds_sql_type::SMALLMONEY:
        case tds_sql_type::BIGINT:
        {
            auto len = fixed_len_size(type);

            col.val.resize(len);

            if (sv.length() < len)
                throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

            memcpy(col.val.data(), sv.data(), len);

            sv = sv.substr(len);

            break;
        }

        case tds_sql_type::UNIQUEIDENTIFIER:
        case tds_sql_type::INTN:
        case tds_sql_type::DECIMAL:
        case tds_sql_type::NUMERIC:
        case tds_sql_type::BITN:
        case tds_sql_type::FLTN:
        case tds_sql_type::MONEYN:
        case tds_sql_type::DATETIMN:
        case tds_sql_type::DATEN:
        case tds_sql_type::TIMEN:
        case tds_sql_type::DATETIME2N:
        case tds_sql_type::DATETIMEOFFSETN:
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

        case tds_sql_type::VARCHAR:
        case tds_sql_type::NVARCHAR:
        case tds_sql_type::VARBINARY:
        case tds_sql_type::CHAR:
        case tds_sql_type::NCHAR:
        case tds_sql_type::BINARY:
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

                col.val.resize(len);
                col.is_null = false;

                if (sv.length() < len)
                    throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

                memcpy(col.val.data(), sv.data(), len);
                sv = sv.substr(len);
            }

            break;

        default:
            throw formatted_error(FMT_STRING("Unhandled type {} in ROW message."), type);
    }
}

// FIXME - can we do static assert if no. of question marks different from no. of parameters?
query::query(tds& conn, const string_view& q) {
    tds_output_param<int32_t> handle;

    {
        rpc r1(conn, u"sp_prepare", handle, u"", utf8_to_utf16(q), 1); // 1 means return metadata

#ifdef DEBUG_SHOW_MSGS
        fmt::print("sp_prepare handle is {}.\n", handle);
#endif

        cols = r1.cols;
    }

    r2.reset(new rpc(conn, u"sp_execute", static_cast<tds_param>(handle)));

    // FIXME - sp_unprepare (is this necessary?)
}

template<typename... Args>
query::query(tds& conn, const string_view& q, Args&&... args) {
    tds_output_param<int32_t> handle;
    string q2;
    bool in_quotes = false;
    unsigned int param_num = 1;

    // replace ? in q with parameters

    q2.reserve(q.length());

    for (unsigned int i = 0; i < q.length(); i++) {
        if (q[i] == '\'')
            in_quotes = !in_quotes;

        if (q[i] == '?' && !in_quotes) {
            q2 += "@P" + to_string(param_num);
            param_num++;
        } else
            q2 += q[i];
    }

    auto params_string = create_params_string(1, forward<Args>(args)...);

    {
        rpc r1(conn, u"sp_prepare", handle, utf8_to_utf16(params_string), utf8_to_utf16(q2), 1); // 1 means return metadata

#ifdef DEBUG_SHOW_MSGS
        fmt::print("sp_prepare handle is {}.\n", handle);
#endif

        cols = r1.cols;
    }

    r2.reset(new rpc(conn, u"sp_execute", static_cast<tds_param>(handle), forward<Args>(args)...));

    // FIXME - sp_unprepare (is this necessary?)
}

uint16_t query::num_columns() const {
    return (uint16_t)r2->cols.size();
}

const tds_column& query::operator[](uint16_t i) const {
    return r2->cols[i];
}

bool query::fetch_row() {
    return r2->fetch_row();
}

template<typename T, typename... Args>
string query::create_params_string(unsigned int num, T&& t, Args&&... args) {
    string s;

    s += create_params_string(num, t);

    if constexpr (sizeof...(args) != 0)
        s += ", " + create_params_string(num + 1, args...);

    return s;
}

template<typename T>
string query::create_params_string(unsigned int num, T&& t) {
    string s = "@P" + to_string(num) + " ";

    // FIXME - also add optional<T> versions

    if constexpr (is_same_v<decay_t<T>, int32_t>)
        return s + "INT";
    else if constexpr (is_same_v<decay_t<T>, int64_t>)
        return s + "BIGINT";
    else if constexpr (is_same_v<decay_t<T>, int16_t>)
        return s + "SMALLINT";
    else if constexpr (is_same_v<decay_t<T>, uint8_t>)
        return s + "TINYINT";
    else if constexpr (is_same_v<decay_t<T>, float>)
        return s + "REAL";
    else if constexpr (is_same_v<decay_t<T>, double>)
        return s + "FLOAT";
    else if constexpr (is_same_v<decay_t<T>, tds_date>)
        return s + "DATE";
    else if constexpr (is_same_v<decay_t<T>, tds_time>)
        return s + "TIME";
    else if constexpr (is_same_v<decay_t<T>, tds_datetime>)
        return s + "DATETIME2";
    else if constexpr (is_same_v<decay_t<T>, tds_datetimeoffset>)
        return s + "DATETIMEOFFSET";
    else if constexpr (is_same_v<decay_t<T>, bool>)
        return s + "BIT";
    else if constexpr (is_convertible_v<decay_t<T>, u16string_view>) {
        auto len = u16string_view(t).length();

        if (len > 4000)
            return s + "NVARCHAR(MAX)";
        else
            return s + "NVARCHAR(" + to_string(len == 0 ? 1 : len) + ")";
    } else if constexpr (is_convertible_v<decay_t<T>, string_view>) {
        auto len = string_view(t).length();

        if (len > 8000)
            return s + "VARCHAR(MAX)";
        else
            return s + "VARCHAR(" + to_string(len == 0 ? 1 : len) + ")";
    } else if constexpr (is_convertible_v<decay_t<T>, u8string_view>) {
        auto sv = u8string_view(t);
        auto len = utf8_to_utf16(string_view((char*)sv.data(), sv.length())).length();

        if (len > 4000)
            return s + "NVARCHAR(MAX)";
        else
            return s + "NVARCHAR(" + to_string(len == 0 ? 1 : len) + ")";
    } else if constexpr (is_constructible_v<span<byte>, add_lvalue_reference_t<decay_t<T>>>) {
        auto len = span<byte>(t).size();

        if (len > 8000)
            return s + "VARBINARY(MAX)";
        else
            return s + "VARBINARY(" + to_string(len == 0 ? 1 : len) + ")";
    } else {
        []<bool flag = false>() {
            static_assert(flag, "Unable to get SQL type from parameter.");
        }();
    }
}

static void show_msg(const string_view&, const string_view& message, const string_view&, const string_view&,
                     int32_t msgno, int32_t, int16_t, uint8_t, uint8_t severity, int, bool) {
    if (severity > 10)
        fmt::print("\x1b[31;1mError {}: {}\x1b[0m\n", msgno, message);
    else if (msgno == 50000) // match SSMS by not displaying message no. if 50000 (RAISERROR etc.)
        fmt::print("{}\n", message);
    else
        fmt::print("{}: {}\n", msgno, message);
}

template<typename T>
void test(T) = delete;

int main() {
    try {
        tds n(db_server, db_port, db_user, db_password, show_msg);

        query sq(n, "SELECT SYSTEM_USER AS [user], ? AS answer, ? AS greeting, ? AS now, ? AS pi, ? AS test", 42, "Hello", tds_datetimeoffset{2010, 10, 28, 17, 58, 50, -360}, 3.1415926f, true);

        for (uint16_t i = 0; i < sq.num_columns(); i++) {
            fmt::print("{}\t", sq[i].name);
        }
        fmt::print("\n");

        while (sq.fetch_row()) {
            for (uint16_t i = 0; i < sq.num_columns(); i++) {
                fmt::print("{}\t", sq[i]);
            }
            fmt::print("\n");
        }
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
