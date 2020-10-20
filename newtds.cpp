#include <iostream>
#include <string>
#include <codecvt>
#include <fmt/format.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

static const string db_server = "luthien", db_user = "sa", db_password = "Password1$";
static const uint16_t db_port = 1433;

class formatted_error : public exception {
public:
    template<typename T, typename... Args>
    formatted_error(const T& s, Args&&... args) {
        msg = fmt::format(s, forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

enum class tds_msg : uint8_t {
    sql_batch = 1,
    pretds7_login,
    rpc,
    tabular_result,
    attention_signal = 6,
    bulk_load_data,
    federated_auth_token,
    trans_man_req = 14,
    tds7_login = 16,
    sspi,
    prelogin
};

struct tds_header {
    enum tds_msg type;
    uint8_t status;
    uint16_t length;
    uint16_t spid;
    uint8_t packet_id;
    uint8_t window;
};

static_assert(sizeof(tds_header) == 8, "tds_header has wrong size");

enum class tds_login_opt_type : uint8_t {
    version = 0,
    encryption,
    instopt,
    threadid,
    mars,
    traceid,
    fedauthrequired,
    nonceopt,
    terminator = 0xff
};

struct login_opt {
    login_opt(enum tds_login_opt_type type, const string_view& payload) : type(type), payload(payload) { }

    enum tds_login_opt_type type;
    string payload;
};

struct login_opt_version {
    uint8_t major;
    uint8_t minor;
    uint16_t build;
    uint16_t subbuild;
};

static_assert(sizeof(login_opt_version) == 6, "login_opt_version has wrong size");

#pragma pack(push,1)

struct tds_login_opt {
    enum tds_login_opt_type type;
    uint16_t offset;
    uint16_t length;
};

#pragma pack(pop)

static_assert(sizeof(tds_login_opt) == 5, "tds_login_opt has wrong size");

enum class tds_encryption_type : uint8_t {
    ENCRYPT_OFF,
    ENCRYPT_ON,
    ENCRYPT_NOT_SUP,
    ENCRYPT_REQ
};

#pragma pack(push,1)

struct tds_login_msg {
    uint32_t length;
    uint32_t tds_version;
    uint32_t packet_size;
    uint32_t client_version;
    uint32_t client_pid;
    uint32_t connexion_id;
    uint8_t option_flags1;
    uint8_t option_flags2;
    uint8_t sql_type_flags;
    uint8_t option_flags3;
    int32_t timezone;
    uint32_t collation;
    uint16_t client_name_offset;
    uint16_t client_name_length;
    uint16_t username_offset;
    uint16_t username_length;
    uint16_t password_offset;
    uint16_t password_length;
    uint16_t app_name_offset;
    uint16_t app_name_length;
    uint16_t server_name_offset;
    uint16_t server_name_length;
    uint16_t unused_offset;
    uint16_t unused_length;
    uint16_t interface_library_offset;
    uint16_t interface_library_length;
    uint16_t locale_offset;
    uint16_t locale_length;
    uint16_t database_offset;
    uint16_t database_length;
    uint8_t mac_address[6];
    uint16_t sspi_offset;
    uint16_t sspi_length;
    uint16_t attach_db_offset;
    uint16_t attach_db_length;
    uint16_t new_password_offset;
    uint16_t new_password_length;
    uint16_t sspi_long_offset;
    uint16_t sspi_long_length;
};

#pragma pack(pop)

static_assert(sizeof(tds_login_msg) == 94, "tds_login_msg has wrong size");

enum class tds_token : uint8_t {
    OFFSET = 0x78,
    RETURNSTATUS = 0x79,
    COLMETADATA = 0x81,
    ALTMETADATA = 0x88,
    DATACLASSIFICATION = 0xa3,
    TABNAME = 0xa4,
    COLINFO = 0xa5,
    ORDER = 0xa9,
    ERROR = 0xaa,
    INFO = 0xab,
    RETURNVALUE = 0xac,
    LOGINACK = 0xad,
    FEATUREEXTACK = 0xae,
    ROW = 0xd1,
    NBCROW = 0xd2,
    ALTROW = 0xd3,
    ENVCHANGE = 0xe3,
    SESSIONSTATE = 0xe4,
    SSPI = 0xed,
    FEDAUTHINFO = 0xee,
    DONE = 0xfd,
    DONEPROC = 0xfe,
    DONEINPROC = 0xff
};

#pragma pack(push,1)

struct tds_done_msg {
    uint16_t status;
    uint16_t curcmd;
    uint64_t rowcount;
};

#pragma pack(pop)

static_assert(sizeof(tds_done_msg) == 12, "tds_done_msg has wrong size");

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

static u16string utf8_to_utf16(const string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.from_bytes(sv.data(), sv.data() + sv.length());
}

class tds {
public:
    tds(const string& server, uint16_t port, const string_view& user, const string_view& password) {
        connect(server, port);

        send_prelogin_msg();

        send_login_msg(user, password);
    }

    ~tds() {
        if (sock != 0)
            close(sock);
    }

private:
    void connect(const string& server, uint16_t port) {
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
        } while (res = res->ai_next);

        freeaddrinfo(orig_res);

        if (sock <= 0)
            throw formatted_error(FMT_STRING("Could not connect to {}:{}."), server, port);
    }

    void send_prelogin_msg() {
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
            tlo->offset = htons(off);
            tlo->length = htons(opt.payload.size());

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

    void send_login_msg(const string_view& user, const string_view& password) {
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

        parse_result_message(payload);
        // FIXME - parse
    }

    void send_login_msg2(uint32_t tds_version, uint32_t packet_size, uint32_t client_version, uint32_t client_pid,
                         uint32_t connexion_id, uint8_t option_flags1, uint8_t option_flags2, uint8_t sql_type_flags,
                         uint8_t option_flags3, uint32_t collation, const u16string_view& client_name,
                         const u16string_view& username, const u16string_view& password, const u16string_view& app_name,
                         const u16string_view& server_name, const u16string_view& interface_library,
                         const u16string_view& locale, const u16string_view& database, const u16string_view& attach_db,
                         const u16string_view& new_password) {
        uint32_t length, off;

        // FIXME - send features list (UTF-8 support etc.)

        length = sizeof(tds_login_msg);
        length += client_name.length() * sizeof(char16_t);
        length += username.length() * sizeof(char16_t);
        length += password.length() * sizeof(char16_t);
        length += app_name.length() * sizeof(char16_t);
        length += server_name.length() * sizeof(char16_t);
        length += interface_library.length() * sizeof(char16_t);
        length += locale.length() * sizeof(char16_t);
        length += database.length() * sizeof(char16_t);

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
            msg->client_name_length = client_name.length();
            memcpy((uint8_t*)msg + msg->client_name_offset, client_name.data(),
                   client_name.length() * sizeof(char16_t));

            off += client_name.length() * sizeof(char16_t);
        } else
            msg->client_name_length = 0;

        msg->username_offset = off;

        if (!username.empty()) {
            msg->username_length = username.length();
            memcpy((uint8_t*)msg + msg->username_offset, username.data(),
                   username.length() * sizeof(char16_t));

            off += username.length() * sizeof(char16_t);
        } else
            msg->username_length = 0;

        msg->password_offset = off;

        if (!password.empty()) {
            msg->password_length = password.length();

            auto pw_dest = (uint8_t*)msg + msg->password_offset;
            auto pw_src = (uint8_t*)password.data();

            for (unsigned int i = 0; i < password.length() * sizeof(char16_t); i++) {
                uint8_t c = *pw_src;

                c = ((c & 0xf) << 4) | (c >> 4);
                c ^= 0xa5;

                *pw_dest = c;

                pw_src++;
                pw_dest++;
            }

            off += password.length() * sizeof(char16_t);
        } else
            msg->password_length = 0;

        msg->app_name_offset = off;

        if (!app_name.empty()) {
            msg->app_name_length = app_name.length();
            memcpy((uint8_t*)msg + msg->app_name_offset, app_name.data(),
                   app_name.length() * sizeof(char16_t));

            off += app_name.length() * sizeof(char16_t);
        } else
            msg->app_name_length = 0;

        msg->server_name_offset = off;

        if (!server_name.empty()) {
            msg->server_name_length = server_name.length();
            memcpy((uint8_t*)msg + msg->server_name_offset, server_name.data(),
                   server_name.length() * sizeof(char16_t));

            off += server_name.length() * sizeof(char16_t);
        } else
            msg->server_name_length = 0;

        msg->unused_offset = 0;
        msg->unused_length = 0;

        msg->interface_library_offset = off;

        if (!interface_library.empty()) {
            msg->interface_library_length = interface_library.length();
            memcpy((uint8_t*)msg + msg->interface_library_offset, interface_library.data(),
                   interface_library.length() * sizeof(char16_t));

            off += interface_library.length() * sizeof(char16_t);
        } else
            msg->interface_library_length = 0;

        msg->locale_offset = off;

        if (!locale.empty()) {
            msg->locale_length = locale.length();
            memcpy((uint8_t*)msg + msg->locale_offset, locale.data(),
                   locale.length() * sizeof(char16_t));

            off += locale.length() * sizeof(char16_t);
        } else
            msg->locale_length = 0;

        msg->database_offset = off;

        if (!database.empty()) {
            msg->database_length = database.length();
            memcpy((uint8_t*)msg + msg->database_offset, database.data(),
                   database.length() * sizeof(char16_t));

            off += database.length() * sizeof(char16_t);
        } else
            msg->database_length = 0;

        // FIXME - set MAC address properly?
        memset(msg->mac_address, 0, 6);

        // FIXME - SSPI

        msg->sspi_offset = 0;
        msg->sspi_length = 0;

        msg->attach_db_offset = off;

        if (!attach_db.empty()) {
            msg->attach_db_length = attach_db.length();
            memcpy((uint8_t*)msg + msg->attach_db_offset, attach_db.data(),
                   attach_db.length() * sizeof(char16_t));

            off += attach_db.length() * sizeof(char16_t);
        } else
            msg->attach_db_length = 0;

        msg->new_password_offset = off;

        if (!new_password.empty()) {
            msg->new_password_length = new_password.length();
            memcpy((uint8_t*)msg + msg->new_password_offset, new_password.data(),
                   new_password.length() * sizeof(char16_t));

            off += new_password.length() * sizeof(char16_t);
        } else
            msg->new_password_length = 0;

        msg->sspi_long_offset = 0;
        msg->sspi_long_length = 0;

        send_msg(tds_msg::tds7_login, payload);
    }

    void send_msg(enum tds_msg type, const string_view& msg) {
        string payload;

        payload.resize(msg.length() + sizeof(tds_header));

        auto h = (tds_header*)payload.data();

        h->type = type;
        h->status = 1; // last message
        h->length = htons(msg.length() + sizeof(tds_header));
        h->spid = 0;
        h->packet_id = 0; // FIXME?
        h->window = 0;

        if (!msg.empty())
            memcpy(payload.data() + sizeof(tds_header), msg.data(), msg.size());

        auto ret = send(sock, payload.data(), payload.length(), 0);

        if (ret == -1)
            throw formatted_error(FMT_STRING("send failed (error {})"), errno);

        if (ret < payload.length())
            throw formatted_error(FMT_STRING("send sent {} bytes, expected {}"), ret, payload.length());
    }

    void wait_for_msg(enum tds_msg& type, string& payload) {
        tds_header h;

        auto ret = recv(sock, &h, sizeof(tds_header), MSG_WAITALL);

        if (ret == -1)
            throw formatted_error(FMT_STRING("recv failed (error {})"), errno);

        if (ret == 0)
            throw formatted_error(FMT_STRING("Disconnected."));

        if (ret < sizeof(h))
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

            if (ret == -1)
                throw formatted_error(FMT_STRING("recv failed (error {})"), errno);

            if (ret == 0)
                throw formatted_error(FMT_STRING("Disconnected."));

            if (ret < len)
                throw formatted_error(FMT_STRING("recv received {} bytes, expected {}"), ret, len);
        } else
            payload.clear();
    }

    void parse_result_message(string_view sv) {
        tds_token type;

        while (!sv.empty()) {
            type = (tds_token)sv[0];
            sv = sv.substr(1);

            if (sv.length() < sizeof(uint16_t))
                throw formatted_error(FMT_STRING("Short message ({} bytes, expected at least 2)."), sv.length());

            switch (type) {
                case tds_token::DONE:
                    if (sv.length() < sizeof(tds_done_msg))
                        throw formatted_error(FMT_STRING("Short DONE message ({} bytes, expected {})."), sv.length(), sizeof(tds_done_msg));

                    msgs.emplace_back(type, sv.substr(0, sizeof(tds_done_msg)));

                    sv = sv.substr(sizeof(tds_done_msg));
                break;

                case tds_token::LOGINACK:
                case tds_token::INFO:
                case tds_token::ENVCHANGE:
                {
                    auto len = *(uint16_t*)&sv[0];

                    sv = sv.substr(sizeof(uint16_t));

                    if (sv.length() < len)
                        throw formatted_error(FMT_STRING("Short message ({} bytes, expected {})."), sv.length(), len);

                    msgs.emplace_back(type, sv.substr(0, len));

                    sv = sv.substr(len);

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {}."), type);
            }
        }
    }

    int sock = 0;
    vector<pair<tds_token, string>> msgs;
};

int main() {
    try {
        tds n(db_server, db_port, db_user, db_password);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
