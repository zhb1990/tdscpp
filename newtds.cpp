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

static_assert(sizeof(tds_done_msg) == 12, "tds_done_msg has wrong size");

struct tds_header_trans_desc {
    uint16_t type;
    uint64_t descriptor;
    uint32_t outstanding;
};

static_assert(sizeof(tds_header_trans_desc) == 14, "tds_header_trans_desc has wrong size");

struct tds_all_headers {
    uint32_t total_size;
    uint32_t size;
    tds_header_trans_desc trans_desc;
};

static_assert(sizeof(tds_all_headers) == 22, "tds_all_headers has wrong size");

struct tds_rpc_batch {
    tds_all_headers all_headers;
    uint16_t proc_id_switch;
    uint16_t proc_id;
    uint16_t flags;
};

static_assert(sizeof(tds_rpc_batch) == 28, "tds_rpc_batch has wrong size");

enum class tds_sql_type : uint8_t {
    SQL_NULL = 0x1F,
    IMAGE = 0x22,
    TEXT = 0x23,
    UNIQUEIDENTIFIER = 0x24,
    INTN = 0x26,
    DATEN = 0x28,
    TIMEN = 0x29,
    DATETIME2N = 0x2A,
    DATETIMEOFFSETN = 0x2B,
    TINYINT = 0x30,
    BIT = 0x32,
    SMALLINT = 0x34,
    INT = 0x38,
    SMALLDATETIME = 0x3A,
    REAL = 0x3B,
    MONEY = 0x3C,
    DATETIME = 0x3D,
    FLOAT = 0x3E,
    SQL_VARIANT = 0x62,
    NTEXT = 0x63,
    BITN = 0x68,
    DECIMAL = 0x6A,
    NUMERIC = 0x6C,
    FLTN = 0x6D,
    MONEYN = 0x6E,
    DATETIMN = 0x6F,
    SMALLMONEY = 0x7A,
    BIGINT = 0x7F,
    VARBINARY = 0xA5,
    VARCHAR = 0xA7,
    BINARY = 0xAD,
    CHAR = 0xAF,
    NVARCHAR = 0xE7,
    NCHAR = 0xEF,
    UDT = 0xF0,
    XML = 0xF1,
};

struct tds_param_header {
    uint8_t name_len;
    uint8_t flags;
    tds_sql_type type;
};

struct tds_INT_param {
    tds_param_header h;
    uint8_t max_length;
    uint8_t length;
};

static_assert(sizeof(tds_INT_param) == 5, "tds_INT_param has wrong size");

struct tds_collation {
    uint32_t lcid : 20;
    uint32_t ignore_case : 1;
    uint32_t ignore_accent : 1;
    uint32_t ignore_width : 1;
    uint32_t ignore_kana : 1;
    uint32_t binary : 1;
    uint32_t binary2 : 1;
    uint32_t utf8 : 1;
    uint32_t reserved : 1;
    uint32_t version : 4;
    uint8_t sort_id;
};

static_assert(sizeof(tds_collation) == 5, "tds_collation has wrong size");

struct tds_VARCHAR_param {
    tds_param_header h;
    uint16_t max_length;
    tds_collation collation;
    uint16_t length;
};

static_assert(sizeof(tds_VARCHAR_param) == 12, "tds_VARCHAR_param has wrong size");

struct tds_return_value {
    uint16_t param_ordinal;
    uint8_t param_name_len;
    // FIXME - then param name if present
    uint8_t status;
    uint32_t user_type;
    uint16_t flags;
    tds_sql_type type;
};

static_assert(sizeof(tds_return_value) == 11, "tds_return_value has wrong size");

struct tds_colmetadata_col {
    uint32_t user_type;
    uint16_t flags;
    tds_sql_type type;
};

static_assert(sizeof(tds_colmetadata_col) == 7, "tds_colmetadata_col has wrong size");

#pragma pack(pop)

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

            case tds_sql_type::SMALLDATETIME:
                return format_to(ctx.out(), "SMALLDATETIME");

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

using msg_handler = function<void(const string_view& server, const string_view& message, const string_view& proc_name,
                                  const string_view& sql_state, int32_t msgno, int32_t line_number, int16_t state, uint8_t priv_msg_type,
                                  uint8_t severity, int oserr, bool error)>;

// FIXME - use pimpl
class tds {
public:
    tds(const string& server, uint16_t port, const string_view& user, const string_view& password,
        const msg_handler& message_handler = nullptr) : message_handler(message_handler) {
        connect(server, port);

        send_prelogin_msg();

        send_login_msg(user, password);
    }

    ~tds() {
        if (sock != 0)
            close(sock);
    }

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

    void send_msg(enum tds_msg type, const span<uint8_t>& msg) {
        send_msg(type, string_view{(const char*)msg.data(), (const char*)msg.data() + msg.size()});
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

    void handle_loginack_msg(string_view sv) {
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

    void handle_info_msg(const string_view& sv, bool error) {
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

    int sock = 0;
    list<pair<tds_token, string>> msgs;
    msg_handler message_handler;
};

class tds_param {
public:
    tds_param() {
        type = tds_sql_type::SQL_NULL;
    }

    tds_param(int32_t i) {
        init(i, false);
    }

    tds_param(const optional<int32_t>& i) {
        init(i.has_value() ? i.value() : 0, !i.has_value());
    }

    tds_param(const u16string_view& sv) {
        init(sv, false);
    }

//     tds_param(const optional<u16string_view>& sv) {
//         init(sv.has_value() ? sv.value() : u"", !sv.has_value());
//     }

    void init(int32_t i, bool null) {
        type = tds_sql_type::INTN;

        val.resize(sizeof(int32_t));

        if (!null)
            *(int32_t*)val.data() = i;
        else
            is_null = true;
    }

    void init(const u16string_view& sv, bool null) {
        type = tds_sql_type::NVARCHAR;

        if (null)
            is_null = true;
        else {
            val.resize(sv.length() * sizeof(char16_t));
            memcpy(val.data(), sv.data(), val.length());
        }
    }

    enum tds_sql_type type;
    string val;
    bool is_null = false;
    bool is_output = false;
};

class tds_column : public tds_param {
public:
    u16string name;
    unsigned int max_length;
};

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
                }
            break;

            case tds_sql_type::NVARCHAR: {
                u16string_view sv((char16_t*)p.val.data(), p.val.length() / sizeof(char16_t));
                auto s = utf16_to_utf8(sv);

                return format_to(ctx.out(), "{}", s);
            }

            case tds_sql_type::VARCHAR: {
                string_view sv(p.val.data(), p.val.length());

                return format_to(ctx.out(), "{}", sv);
            }
        }

        throw formatted_error(FMT_STRING("Unable to format type {} as string."), p.type);
    }
};

template<typename T>
class tds_output_param : public tds_param {
public:
    tds_output_param() : tds_param(optional<T>(nullopt)) {
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

static bool is_fixed_len_type(enum tds_sql_type type) {
    switch (type) {
        case tds_sql_type::SQL_NULL:
        case tds_sql_type::TINYINT:
        case tds_sql_type::BIT:
        case tds_sql_type::SMALLINT:
        case tds_sql_type::INT:
        case tds_sql_type::SMALLDATETIME:
        case tds_sql_type::REAL:
        case tds_sql_type::MONEY:
        case tds_sql_type::DATETIME:
        case tds_sql_type::FLOAT:
        case tds_sql_type::SMALLMONEY:
        case tds_sql_type::BIGINT:
            return true;

        default:
            return false;
    }
}

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

        case tds_sql_type::SQL_NULL:
        case tds_sql_type::BIT:
        case tds_sql_type::SMALLDATETIME:
        case tds_sql_type::REAL:
        case tds_sql_type::MONEY:
        case tds_sql_type::DATETIME:
        case tds_sql_type::FLOAT:
        case tds_sql_type::SMALLMONEY:
            throw formatted_error(FMT_STRING("FIXME - fixed_len_size for {}"), type); // FIXME

        default:
            return 0;
    }
}

class rpc {
public:
    template<typename... Args>
    rpc(tds& conn, const u16string_view& name, Args&&... args) {
        params.reserve(sizeof...(args));

        add_param(args...);

        do_rpc(conn, name);
    }

    rpc(tds& conn, const u16string_view& name) {
        do_rpc(conn, name);
    }

    void do_rpc(tds& conn, const u16string_view& name) {
        size_t bufsize;

        bufsize = sizeof(tds_all_headers) + sizeof(uint16_t) + (name.length() * sizeof(uint16_t)) + sizeof(uint16_t);

        for (const auto& p : params) {
            if (is_fixed_len_type(p.type))
                bufsize += sizeof(tds_param_header) + fixed_len_size(p.type);
            else if (is_byte_len_type(p.type))
                bufsize += sizeof(tds_param_header) + sizeof(uint8_t) + sizeof(uint8_t) + (p.is_null ? 0 : p.val.length());
            else if (p.type == tds_sql_type::NVARCHAR)
                bufsize += sizeof(tds_VARCHAR_param) + (p.is_null ? 0 : p.val.length());
            else
                throw formatted_error(FMT_STRING("Unhandled type {} in RPC params."), p.type);
        }

        vector<uint8_t> buf(bufsize);

        auto all_headers = (tds_all_headers*)&buf[0];

        all_headers->total_size = sizeof(tds_all_headers);
        all_headers->size = sizeof(uint32_t) + sizeof(tds_header_trans_desc);
        all_headers->trans_desc.type = 2; // transaction descriptor
        all_headers->trans_desc.descriptor = 0;
        all_headers->trans_desc.outstanding = 1;

        auto ptr = (uint8_t*)&all_headers[1];

        *(uint16_t*)ptr = name.length();
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

            if (is_fixed_len_type(p.type)) {
                memcpy(ptr, p.val.data(), p.val.length());

                ptr += p.val.length();
            } else if (is_byte_len_type(p.type)) {
                *ptr = p.val.length(); ptr++;

                if (p.is_null) {
                    *ptr = 0;
                    ptr++;
                } else {
                    *ptr = p.val.length(); ptr++;
                    memcpy(ptr, p.val.data(), p.val.length());
                    ptr += p.val.length();
                }
            } else if (p.type == tds_sql_type::NVARCHAR) { // FIXME - MAX
                auto h2 = (tds_VARCHAR_param*)h;

                h2->max_length = p.is_null ? sizeof(char16_t) : p.val.length();
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
                h2->length = p.is_null ? 0 : p.val.length();

                if (h2->max_length == 0)
                    h2->max_length = sizeof(char16_t);

                ptr += sizeof(tds_VARCHAR_param) - sizeof(tds_param_header);

                if (!p.is_null) {
                    memcpy(ptr, p.val.data(), h2->length);
                    ptr += h2->length;
                }
            } else
                throw formatted_error(FMT_STRING("Unhandled type {} in RPC params."), p.type);
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
        vector<tds_column> cols;

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

                    // FIXME - actually parse

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

                        if (is_fixed_len_type(c.type)) {
                            // nop
                        } else if (is_byte_len_type(c.type)) {
                            if (sv2.length() < sizeof(uint8_t))
                                throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                            col.max_length = *(uint8_t*)sv2.data();

                            len++;
                            sv2 = sv2.substr(1);
                        } else if (c.type == tds_sql_type::VARCHAR || c.type == tds_sql_type::NVARCHAR) {
                            // FIXME - handle MAX

                            if (sv2.length() < sizeof(uint16_t) + sizeof(tds_collation))
                                throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), sizeof(uint16_t) + sizeof(tds_collation));

                            len += sizeof(uint16_t) + sizeof(tds_collation);
                            sv2 = sv2.substr(sizeof(uint16_t) + sizeof(tds_collation));
                        } else
                            throw formatted_error(FMT_STRING("Unhandled type {} in COLMETADATA message."), c.type);

                        if (sv2.length() < 1)
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least 1)."), sv2.length());

                        auto name_len = *(uint8_t*)&sv2[0];

                        sv2 = sv2.substr(1);
                        len++;

                        if (sv2.length() < name_len * sizeof(char16_t))
                            throw formatted_error(FMT_STRING("Short COLMETADATA message ({} bytes left, expected at least {})."), sv2.length(), name_len * sizeof(char16_t));

                        col.name = u16string((char16_t*)sv2.data(), name_len);

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
                    for (auto& col : cols) {
                        handle_row_col(col, sv);
                    }

                    break;
                }

                case tds_token::NBCROW:
                {
                    if (cols.empty())
                        break;

                    unsigned int bitset_length = (cols.size() + 7) / 8;

                    if (sv.length() < bitset_length)
                        throw formatted_error(FMT_STRING("Short NBCROW message ({} bytes, expected at least {})."), sv.length(), bitset_length);

                    string_view bitset(sv.data(), bitset_length);
                    auto bsv = (uint8_t)bitset[0];

                    sv = sv.substr(bitset_length);

                    for (unsigned int i = 0; i < cols.size(); i++) {
                        auto& col = cols[i];

                        if (i != 0) {
                            if (i & 7 == 0) {
                                bitset = bitset.substr(1);
                                bsv = bitset[0];
                            } else
                                bsv >>= 1;
                        }

                        if (bsv & 1) // NULL
                            col.is_null = true;
                        else
                            handle_row_col(col, sv);
                    }

                    break;
                }

                default:
                    throw formatted_error(FMT_STRING("Unhandled token type {} while executing RPC."), type);
            }
        }
    }

    void handle_row_col(tds_column& col, string_view& sv) {
        if (is_fixed_len_type(col.type)) {
            auto len = fixed_len_size(col.type);

            col.val.resize(len);

            if (sv.length() < len)
                throw formatted_error(FMT_STRING("Short ROW message ({} bytes left, expected at least {})."), sv.length(), len);

            memcpy(col.val.data(), sv.data(), len);

            sv = sv.substr(len);
        } else if (is_byte_len_type(col.type)) {
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
        } else if (col.type == tds_sql_type::VARCHAR || col.type == tds_sql_type::NVARCHAR) {
            // FIXME - handle MAX

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
        } else
            throw formatted_error(FMT_STRING("Unhandled type {} in ROW message."), col.type);
    }

    template<typename T, typename... Args>
    void add_param(T&& t, Args&&... args) {
        add_param(t);
        add_param(args...);
    }

    template<typename T>
    void add_param(T&& t) {
        params.emplace_back(t);
    }

    template<typename T>
    void add_param(tds_output_param<T>& t) {
        params.emplace_back(static_cast<tds_param>(t));
        params.back().is_output = true;

        output_params[params.size() - 1] = static_cast<tds_param*>(&t);
    }

    int32_t return_status = 0;
    vector<tds_param> params;
    map<unsigned int, tds_param*> output_params;
};

class query {
public:
    query(tds& conn, const string_view& q) {
        tds_output_param<int32_t> handle;

        // FIXME - allow parameters

        rpc(conn, u"sp_prepare", handle, u"", utf8_to_utf16(q), 1); // 1 means return metadata

#ifdef DEBUG_SHOW_MSGS
        fmt::print("sp_prepare handle is {}.\n", handle);
#endif

        rpc(conn, u"sp_execute", static_cast<tds_param>(handle));

        // FIXME - sp_unprepare (is this necessary?)
    }
};

static void show_msg(const string_view& server, const string_view& message, const string_view& proc_name,
                     const string_view& sql_state, int32_t msgno, int32_t line_number, int16_t state, uint8_t priv_msg_type,
                     uint8_t severity, int oserr, bool error) {
    if (severity > 10)
        fmt::print("\x1b[31;1mError {}: {}\x1b[0m\n", msgno, message);
    else if (msgno == 50000) // match SSMS by not displaying message no. if 50000 (RAISERROR etc.)
        fmt::print("{}\n", message);
    else
        fmt::print("{}: {}\n", msgno, message);
}

int main() {
    try {
        tds n(db_server, db_port, db_user, db_password, show_msg);

//         query sq(n, "SELECT SYSTEM_USER AS [user], ? AS answer, ? AS greeting, GETDATE() AS now, ? AS pi", 42, "Hello"s, 3.1415926f);
        query sq(n, "SELECT SYSTEM_USER AS [user]");

        // FIXME
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
