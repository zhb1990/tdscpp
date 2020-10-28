#pragma once

#include <fmt/format.h>
#include <string>
#include <span>
#include <list>
#include <functional>
#include <optional>
#include <vector>
#include <map>

class formatted_error : public std::exception {
public:
    template<typename T, typename... Args>
    formatted_error(const T& s, Args&&... args) {
        msg = fmt::format(s, forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
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
    login_opt(enum tds_login_opt_type type, const std::string_view& payload) : type(type), payload(payload) { }

    enum tds_login_opt_type type;
    std::string payload;
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
    DATETIM4 = 0x3A,
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

struct tds_VARCHAR_MAX_param {
    tds_param_header h;
    uint16_t max_length;
    tds_collation collation;
    uint64_t length;
    uint32_t chunk_length;
};

static_assert(sizeof(tds_VARCHAR_MAX_param) == 22, "tds_VARCHAR_MAX_param has wrong size");

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

using msg_handler = std::function<void(const std::string_view& server, const std::string_view& message, const std::string_view& proc_name,
                                       const std::string_view& sql_state, int32_t msgno, int32_t line_number, int16_t state, uint8_t priv_msg_type,
                                       uint8_t severity, int oserr, bool error)>;

// FIXME - use pimpl
class tds {
public:
    tds(const std::string& server, uint16_t port, const std::string_view& user, const std::string_view& password,
        const msg_handler& message_handler = nullptr);
    ~tds();
    void connect(const std::string& server, uint16_t port);
    void send_prelogin_msg();
    void send_login_msg(const std::string_view& user, const std::string_view& password);
    void send_login_msg2(uint32_t tds_version, uint32_t packet_size, uint32_t client_version, uint32_t client_pid,
                         uint32_t connexion_id, uint8_t option_flags1, uint8_t option_flags2, uint8_t sql_type_flags,
                         uint8_t option_flags3, uint32_t collation, const std::u16string_view& client_name,
                         const std::u16string_view& username, const std::u16string_view& password, const std::u16string_view& app_name,
                         const std::u16string_view& server_name, const std::u16string_view& interface_library,
                         const std::u16string_view& locale, const std::u16string_view& database, const std::u16string_view& attach_db,
                         const std::u16string_view& new_password);
    void send_msg(enum tds_msg type, const std::string_view& msg);
    void send_msg(enum tds_msg type, const std::span<uint8_t>& msg);
    void wait_for_msg(enum tds_msg& type, std::string& payload);
    void handle_loginack_msg(std::string_view sv);
    void handle_info_msg(const std::string_view& sv, bool error);

    int sock = 0;
    std::list<std::pair<tds_token, std::string>> msgs;
    msg_handler message_handler;
};

class tds_date {
public:
    tds_date(int32_t num);
    tds_date(uint16_t year, uint8_t month, uint8_t day);

    int32_t num;
    uint16_t year;
    uint8_t month, day;
};

class tds_time {
public:
    tds_time(uint8_t hour, uint8_t minute, uint8_t second) : hour(hour), minute(minute), second(second) { }
    tds_time(uint32_t secs) : hour(secs / 3600), minute((secs / 60) % 60), second(secs % 60) { }

    uint8_t hour, minute, second;
};

class tds_datetime {
public:
    tds_datetime(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) :
        date(year, month, day), time(hour, minute, second) { }
    tds_datetime(int32_t num, uint32_t secs) : date(num), time(secs) { }

    tds_date date;
    tds_time time;
};

class tds_datetimeoffset : public tds_datetime {
public:
    tds_datetimeoffset(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, int16_t offset) :
        tds_datetime(year, month, day, hour, minute, second), offset(offset) { }
    tds_datetimeoffset(int32_t num, uint32_t secs, int16_t offset) : tds_datetime(num, secs), offset(offset) { }

    int16_t offset;
};

class tds_param {
public:
    tds_param();
    tds_param(int32_t i);
    tds_param(const std::optional<int32_t>& i);
    tds_param(const std::u16string_view& sv);
    tds_param(const std::u16string& sv);
    tds_param(const char16_t* sv);
    tds_param(const std::optional<std::u16string_view>& sv);
    tds_param(const std::string_view& sv);
    tds_param(const std::string& sv);
    tds_param(const char* sv);
    tds_param(const std::optional<std::string_view>& sv);
    tds_param(const std::u8string_view& sv);
    tds_param(const std::u8string& sv);
    tds_param(const char8_t* sv);
    tds_param(const std::optional<std::u8string_view>& sv);
    tds_param(float f);
    tds_param(const std::optional<float>& f);
    tds_param(double d);
    tds_param(const std::optional<double>& d);
    tds_param(const tds_date& d);
    tds_param(const std::optional<tds_date>& d);
    tds_param(const tds_time& t);
    tds_param(const std::optional<tds_time>& t);
    tds_param(const tds_datetime& dt);
    tds_param(const std::optional<tds_datetime>& t);
    tds_param(const tds_datetimeoffset& dt);
    tds_param(const std::optional<tds_datetimeoffset>& t);

    enum tds_sql_type type;
    std::string val;
    bool is_null = false;
    bool is_output = false;
    unsigned int max_length = 0;
};

class tds_column : public tds_param {
public:
    std::string name;
};


template<typename T>
class tds_output_param : public tds_param {
public:
    tds_output_param() : tds_param(std::optional<T>(std::nullopt)) {
    }
};

class rpc {
public:
    template<typename... Args>
    rpc(tds& conn, const std::u16string_view& name, Args&&... args) {
        params.reserve(sizeof...(args));

        add_param(args...);

        do_rpc(conn, name);
    }

    rpc(tds& conn, const std::u16string_view& name) {
        do_rpc(conn, name);
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

    bool fetch_row();

    int32_t return_status = 0;
    std::vector<tds_column> cols;

private:
    void do_rpc(tds& conn, const std::u16string_view& name);
    void handle_row_col(tds_param& col, enum tds_sql_type type, std::string_view& sv);

    std::vector<tds_param> params;
    std::map<unsigned int, tds_param*> output_params;
    bool finished = false;
    std::list<std::vector<tds_param>> rows;
};

class query {
public:
    query(tds& conn, const std::string_view& q);

    template<typename... Args>
    query(tds& conn, const std::string_view& q, Args&&... args);

    uint16_t num_columns() const;

    const tds_column& operator[](unsigned int i) const;

    bool fetch_row();

private:
    template<typename T, typename... Args>
    std::string create_params_string(unsigned int num, T&& t, Args&&... args);

    template<typename T>
    std::string create_params_string(unsigned int num, T&& t);

    std::vector<tds_column> cols;
    std::unique_ptr<rpc> r2;
};
