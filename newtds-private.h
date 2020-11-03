#pragma once

#include <fmt/format.h>
#include <string>
#include <stdint.h>

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

namespace tds {
    enum class sql_type : uint8_t;
}

struct tds_param_header {
    uint8_t name_len;
    uint8_t flags;
    tds::sql_type type;
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

struct tds_VARBINARY_param {
    tds_param_header h;
    uint16_t max_length;
    uint16_t length;
};

static_assert(sizeof(tds_VARBINARY_param) == 7, "tds_VARBINARY_param has wrong size");

struct tds_VARBINARY_MAX_param {
    tds_param_header h;
    uint16_t max_length;
    uint64_t length;
    uint32_t chunk_length;
};

static_assert(sizeof(tds_VARBINARY_MAX_param) == 17, "tds_VARBINARY_MAX_param has wrong size");

struct tds_return_value {
    uint16_t param_ordinal;
    uint8_t param_name_len;
    // FIXME - then param name if present
    uint8_t status;
    uint32_t user_type;
    uint16_t flags;
    tds::sql_type type;
};

static_assert(sizeof(tds_return_value) == 11, "tds_return_value has wrong size");

struct tds_colmetadata_col {
    uint32_t user_type;
    uint16_t flags;
    tds::sql_type type;
};

static_assert(sizeof(tds_colmetadata_col) == 7, "tds_colmetadata_col has wrong size");

enum class tds_tm_type : uint16_t {
    TM_GET_DTC_ADDRESS = 0,
    TM_PROPAGATE_XACT = 1,
    TM_BEGIN_XACT = 5,
    TM_PROMOTE_XACT = 6,
    TM_COMMIT_XACT = 7,
    TM_ROLLBACK_XACT = 8,
    TM_SAVE_XACT = 9
};

struct tds_tm_msg {
    tds_all_headers all_headers;
    enum tds_tm_type type;
};

static_assert(sizeof(tds_tm_msg) == 24, "tds_tm_msg has wrong size");

struct tds_tm_begin {
    tds_tm_msg header;
    uint8_t isolation_level;
    uint8_t name_len;
};

static_assert(sizeof(tds_tm_begin) == 26, "tds_tm_begin has wrong size");

struct tds_tm_rollback {
    tds_tm_msg header;
    uint8_t name_len;
    uint8_t flags;
};

static_assert(sizeof(tds_tm_rollback) == 26, "tds_tm_rollback has wrong size");

struct tds_tm_commit {
    tds_tm_msg header;
    uint8_t name_len;
    uint8_t flags;
};

static_assert(sizeof(tds_tm_commit) == 26, "tds_tm_commit has wrong size");

enum class tds_envchange_type : uint8_t {
    database = 1,
    language,
    charset,
    packet_size,
    unicode_data_sort_local_id,
    unicode_data_sort_comparison_flags,
    collation,
    begin_trans,
    commit_trans,
    rollback_trans,
    enlist_dist_trans,
    defect_trans,
    log_shipping,
    promote_trans = 15,
    trans_man_address,
    trans_ended,
    reset_completion_acknowledgement,
    user_instance_started,
    routing
};

struct tds_envchange {
    enum tds_token token;
    uint16_t length;
    enum tds_envchange_type type;
};

static_assert(sizeof(tds_envchange) == 4, "tds_envchange has wrong size");

struct tds_envchange_begin_trans {
    struct tds_envchange header;
    uint8_t new_len;
    uint64_t trans_id;
    uint8_t old_len;
};

static_assert(sizeof(tds_envchange_begin_trans) == 14, "tds_envchange_begin_trans has wrong size");

struct tds_envchange_rollback_trans {
    struct tds_envchange header;
    uint8_t new_len;
    uint8_t old_len;
    uint64_t trans_id;
};

static_assert(sizeof(tds_envchange_rollback_trans) == 14, "tds_envchange_rollback_trans has wrong size");

struct tds_envchange_commit_trans {
    struct tds_envchange header;
    uint8_t new_len;
    uint8_t old_len;
    uint64_t trans_id;
};

static_assert(sizeof(tds_envchange_commit_trans) == 14, "tds_envchange_commit_trans has wrong size");

#pragma pack(pop)
