#pragma once

#include <string>
#include <span>
#include <list>
#include <functional>
#include <optional>
#include <vector>
#include <map>

namespace tds {
    enum class sql_type : uint8_t {
        SQL_NULL = 0x1F,
        IMAGE = 0x22,
        TEXT = 0x23,
        UNIQUEIDENTIFIER = 0x24,
        INTN = 0x26,
        DATE = 0x28,
        TIME = 0x29,
        DATETIME2 = 0x2A,
        DATETIMEOFFSET = 0x2B,
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

    using msg_handler = std::function<void(const std::string_view& server, const std::string_view& message, const std::string_view& proc_name,
                                        int32_t msgno, int32_t line_number, int16_t state, uint8_t severity, bool error)>;

    // FIXME - use pimpl
    class tds {
    public:
        tds(const std::string& server, uint16_t port, const std::string_view& user, const std::string_view& password,
            const msg_handler& message_handler = nullptr);
        ~tds();
        void send_msg(enum tds_msg type, const std::string_view& msg);
        void send_msg(enum tds_msg type, const std::span<uint8_t>& msg);
        void wait_for_msg(enum tds_msg& type, std::string& payload);
        void handle_info_msg(const std::string_view& sv, bool error);

        msg_handler message_handler;

    private:
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
        void handle_loginack_msg(std::string_view sv);

        int sock = 0;
    };

    class date {
    public:
        date(int32_t num);
        date(uint16_t year, uint8_t month, uint8_t day);

        int32_t num;
        uint16_t year;
        uint8_t month, day;
    };

    class time {
    public:
        time(uint8_t hour, uint8_t minute, uint8_t second) : hour(hour), minute(minute), second(second) { }
        time(uint32_t secs) : hour((uint8_t)(secs / 3600)), minute((uint8_t)((secs / 60) % 60)), second((uint8_t)(secs % 60)) { }

        uint8_t hour, minute, second;
    };

    class datetime {
    public:
        datetime(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) :
            d(year, month, day), t(hour, minute, second) { }
        datetime(int32_t num, uint32_t secs) : d(num), t(secs) { }

        date d;
        time t;
    };

    class datetimeoffset : public datetime {
    public:
        datetimeoffset(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, int16_t offset) :
            datetime(year, month, day, hour, minute, second), offset(offset) { }
        datetimeoffset(int32_t num, uint32_t secs, int16_t offset) : datetime(num, secs), offset(offset) { }

        int16_t offset;
    };

    class value {
    public:
        // make sure pointers don't get interpreted as bools
        template<typename T>
        value(T*) = delete;

        value();
        value(int32_t i);
        value(const std::optional<int32_t>& i);
        value(const std::u16string_view& sv);
        value(const std::u16string& sv);
        value(const char16_t* sv);
        value(const std::optional<std::u16string_view>& sv);
        value(const std::string_view& sv);
        value(const std::string& sv);
        value(const char* sv);
        value(const std::optional<std::string_view>& sv);
        value(const std::u8string_view& sv);
        value(const std::u8string& sv);
        value(const char8_t* sv);
        value(const std::optional<std::u8string_view>& sv);
        value(float f);
        value(const std::optional<float>& f);
        value(double d);
        value(const std::optional<double>& d);
        value(const date& d);
        value(const std::optional<date>& d);
        value(const time& t);
        value(const std::optional<time>& t);
        value(const datetime& dt);
        value(const std::optional<datetime>& t);
        value(const datetimeoffset& dt);
        value(const std::optional<datetimeoffset>& t);
        value(const std::span<std::byte>& bin);
        value(bool b);
        value(const std::optional<bool>& b);

        operator std::string() const;
        operator std::u16string() const;
        operator int64_t() const;
        operator double() const;
        operator date() const;
        operator time() const;
        operator datetime() const;

        enum sql_type type;
        std::string val;
        bool is_null = false;
        bool is_output = false;
        unsigned int max_length = 0;
    };

    class column : public value {
    public:
        std::string name;

        operator std::string() const {
            return (std::string)static_cast<value>(*this);
        }

        operator std::u16string() const {
            return (std::u16string)static_cast<value>(*this);
        }

        operator int64_t() const {
            return (int64_t)static_cast<value>(*this);
        }

        operator double() const {
            return (double)static_cast<value>(*this);
        }

        operator date() const {
            return (date)static_cast<value>(*this);
        }

        operator time() const {
            return (time)static_cast<value>(*this);
        }

        operator datetime() const {
            return (datetime)static_cast<value>(*this);
        }
    };


    template<typename T>
    class output_param : public value {
    public:
        output_param() : value(std::optional<T>(std::nullopt)) {
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

        bool fetch_row();

        int32_t return_status = 0;
        std::vector<column> cols;

    private:
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
        void add_param(output_param<T>& t) {
            params.emplace_back(static_cast<value>(t));
            params.back().is_output = true;

            output_params[(unsigned int)(params.size() - 1)] = static_cast<value*>(&t);
        }

        void do_rpc(tds& conn, const std::u16string_view& name);
        void handle_row_col(value& col, enum sql_type type, unsigned int max_length, std::string_view& sv);

        std::vector<value> params;
        std::map<unsigned int, value*> output_params;
        bool finished = false;
        std::list<std::vector<value>> rows;
    };

    class query {
    public:
        query(tds& conn, const std::string_view& q);

        template<typename... Args>
        query(tds& conn, const std::string_view& q, Args&&... args);

        uint16_t num_columns() const;

        const column& operator[](uint16_t i) const;

        bool fetch_row();

    private:
        template<typename T, typename... Args>
        std::string create_params_string(unsigned int num, T&& t, Args&&... args);

        template<typename T>
        std::string create_params_string(unsigned int num, T&& t);

        std::vector<column> cols;
        std::unique_ptr<rpc> r2;
    };
};
