#pragma once

#include <fmt/format.h>
#include <string>
#include <list>
#include <functional>
#include <optional>
#include <vector>
#include <map>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

#ifdef _WIN32

#ifdef TDSCPP_EXPORT
#define TDSCPP __declspec(dllexport)
#elif !defined(TDSCPP_STATIC)
#define TDSCPP __declspec(dllimport)
#else
#define TDSCPP
#endif

#else

#ifdef TDSCPP_EXPORT
#define TDSCPP __attribute__ ((visibility ("default")))
#elif !defined(TDSCPP_STATIC)
#define TDSCPP __attribute__ ((dllimport))
#else
#define TDSCPP
#endif

#endif

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
    using func_count_handler = std::function<void(uint64_t count, uint16_t curcmd)>;

    class value;
    class tds_impl;

    class TDSCPP tds {
    public:
        tds(const std::string& server, const std::string_view& user, const std::string_view& password,
            const std::string_view& app_name = "tdscpp", const msg_handler& message_handler = nullptr,
            const func_count_handler& count_handler = nullptr, uint16_t port = 1433);
        ~tds();

        template<typename... Args>
        void run(const std::string_view& s, Args&&... args);

        template<typename... Args>
        void run(const std::u16string_view& s, Args&&... args);

        void bcp(const std::u16string_view& table, const std::vector<std::u16string>& np, const std::vector<std::vector<value>>& vp);

        tds_impl* impl;
    };

    class TDSCPP date {
    public:
        date(int32_t num);
        date(uint16_t year, uint8_t month, uint8_t day);

        int32_t num;
        uint16_t year;
        uint8_t month, day;
    };

    class TDSCPP time {
    public:
        time(uint8_t hour, uint8_t minute, uint8_t second) : hour(hour), minute(minute), second(second) { }
        time(uint32_t secs) : hour((uint8_t)(secs / 3600)), minute((uint8_t)((secs / 60) % 60)), second((uint8_t)(secs % 60)) { }

        uint8_t hour, minute, second;
    };

    class TDSCPP datetime {
    public:
        datetime(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) :
            d(year, month, day), t(hour, minute, second) { }
        datetime(int32_t num, uint32_t secs) : d(num), t(secs) { }

        date d;
        time t;
    };

    class TDSCPP datetimeoffset : public datetime {
    public:
        datetimeoffset(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, int16_t offset) :
            datetime(year, month, day, hour, minute, second), offset(offset) { }
        datetimeoffset(int32_t num, uint32_t secs, int16_t offset) : datetime(num, secs), offset(offset) { }

        int16_t offset;
    };

    class TDSCPP value {
    public:
        // make sure pointers don't get interpreted as bools
        template<typename T>
        value(T*) = delete;

        value();
        value(std::nullptr_t);
        value(int32_t i);
        value(const std::optional<int32_t>& i);
        value(int64_t i);
        value(const std::optional<int64_t>& i);
        value(uint32_t i);
        value(const std::optional<uint32_t>& i);
        value(const std::u16string_view& sv);
        value(const std::u16string& sv);
        value(const char16_t* sv);
        value(const std::optional<std::u16string_view>& sv);
        value(const std::string_view& sv);
        value(const std::string& sv);
        value(const char* sv);
        value(const std::optional<std::string_view>& sv);
#ifdef __cpp_char8_t
        value(const std::u8string_view& sv);
        value(const std::u8string& sv);
        value(const char8_t* sv);
        value(const std::optional<std::u8string_view>& sv);
#endif
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
        value(const std::vector<std::byte>& bin);
        value(bool b);
        value(const std::optional<bool>& b);

        operator const std::string() const;
        operator const std::u16string() const;
        operator int64_t() const;
        operator double() const;
        operator const date() const;
        operator const time() const;
        operator const datetime() const;

        operator uint32_t() const {
            return static_cast<uint32_t>(static_cast<int64_t>(*this));
        }

        operator int32_t() const {
            return static_cast<int32_t>(static_cast<int64_t>(*this));
        }

        operator uint64_t() const {
            return static_cast<uint64_t>(static_cast<int64_t>(*this));
        }

        operator float() const {
            return static_cast<float>(static_cast<double>(*this));
        }

        enum sql_type type;
        std::string val;
        bool is_null = false;
        bool is_output = false;
        unsigned int max_length = 0;
        uint8_t precision;
        uint8_t scale;
    };

    class TDSCPP column : public value {
    public:
        std::u16string name;
        bool nullable;

        operator const std::string() const {
            return (std::string)static_cast<value>(*this);
        }

        operator const std::u16string() const {
            return (std::u16string)static_cast<value>(*this);
        }

        operator int64_t() const {
            return (int64_t)static_cast<value>(*this);
        }

        operator double() const {
            return (double)static_cast<value>(*this);
        }

        operator const date() const {
            return (date)static_cast<value>(*this);
        }

        operator const time() const {
            return (time)static_cast<value>(*this);
        }

        operator const datetime() const {
            return (datetime)static_cast<value>(*this);
        }

        operator uint32_t() const {
            return (uint32_t)static_cast<value>(*this);
        }

        operator int32_t() const {
            return (int32_t)static_cast<value>(*this);
        }

        operator uint64_t() const {
            return (uint64_t)static_cast<value>(*this);
        }

        operator float() const {
            return (float)static_cast<value>(*this);
        }
    };


    template<typename T>
    class output_param : public value {
    public:
        output_param() : value(std::optional<T>(std::nullopt)) {
        }
    };

    class TDSCPP rpc {
    public:
        ~rpc();

        template<typename... Args>
        rpc(tds& conn, const std::u16string_view& name, Args&&... args) : conn(conn), name(name) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_rpc(conn, name);
        }

        rpc(tds& conn, const std::u16string_view& name) : conn(conn), name(name) {
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

        template<typename T>
        void add_param(std::vector<T>& v) {
            for (const auto& t : v) {
                params.emplace_back(t);
            }
        }

        void add_param(std::vector<std::byte>& v) {
            params.emplace_back(v);
        }

        template<typename T>
        void add_param(std::optional<T>& v) {
            if (!v.has_value()) {
                params.emplace_back("");
                params.back().is_null = true;
            } else
                params.emplace_back(v.value());
        }

        void do_rpc(tds& conn, const std::u16string_view& name);
        void wait_for_packet();

        tds& conn;
        std::vector<value> params;
        std::map<unsigned int, value*> output_params;
        bool finished = false;
        std::list<std::vector<value>> rows;
        std::list<std::string> tokens;
        std::string buf;
        std::vector<column> buf_columns;
        std::u16string name;
    };

    class TDSCPP query {
    public:
        query(tds& conn, const std::string_view& q) {
            do_query(conn, q);
        }

        query(tds& conn, const std::u16string_view& q) {
            do_query(conn, q);
        }

        template<typename... Args>
        query(tds& conn, const std::string_view& q, Args&&... args) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_query(conn, q);
        }

        template<typename... Args>
        query(tds& conn, const std::u16string_view& q, Args&&... args) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_query(conn, q);
        }

        uint16_t num_columns() const;

        const column& operator[](uint16_t i) const;

        bool fetch_row();

    private:
        void do_query(tds& conn, const std::string_view& q);
        void do_query(tds& conn, const std::u16string_view& q);

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
        void add_param(std::vector<T>& v) {
            for (const auto& t : v) {
                params.emplace_back(t);
            }
        }

        void add_param(std::vector<std::byte>& v) {
            params.emplace_back(v);
        }

        template<typename T>
        void add_param(std::optional<T>& v) {
            if (!v.has_value()) {
                params.emplace_back("");
                params.back().is_null = true;
            } else
                params.emplace_back(v.value());
        }

        std::u16string create_params_string();

        std::vector<value> params;
        std::vector<column> cols;
        std::unique_ptr<rpc> r2;
    };

    template<typename... Args>
    void tds::run(const std::string_view& s, Args&&... args) {
        query q(*this, s, args...);

        while (q.fetch_row()) { // FIXME - do we need this?
        }
    }

    template<typename... Args>
    void tds::run(const std::u16string_view& s, Args&&... args) {
        query q(*this, s, args...);

        while (q.fetch_row()) { // FIXME - do we need this?
        }
    }

    class batch_impl;

    class TDSCPP batch {
    public:
        batch(tds& conn, const std::u16string_view& q);
        batch(tds& conn, const std::string_view& q);
        ~batch();

        uint16_t num_columns() const;
        const column& operator[](uint16_t i) const;
        bool fetch_row();

    private:
        batch_impl* impl;
    };

    class TDSCPP trans {
    public:
        trans(tds& conn);
        ~trans();
        void commit();

    private:
        tds& conn;
        bool committed = false;
    };
};

template<>
struct fmt::formatter<enum tds::sql_type> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum tds::sql_type t, format_context& ctx) {
        switch (t) {
            case tds::sql_type::IMAGE:
                return format_to(ctx.out(), "IMAGE");

            case tds::sql_type::TEXT:
                return format_to(ctx.out(), "TEXT");

            case tds::sql_type::UNIQUEIDENTIFIER:
                return format_to(ctx.out(), "UNIQUEIDENTIFIER");

            case tds::sql_type::INTN:
                return format_to(ctx.out(), "INTN");

            case tds::sql_type::DATE:
                return format_to(ctx.out(), "DATE");

            case tds::sql_type::TIME:
                return format_to(ctx.out(), "TIME");

            case tds::sql_type::DATETIME2:
                return format_to(ctx.out(), "DATETIME2");

            case tds::sql_type::DATETIMEOFFSET:
                return format_to(ctx.out(), "DATETIMEOFFSET");

            case tds::sql_type::SQL_VARIANT:
                return format_to(ctx.out(), "SQL_VARIANT");

            case tds::sql_type::NTEXT:
                return format_to(ctx.out(), "NTEXT");

            case tds::sql_type::BITN:
                return format_to(ctx.out(), "BITN");

            case tds::sql_type::DECIMAL:
                return format_to(ctx.out(), "DECIMAL");

            case tds::sql_type::NUMERIC:
                return format_to(ctx.out(), "NUMERIC");

            case tds::sql_type::FLTN:
                return format_to(ctx.out(), "FLTN");

            case tds::sql_type::MONEYN:
                return format_to(ctx.out(), "MONEYN");

            case tds::sql_type::DATETIMN:
                return format_to(ctx.out(), "DATETIMN");

            case tds::sql_type::VARBINARY:
                return format_to(ctx.out(), "VARBINARY");

            case tds::sql_type::VARCHAR:
                return format_to(ctx.out(), "VARCHAR");

            case tds::sql_type::BINARY:
                return format_to(ctx.out(), "BINARY");

            case tds::sql_type::CHAR:
                return format_to(ctx.out(), "CHAR");

            case tds::sql_type::NVARCHAR:
                return format_to(ctx.out(), "NVARCHAR");

            case tds::sql_type::NCHAR:
                return format_to(ctx.out(), "NCHAR");

            case tds::sql_type::UDT:
                return format_to(ctx.out(), "UDT");

            case tds::sql_type::XML:
                return format_to(ctx.out(), "XML");

            case tds::sql_type::SQL_NULL:
                return format_to(ctx.out(), "NULL");

            case tds::sql_type::TINYINT:
                return format_to(ctx.out(), "TINYINT");

            case tds::sql_type::BIT:
                return format_to(ctx.out(), "BIT");

            case tds::sql_type::SMALLINT:
                return format_to(ctx.out(), "SMALLINT");

            case tds::sql_type::INT:
                return format_to(ctx.out(), "INT");

            case tds::sql_type::DATETIM4:
                return format_to(ctx.out(), "DATETIM4");

            case tds::sql_type::REAL:
                return format_to(ctx.out(), "REAL");

            case tds::sql_type::MONEY:
                return format_to(ctx.out(), "MONEY");

            case tds::sql_type::DATETIME:
                return format_to(ctx.out(), "DATETIME");

            case tds::sql_type::FLOAT:
                return format_to(ctx.out(), "FLOAT");

            case tds::sql_type::SMALLMONEY:
                return format_to(ctx.out(), "SMALLMONEY");

            case tds::sql_type::BIGINT:
                return format_to(ctx.out(), "BIGINT");

            default:
                return format_to(ctx.out(), "{:x}", (uint8_t)t);
        }
    }
};

template<>
struct fmt::formatter<tds::date> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::date& d, format_context& ctx) {
        return format_to(ctx.out(), "{:04}-{:02}-{:02}", d.year, d.month, d.day);
    }
};

template<>
struct fmt::formatter<tds::time> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::time& t, format_context& ctx) {
        return format_to(ctx.out(), "{:02}:{:02}:{:02}", t.hour, t.minute, t.second);
    }
};

template<>
struct fmt::formatter<tds::datetime> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::datetime& dt, format_context& ctx) {
        return format_to(ctx.out(), "{} {}", dt.d, dt.t);
    }
};

template<>
struct fmt::formatter<tds::datetimeoffset> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::datetimeoffset& dto, format_context& ctx) {
        auto absoff = abs(dto.offset);

        return format_to(ctx.out(), "{} {} {}{:02}:{:02}", dto.d, dto.t,
                        dto.offset < 0 ? '-' : '+',
                        absoff / 60, absoff % 60);
    }
};

template<>
struct fmt::formatter<tds::value> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::value& p, format_context& ctx) {
        if (p.is_null)
            return format_to(ctx.out(), "NULL");
        else
            return format_to(ctx.out(), "{}", (std::string)p);
    }
};

template<typename T>
struct fmt::formatter<tds::output_param<T>> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::output_param<T>& p, format_context& ctx) {
        return format_to(ctx.out(), "{}", static_cast<tds::value>(p));
    }
};

template<>
struct fmt::formatter<tds::column> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::column& c, format_context& ctx) {
        return format_to(ctx.out(), "{}", static_cast<tds::value>(c));
    }
};

#ifdef _MSC_VER
#define pragma warning(pop)
#endif
