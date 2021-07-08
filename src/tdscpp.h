#pragma once

#include <fmt/format.h>
#include <string>
#include <list>
#include <functional>
#include <optional>
#include <vector>
#include <map>
#include <span>
#include <ranges>
#include <chrono>
#include <time.h>
#include <nlohmann/json.hpp>

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

#ifdef __GNUC__
#define WARN_UNUSED __attribute__ ((warn_unused))
#else
#define WARN_UNUSED
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

    enum class token : uint8_t {
        OFFSET = 0x78,
        RETURNSTATUS = 0x79,
        COLMETADATA = 0x81,
        ALTMETADATA = 0x88,
        DATACLASSIFICATION = 0xa3,
        TABNAME = 0xa4,
        COLINFO = 0xa5,
        ORDER = 0xa9,
        TDS_ERROR = 0xaa,
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

#pragma pack(push, 1)

    struct tds_colmetadata_col {
        uint32_t user_type;
        uint16_t flags;
        tds::sql_type type;
    };

#pragma pack(pop)

    static_assert(sizeof(tds_colmetadata_col) == 7, "tds_colmetadata_col has wrong size");

    using msg_handler = std::function<void(const std::string_view& server, const std::string_view& message, const std::string_view& proc_name,
                                      int32_t msgno, int32_t line_number, int16_t state, uint8_t severity, bool error)>;
    using func_count_handler = std::function<void(uint64_t count, uint16_t curcmd)>;

    class value;
    class tds_impl;

    class col_info {
    public:
        col_info(sql_type type, int16_t max_length, uint8_t precision, uint8_t scale,
                const std::u16string_view& collation, bool nullable, unsigned int codepage) :
                type(type), max_length(max_length), precision(precision), scale(scale),
                collation(collation), nullable(nullable), codepage(codepage) {
        }

        sql_type type;
        int16_t max_length;
        uint8_t precision;
        uint8_t scale;
        std::u16string collation;
        bool nullable;
        unsigned int codepage;
    };

#if __cpp_lib_constexpr_string >= 201907L
#define CONSTEXPR_STRING constexpr
#else
#define CONSTEXPR_STRING
#endif

    static constexpr size_t utf8_to_utf16_len(std::string_view sv) noexcept {
        size_t ret = 0;

        while (!sv.empty()) {
            if ((uint8_t)sv[0] < 0x80) {
                ret++;
                sv = sv.substr(1);
            } else if (((uint8_t)sv[0] & 0xe0) == 0xc0 && (uint8_t)sv.length() >= 2 && ((uint8_t)sv[1] & 0xc0) == 0x80) {
                ret++;
                sv = sv.substr(2);
            } else if (((uint8_t)sv[0] & 0xf0) == 0xe0 && (uint8_t)sv.length() >= 3 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80) {
                ret++;
                sv = sv.substr(3);
            } else if (((uint8_t)sv[0] & 0xf8) == 0xf0 && (uint8_t)sv.length() >= 4 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80 && ((uint8_t)sv[3] & 0xc0) == 0x80) {
                char32_t cp = (char32_t)(((uint8_t)sv[0] & 0x7) << 18) | (char32_t)(((uint8_t)sv[1] & 0x3f) << 12) | (char32_t)(((uint8_t)sv[2] & 0x3f) << 6) | (char32_t)((uint8_t)sv[3] & 0x3f);

                if (cp > 0x10ffff) {
                    ret++;
                    sv = sv.substr(4);
                    continue;
                }

                ret += 2;
                sv = sv.substr(4);
            } else {
                ret++;
                sv = sv.substr(1);
            }
        }

        return ret;
    }

    static CONSTEXPR_STRING __inline std::u16string utf8_to_utf16(std::string_view sv) {
        std::u16string ret(utf8_to_utf16_len(sv), 0);

        if (sv.empty())
            return u"";

        auto ptr = &ret[0];

        while (!sv.empty()) {
            if ((uint8_t)sv[0] < 0x80) {
                *ptr = (uint8_t)sv[0];
                ptr++;
                sv = sv.substr(1);
            } else if (((uint8_t)sv[0] & 0xe0) == 0xc0 && (uint8_t)sv.length() >= 2 && ((uint8_t)sv[1] & 0xc0) == 0x80) {
                char16_t cp = (char16_t)(((uint8_t)sv[0] & 0x1f) << 6) | (char16_t)((uint8_t)sv[1] & 0x3f);

                *ptr = cp;
                ptr++;
                sv = sv.substr(2);
            } else if (((uint8_t)sv[0] & 0xf0) == 0xe0 && (uint8_t)sv.length() >= 3 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80) {
                char16_t cp = (char16_t)(((uint8_t)sv[0] & 0xf) << 12) | (char16_t)(((uint8_t)sv[1] & 0x3f) << 6) | (char16_t)((uint8_t)sv[2] & 0x3f);

                if (cp >= 0xd800 && cp <= 0xdfff) {
                    *ptr = 0xfffd;
                    ptr++;
                    sv = sv.substr(3);
                    continue;
                }

                *ptr = cp;
                ptr++;
                sv = sv.substr(3);
            } else if (((uint8_t)sv[0] & 0xf8) == 0xf0 && (uint8_t)sv.length() >= 4 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80 && ((uint8_t)sv[3] & 0xc0) == 0x80) {
                char32_t cp = (char32_t)(((uint8_t)sv[0] & 0x7) << 18) | (char32_t)(((uint8_t)sv[1] & 0x3f) << 12) | (char32_t)(((uint8_t)sv[2] & 0x3f) << 6) | (char32_t)((uint8_t)sv[3] & 0x3f);

                if (cp > 0x10ffff) {
                    *ptr = 0xfffd;
                    ptr++;
                    sv = sv.substr(4);
                    continue;
                }

                cp -= 0x10000;

                *ptr = (char16_t)(0xd800 | (cp >> 10)); ptr++;
                *ptr = (char16_t)(0xdc00 | (cp & 0x3ff)); ptr++;
                sv = sv.substr(4);
            } else {
                *ptr = 0xfffd;
                ptr++;
                sv = sv.substr(1);
            }
        }

        return ret;
    }

    static constexpr size_t utf16_to_utf8_len(std::u16string_view sv) noexcept {
        size_t ret = 0;

        while (!sv.empty()) {
            if (sv[0] < 0x80)
                ret++;
            else if (sv[0] < 0x800)
                ret += 2;
            else if (sv[0] < 0xd800)
                ret += 3;
            else if (sv[0] < 0xdc00) {
                if (sv.length() < 2 || (sv[1] & 0xdc00) != 0xdc00) {
                    ret += 3;
                    sv = sv.substr(1);
                    continue;
                }

                ret += 4;
                sv = sv.substr(1);
            } else
                ret += 3;

            sv = sv.substr(1);
        }

        return ret;
    }

    static CONSTEXPR_STRING __inline std::string utf16_to_utf8(std::u16string_view sv) {
        std::string ret(utf16_to_utf8_len(sv), 0);

        if (sv.empty())
            return "";

        auto ptr = &ret[0];

        while (!sv.empty()) {
            if (sv[0] < 0x80) {
                *ptr = (uint8_t)sv[0]; ptr++;
            } else if (sv[0] < 0x800) {
                *ptr = (uint8_t)(0xc0 | (sv[0] >> 6)); ptr++;
                *ptr = (uint8_t)(0x80 | (sv[0] & 0x3f)); ptr++;
            } else if (sv[0] < 0xd800) {
                *ptr = (uint8_t)(0xe0 | (sv[0] >> 12)); ptr++;
                *ptr = (uint8_t)(0x80 | ((sv[0] >> 6) & 0x3f)); ptr++;
                *ptr = (uint8_t)(0x80 | (sv[0] & 0x3f)); ptr++;
            } else if (sv[0] < 0xdc00) {
                if (sv.length() < 2 || (sv[1] & 0xdc00) != 0xdc00) {
                    *ptr = (uint8_t)0xef; ptr++;
                    *ptr = (uint8_t)0xbf; ptr++;
                    *ptr = (uint8_t)0xbd; ptr++;
                    sv = sv.substr(1);
                    continue;
                }

                char32_t cp = 0x10000 | ((sv[0] & ~0xd800) << 10) | (sv[1] & ~0xdc00);

                *ptr = (uint8_t)(0xf0 | (cp >> 18)); ptr++;
                *ptr = (uint8_t)(0x80 | ((cp >> 12) & 0x3f)); ptr++;
                *ptr = (uint8_t)(0x80 | ((cp >> 6) & 0x3f)); ptr++;
                *ptr = (uint8_t)(0x80 | (cp & 0x3f)); ptr++;
                sv = sv.substr(1);
            } else if (sv[0] < 0xe000) {
                *ptr = (uint8_t)0xef; ptr++;
                *ptr = (uint8_t)0xbf; ptr++;
                *ptr = (uint8_t)0xbd; ptr++;
            } else {
                *ptr = (uint8_t)(0xe0 | (sv[0] >> 12)); ptr++;
                *ptr = (uint8_t)(0x80 | ((sv[0] >> 6) & 0x3f)); ptr++;
                *ptr = (uint8_t)(0x80 | (sv[0] & 0x3f)); ptr++;
            }

            sv = sv.substr(1);
        }

        return ret;
    }

    size_t TDSCPP bcp_colmetadata_size(const col_info& col);
    void TDSCPP bcp_colmetadata_data(uint8_t*& ptr, const col_info& col, const std::u16string_view& name);

    template<typename T>
    concept list_of_values = std::ranges::input_range<T> && std::is_convertible_v<std::ranges::range_value_t<T>, value>;

    template<typename T>
    concept list_of_list_of_values = std::ranges::input_range<T> && list_of_values<std::ranges::range_value_t<T>>;

    template<typename T>
    concept is_string = std::is_convertible_v<T, std::string_view>;

    template<typename T>
    concept is_u16string = std::is_convertible_v<T, std::u16string_view>;

    template<typename T>
    concept is_u8string = std::is_convertible_v<T, std::u8string_view>;

    template<typename T>
    concept string_or_u16string = is_string<T> || is_u16string<T>;

    template<typename T>
    concept list_of_u16string = std::ranges::input_range<T> && is_u16string<std::ranges::range_value_t<T>>;

    template<typename T>
    concept list_of_string = std::ranges::input_range<T> && is_string<std::ranges::range_value_t<T>>;

    template<typename T>
    concept list_of_string_or_u16string = list_of_string<T> || list_of_u16string<T>;

    template<typename T>
    concept is_optional = std::is_convertible_v<std::nullopt_t, T>;

    class TDSCPP tds {
    public:
        tds(const std::string& server, const std::string_view& user, const std::string_view& password,
            const std::string_view& app_name = "tdscpp", const msg_handler& message_handler = nullptr,
            const func_count_handler& count_handler = nullptr, uint16_t port = 1433);
        ~tds();

        void run(const std::string_view& s);
        void run(const std::u16string_view& s);

        template<typename... Args>
        void run(const std::string_view& s, Args&&... args);

        template<typename... Args>
        void run(const std::u16string_view& s, Args&&... args);

        template<string_or_u16string T = std::u16string_view>
        void bcp(const string_or_u16string auto& table, const list_of_u16string auto& np,
                 const list_of_list_of_values auto& vp, const T& db = u"") {
            std::vector<col_info> cols;

            if constexpr (is_u16string<decltype(table)> && is_u16string<decltype(db)>)
                cols = bcp_start(table, np, db);
            else if constexpr (is_u16string<decltype(table)>)
                cols = bcp_start(table, np, utf8_to_utf16(db));
            else if constexpr (is_u16string<decltype(db)>)
                cols = bcp_start(utf8_to_utf16(table), np, db);
            else
                cols = bcp_start(utf8_to_utf16(table), np, utf8_to_utf16(db));

            // send COLMETADATA for rows
            auto buf = bcp_colmetadata(np, cols);

            for (const auto& v : vp) {
                auto buf2 = bcp_row(v, np, cols);

                auto oldlen = buf.size();
                buf.resize(oldlen + buf2.size());
                memcpy(&buf[oldlen], buf2.data(), buf2.size());
            }

            bcp_sendmsg(std::string_view((char*)buf.data(), buf.size()));
        }

        template<string_or_u16string T = std::u16string_view>
        void bcp(const string_or_u16string auto& table, const list_of_string auto& np,
                 const list_of_list_of_values auto& vp, const T& db = u"") {
            std::vector<std::u16string> np2;

            for (const auto& s : np) {
                np2.emplace_back(utf8_to_utf16(s));
            }

            bcp(table, np2, vp, db);
        }

        uint16_t spid() const;

        tds_impl* impl;

    private:
        std::vector<col_info> bcp_start(const std::u16string_view& table, const list_of_u16string auto& np,
                                        const std::u16string_view& db);
        std::vector<uint8_t> bcp_colmetadata(const list_of_u16string auto& np, const std::vector<col_info>& cols);
        std::vector<uint8_t> bcp_row(const list_of_values auto& v, const list_of_u16string auto& np, const std::vector<col_info>& cols);

        void bcp_sendmsg(const std::string_view& msg);
        size_t bcp_row_size(const col_info& col, const value& vv);
        void bcp_row_data(uint8_t*& ptr, const col_info& col, const value& vv, const std::u16string_view& col_name);
    };

    using time_t = std::chrono::duration<int64_t, std::ratio<1, 10000000>>;

    class TDSCPP datetime {
    public:
        constexpr datetime() = default;

        constexpr datetime(std::chrono::year year, std::chrono::month month, std::chrono::day day, uint8_t hour, uint8_t minute, uint8_t second) :
            d(year, month, day) {
            auto secs = std::chrono::seconds((hour * 3600) + (minute * 60) + second);

            t = std::chrono::duration_cast<time_t>(secs);
        }

        constexpr datetime(std::chrono::year year, std::chrono::month month, std::chrono::day day, time_t t) :
            d(year, month, day), t(t) { }

        constexpr datetime(const std::chrono::year_month_day& d, time_t t) : d(d), t(t) { }

        template<typename T, typename U>
        datetime(const std::chrono::year_month_day& d, std::chrono::duration<T, U> t) : d(d), t{std::chrono::duration_cast<time_t>(t)} { }

        template<typename T>
        constexpr datetime(const std::chrono::time_point<T>& chr) {
            d = std::chrono::floor<std::chrono::days>(chr);
            t = std::chrono::floor<time_t>(chr - std::chrono::floor<std::chrono::days>(chr));
        }

        constexpr operator std::chrono::time_point<std::chrono::system_clock>() const {
            return std::chrono::sys_days{d} + t;
        }

        std::chrono::year_month_day d;
        time_t t;
    };

    class TDSCPP datetimeoffset : public datetime {
    public:
        constexpr datetimeoffset() = default;
        constexpr datetimeoffset(std::chrono::year year, std::chrono::month month, std::chrono::day day, uint8_t hour, uint8_t minute, uint8_t second, int16_t offset) :
            datetime(year, month, day, hour, minute, second), offset(offset) { }
        constexpr datetimeoffset(const std::chrono::year_month_day& d, time_t t, int16_t offset) : datetime(d, t), offset(offset) { }

        constexpr datetimeoffset(std::chrono::year year, std::chrono::month month, std::chrono::day day, time_t t, int16_t offset) :
            datetime(year, month, day, t), offset(offset) { }

        constexpr datetimeoffset(const std::chrono::time_point<std::chrono::system_clock>& t, int16_t offset) :
            datetime(t), offset(offset) { }

        template<typename T, typename U>
        constexpr datetimeoffset(const std::chrono::year_month_day& d2, std::chrono::duration<T, U> t2, int16_t offset) : offset(offset) {
            d = d2;
            t = std::chrono::duration_cast<time_t>(t2);
        }

        constexpr operator std::chrono::time_point<std::chrono::system_clock>() const {
            return std::chrono::sys_days{d} + t - std::chrono::minutes{offset};
        }

        static datetimeoffset now();

        int16_t offset;
    };

    template<typename T>
    concept byte_list = requires(T t) {
        { std::span<std::byte>{t} };
    };

    template<unsigned N>
    requires (N <= 38)
    class numeric;

    class TDSCPP WARN_UNUSED value {
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
        value(wchar_t) = delete;
        value(const std::u16string_view& sv);

        value(const std::u16string& sv) : value(std::u16string_view(sv)) {
        }

        value(const char16_t* sv) : value(std::u16string_view(sv)) {
        }

        value(const std::optional<std::u16string_view>& sv);
        value(const std::string_view& sv);

        value(const std::string& sv) : value(std::string_view(sv)) {
        }

        value(const char* sv) : value(std::string_view(sv)) {
        }

        value(const std::optional<std::string_view>& sv);
        value(const std::u8string_view& sv);

        value(const std::u8string& sv) : value(std::u8string_view(sv)) {
        }

        value(const char8_t* sv) : value(std::u8string_view(sv)) {
        }

        value(const std::optional<std::u8string_view>& sv);
        value(float f);
        value(const std::optional<float>& f);
        value(double d);
        value(const std::optional<double>& d);
        value(const std::chrono::year_month_day& d);
        value(const std::optional<std::chrono::year_month_day>& d);
        value(time_t t);
        value(const std::optional<time_t>& t);
        value(const datetime& dt);
        value(const std::optional<datetime>& t);
        value(const datetimeoffset& dt);
        value(const std::optional<datetimeoffset>& t);

        value(const std::span<std::byte>& bin) {
            type = sql_type::VARBINARY;
            val.resize(bin.size());
            memcpy(val.data(), bin.data(), bin.size());
        }

        template<typename T> requires byte_list<T>
        value(const std::optional<T>& bin) {
            type = sql_type::VARBINARY;

            if (!bin.has_value())
                is_null = true;
            else {
                const auto& s = std::span{bin.value()};
                val.resize(s.size());
                memcpy(val.data(), s.data(), s.size());
            }
        }

        value(bool b);
        value(const std::optional<bool>& b);
        value(const std::chrono::time_point<std::chrono::system_clock>& chr) : value((datetime)chr) { }

        template<typename T, typename U>
        value(std::chrono::duration<T, U> t) : value(std::chrono::duration_cast<time_t>(t)) { }

        template<unsigned N>
        value(const numeric<N>& n) noexcept {
            type = sql_type::NUMERIC;
            precision = 38;
            scale = N;
            val.resize(17);
            val[0] = n.neg ? 0 : 1;
            *(uint64_t*)&val[1] = n.low_part;
            *(uint64_t*)&val[1 + sizeof(uint64_t)] = n.high_part;
        }

        explicit operator std::string() const;
        explicit operator std::u16string() const;
        explicit operator int64_t() const;
        explicit operator double() const;
        explicit operator std::chrono::year_month_day() const;
        explicit operator datetime() const;
        explicit operator datetimeoffset() const;

        explicit operator time_t() const;

        template<typename T, typename U>
        explicit operator std::chrono::duration<T, U>() const {
            return std::chrono::duration_cast<std::chrono::duration<T, U>>((time_t)*this);
        }

        template<typename T>
        requires std::is_integral_v<T>
        explicit operator T() const {
            return static_cast<T>(static_cast<int64_t>(*this));
        }

        template<typename T>
        requires std::is_floating_point_v<T>
        explicit operator T() const {
            return static_cast<T>(static_cast<double>(*this));
        }

        explicit operator std::chrono::time_point<std::chrono::system_clock>() const {
            return static_cast<std::chrono::time_point<std::chrono::system_clock>>(static_cast<datetime>(*this));
        }

        template<unsigned N>
        explicit operator numeric<N>() const {
            auto type2 = type;
            std::string_view d = val;

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
                    return (int64_t)*this;

                case sql_type::NUMERIC:
                case sql_type::DECIMAL: {
                    numeric<N> n;

                    n.neg = d[0] == 0;

                    if (d.length() >= 9)
                        n.low_part = *(uint64_t*)&d[1];
                    else
                        n.low_part = *(uint32_t*)&d[1];

                    if (d.length() >= 17)
                        n.high_part = *(uint64_t*)&d[1 + sizeof(uint64_t)];
                    else if (d.length() >= 13)
                        n.high_part = *(uint32_t*)&d[1 + sizeof(uint64_t)];
                    else
                        n.high_part = 0;

                    if (N < scale) {
                        for (unsigned int i = N; i < scale; i++) {
                            n.ten_div();
                        }
                    } else if (N > scale) {
                        for (unsigned int i = scale; i < N; i++) {
                            n.ten_mult();
                        }
                    }

                    return n;
                }

                // FIXME - REAL / FLOAT

                default:
                    return (int64_t)*this; // FIXME - should be double when supported
            }
        }

        enum sql_type type;
        std::string val;
        bool is_null = false;
        bool is_output = false;
        bool utf8 = false;
        unsigned int max_length = 0;
        uint8_t precision;
        uint8_t scale;
    };

#pragma pack(push,1)

    struct collation {
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

    static_assert(sizeof(collation) == 5, "tds::collation has wrong size");

#pragma pack(pop)

    class TDSCPP column : public value {
    public:
        std::u16string name;
        bool nullable;
        collation coll;
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
        rpc(tds& tds, const std::u16string_view& rpc_name, Args&&... args) : conn(tds) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_rpc(conn, rpc_name);
        }

        rpc(tds& tds, const std::u16string_view& rpc_name) : conn(tds) {
            do_rpc(conn, rpc_name);
        }

        template<typename... Args>
        rpc(tds& tds, const std::string_view& rpc_name, Args&&... args) : conn(tds) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_rpc(conn, rpc_name);
        }

        rpc(tds& tds, const std::string_view& rpc_name) : conn(tds) {
            do_rpc(conn, rpc_name);
        }

        uint16_t num_columns() const;

        const column& operator[](uint16_t i) const;

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

        template<typename T> requires (std::ranges::input_range<T> && !byte_list<T> && !is_string<T> && !is_u16string<T> && !is_u8string<T>)
        void add_param(T&& v) {
            for (const auto& t : v) {
                params.emplace_back(t);
            }
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
        void do_rpc(tds& conn, const std::string_view& name);
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
        query(tds& tds, const std::string_view& q) : conn(tds) {
            do_query(conn, q);
        }

        query(tds& tds, const std::u16string_view& q) : conn(tds) {
            do_query(conn, q);
        }

        template<typename... Args>
        query(tds& tds, const std::string_view& q, Args&&... args) : conn(tds) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_query(conn, q);
        }

        template<typename... Args>
        query(tds& tds, const std::u16string_view& q, Args&&... args) : conn(tds) {
            params.reserve(sizeof...(args));

            add_param(args...);

            do_query(conn, q);
        }

        ~query();

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

        template<typename T> requires (std::ranges::input_range<T> && !byte_list<T> && !is_string<T> && !is_u16string<T> && !is_u8string<T>)
        void add_param(T&& v) {
            for (const auto& t : v) {
                params.emplace_back(t);
            }
        }

        void add_param(const std::span<std::byte>& bin) {
            params.emplace_back(bin);
        }

        template<typename T> requires byte_list<T>
        void add_param(const std::optional<T>& bin) {
            if (!bin.has_value()) {
                params.emplace_back("");
                params.back().is_null = true;
            } else
                params.emplace_back(bin.value());
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

        tds& conn;
        std::vector<value> params;
        std::vector<column> cols;
        std::unique_ptr<rpc> r2;
        output_param<int32_t> handle;
    };

    template<typename... Args>
    void tds::run(const std::string_view& s, Args&&... args) {
        query q(*this, s, args...);

        while (q.fetch_row()) {
        }
    }

    template<typename... Args>
    void tds::run(const std::u16string_view& s, Args&&... args) {
        query q(*this, s, args...);

        while (q.fetch_row()) {
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

    void __inline tds::run(const std::string_view& s) {
        batch b(*this, s);

        while (b.fetch_row()) {
        }
    }

    void __inline tds::run(const std::u16string_view& s) {
        batch b(*this, s);

        while (b.fetch_row()) {
        }
    }

    class TDSCPP trans {
    public:
        trans(tds& conn);
        ~trans();
        void commit();

    private:
        tds& conn;
        bool committed = false;
    };

    void TDSCPP to_json(nlohmann::json& j, const value& v);

    static void __inline to_json(nlohmann::json& j, const column& c) {
        to_json(j, static_cast<const value&>(c));
    }

    static std::string __inline escape(const std::string_view& sv) {
        std::string s{"["};

        s.reserve(sv.length() + 2);

        for (const auto& c : sv) {
                if (c == ']')
                    s += "]]";
                else
                    s += c;
        }

        s += "]";

        return s;
    }

    static std::u16string __inline escape(const std::u16string_view& sv) {
        std::u16string s{u"["};

        s.reserve(sv.length() + 2);

        for (const auto& c : sv) {
            if (c == u']')
                s += u"]]";
            else
                s += c;
        }

        s += u"]";

        return s;
    }

    uint16_t TDSCPP get_instance_port(const std::string& server, const std::string_view& instance);

    std::vector<uint8_t> tds::bcp_row(const list_of_values auto& v, const list_of_u16string auto& np, const std::vector<col_info>& cols) {
        size_t bufsize = sizeof(uint8_t);

        auto it = v.begin();
        auto it2 = np.begin();
        unsigned int num_cols = 0;

        for (const auto& col : cols) {
            const auto& vv = *it;

            if (it == v.end()) {
                if constexpr (std::ranges::sized_range<decltype(v)>)
                    throw std::runtime_error("Trying to send " + std::to_string(v.size()) + " columns in a BCP row, expected " + std::to_string(cols.size()) + ".");
                else
                    throw std::runtime_error("Trying to send " + std::to_string(num_cols) + " columns in a BCP row, expected " + std::to_string(cols.size()) + ".");
            }

            if constexpr (std::is_same_v<std::ranges::range_value_t<decltype(v)>, value>) {
                if (vv.is_null && !col.nullable)
                    throw std::runtime_error("Cannot insert NULL into column " + utf16_to_utf8(*it2) + " marked NOT NULL.");
            } else if constexpr (is_optional<std::ranges::range_value_t<decltype(v)>>) {
                if (!vv.has_value() && !col.nullable)
                    throw std::runtime_error("Cannot insert NULL into column " + utf16_to_utf8(*it2) + " marked NOT NULL.");
            }

            bufsize += bcp_row_size(col, vv);
            it++;
            it2++;
            num_cols++;
        }

        std::vector<uint8_t> buf(bufsize);
        uint8_t* ptr = buf.data();

        *(token*)ptr = token::ROW;
        ptr++;

        it = v.begin();
        it2 = np.begin();

        for (const auto& col : cols) {
            const auto& vv = *it;

            bcp_row_data(ptr, col, vv, *it2);

            it++;
            it2++;
        }

        return buf;
    }

    std::vector<uint8_t> tds::bcp_colmetadata(const list_of_u16string auto& np, const std::vector<col_info>& cols) {
        size_t bufsize = sizeof(uint8_t) + sizeof(uint16_t) + (cols.size() * sizeof(tds_colmetadata_col));

        for (const auto& col : cols) {
            bufsize += bcp_colmetadata_size(col) + sizeof(uint8_t);
        }

        for (const auto& n : np) {
            bufsize += std::u16string_view{n}.length() * sizeof(char16_t);
        }

        std::vector<uint8_t> buf(bufsize);
        auto ptr = (uint8_t*)buf.data();

        *(token*)ptr = token::COLMETADATA; ptr++;
        *(uint16_t*)ptr = (uint16_t)cols.size(); ptr += sizeof(uint16_t);

        auto it = np.begin();

        for (unsigned int i = 0; i < cols.size(); i++) {
            const auto& col = cols[i];

            bcp_colmetadata_data(ptr, col, *it);

            it++;
        }

        return buf;
    }

    std::map<std::u16string, col_info> TDSCPP get_col_info(tds& tds, const std::u16string_view& table, const std::u16string_view& db);
    std::u16string TDSCPP sql_escape(const std::u16string_view& sv);
    std::u16string TDSCPP type_to_string(enum sql_type type, size_t length, uint8_t precision, uint8_t scale, const std::u16string_view& collation);

    std::vector<col_info> tds::bcp_start(const std::u16string_view& table, const list_of_u16string auto& np, const std::u16string_view& db) {
        if (np.empty())
            throw std::runtime_error("List of columns not supplied.");

        // FIXME - do we need to make sure no duplicates in np?

        std::vector<col_info> cols;

        {
            auto col_info = get_col_info(*this, table, db);

            if constexpr (std::ranges::sized_range<decltype(np)>)
                cols.reserve(np.size());

            for (const auto& n : np) {
                if (col_info.count(n) == 0)
                    throw std::runtime_error("Column " + utf16_to_utf8(n) + " not found in table " + utf16_to_utf8(table) + ".");

                cols.emplace_back(col_info.at(n));
            }
        }

        {
            std::u16string q = u"INSERT BULK " + (!db.empty() ? (std::u16string(db) + u".") : u"") + std::u16string(table) + u"(";
            bool first = true;

            auto it = np.begin();

            for (const auto& col : cols) {
                if (!first)
                    q += u", ";

                q += sql_escape(*it) + u" ";
                q += type_to_string(col.type, col.max_length, col.precision, col.scale, col.collation);

                first = false;

                it++;
            }

            q += u") WITH (TABLOCK)";

            batch b(*this, q);
        }

        // FIXME - handle INT NULLs and VARCHAR NULLs

        return cols;
    }

    template<unsigned N>
    requires (N <= 38)
    class WARN_UNUSED numeric {
    public:
        numeric() = default;

        constexpr numeric(int64_t v) noexcept {
            if (v < 0)
                low_part = (uint64_t)-v;
            else
                low_part = (uint64_t)v;

            high_part = 0;
            neg = v < 0;

            for (unsigned int i = 0; i < N; i++) {
                ten_mult();
            }
        }

        constexpr numeric(uint64_t v) noexcept {
            low_part = v;
            high_part = 0;
            neg = false;

            for (unsigned int i = 0; i < N; i++) {
                ten_mult();
            }
        }

        template<typename T>
        requires std::is_integral_v<T> && std::is_signed_v<T>
        constexpr numeric(T v) noexcept : numeric(static_cast<int64_t>(v)) { }

        template<typename T>
        requires std::is_integral_v<T> && (!std::is_signed_v<T>)
        constexpr numeric(T v) noexcept : numeric(static_cast<uint64_t>(v)) { }

        template<typename T>
        requires std::is_same_v<T, float> || std::is_same_v<T, double>
        constexpr numeric(T d) noexcept {
            auto db = fmt::detail::dragonbox::to_decimal(d);

            neg = d < 0;
            low_part = db.significand;
            high_part = 0;

            for (int i = N; i < -db.exponent; i++) {
                ten_div();
            }

            for (int i = -db.exponent; i < (int)N; i++) {
                ten_mult();
            }
        }

        template<unsigned N2>
        constexpr numeric(const numeric<N2>& n) noexcept {
            low_part = n.low_part;
            high_part = n.high_part;
            neg = n.neg;

            if constexpr (N2 < N) {
                for (unsigned int i = N2; i < N; i++) {
                    ten_mult();
                }
            } else if constexpr (N2 > N) {
                for (unsigned int i = N; i < N2; i++) {
                    ten_div();
                }
            }
        }

        constexpr operator int64_t() noexcept {
            if constexpr (N == 0)
                return neg ? -(int64_t)low_part : low_part;
            else {
                numeric<0> n = *this;

                return neg ? -(int64_t)n.low_part : n.low_part;
            }
        }

        constexpr void ten_mult() noexcept {
            if (low_part >= std::numeric_limits<uint64_t>::max() / 10) {
                auto lp1 = low_part << 1;
                auto lp2 = low_part << 3;

                auto hp1 = low_part >> 63;
                auto hp2 = low_part >> 61;

                low_part = lp1 + lp2;
                high_part *= 10;
                high_part += hp1 + hp2;

                if ((lp1 >> 60) + (lp2 >> 60) >= 0x10)
                    high_part++;
            } else {
                low_part *= 10;
                high_part *= 10;
            }
        }

        constexpr void ten_div() noexcept {
            low_part /= 10;

            if (high_part != 0) {
                auto hp1 = high_part % 10;

                high_part /= 10;
                low_part += 0x199999999999999a * hp1;
            }
        }

        // FIXME - operator uint64_t?
        // FIXME - operator double
        // FIXME - operator numeric<N2>?

        constexpr std::strong_ordering operator<=>(const numeric<N>& n) const {
            if (neg && !n.neg)
                return std::strong_ordering::less;
            else if (!neg && n.neg)
                return std::strong_ordering::greater;

            if (high_part < n.high_part)
                return neg ? std::strong_ordering::greater : std::strong_ordering::less;
            else if (high_part > n.high_part)
                return neg ? std::strong_ordering::less : std::strong_ordering::greater;

            if (low_part < n.low_part)
                return neg ? std::strong_ordering::greater : std::strong_ordering::less;
            else if (low_part > n.low_part)
                return neg ? std::strong_ordering::less : std::strong_ordering::greater;

            return std::strong_ordering::equal;
        }

        uint64_t low_part, high_part;
        bool neg;
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
    auto format(enum tds::sql_type t, format_context& ctx) const {
        switch (t) {
            case tds::sql_type::IMAGE:
                return fmt::format_to(ctx.out(), "IMAGE");

            case tds::sql_type::TEXT:
                return fmt::format_to(ctx.out(), "TEXT");

            case tds::sql_type::UNIQUEIDENTIFIER:
                return fmt::format_to(ctx.out(), "UNIQUEIDENTIFIER");

            case tds::sql_type::INTN:
                return fmt::format_to(ctx.out(), "INTN");

            case tds::sql_type::DATE:
                return fmt::format_to(ctx.out(), "DATE");

            case tds::sql_type::TIME:
                return fmt::format_to(ctx.out(), "TIME");

            case tds::sql_type::DATETIME2:
                return fmt::format_to(ctx.out(), "DATETIME2");

            case tds::sql_type::DATETIMEOFFSET:
                return fmt::format_to(ctx.out(), "DATETIMEOFFSET");

            case tds::sql_type::SQL_VARIANT:
                return fmt::format_to(ctx.out(), "SQL_VARIANT");

            case tds::sql_type::NTEXT:
                return fmt::format_to(ctx.out(), "NTEXT");

            case tds::sql_type::BITN:
                return fmt::format_to(ctx.out(), "BITN");

            case tds::sql_type::DECIMAL:
                return fmt::format_to(ctx.out(), "DECIMAL");

            case tds::sql_type::NUMERIC:
                return fmt::format_to(ctx.out(), "NUMERIC");

            case tds::sql_type::FLTN:
                return fmt::format_to(ctx.out(), "FLTN");

            case tds::sql_type::MONEYN:
                return fmt::format_to(ctx.out(), "MONEYN");

            case tds::sql_type::DATETIMN:
                return fmt::format_to(ctx.out(), "DATETIMN");

            case tds::sql_type::VARBINARY:
                return fmt::format_to(ctx.out(), "VARBINARY");

            case tds::sql_type::VARCHAR:
                return fmt::format_to(ctx.out(), "VARCHAR");

            case tds::sql_type::BINARY:
                return fmt::format_to(ctx.out(), "BINARY");

            case tds::sql_type::CHAR:
                return fmt::format_to(ctx.out(), "CHAR");

            case tds::sql_type::NVARCHAR:
                return fmt::format_to(ctx.out(), "NVARCHAR");

            case tds::sql_type::NCHAR:
                return fmt::format_to(ctx.out(), "NCHAR");

            case tds::sql_type::UDT:
                return fmt::format_to(ctx.out(), "UDT");

            case tds::sql_type::XML:
                return fmt::format_to(ctx.out(), "XML");

            case tds::sql_type::SQL_NULL:
                return fmt::format_to(ctx.out(), "NULL");

            case tds::sql_type::TINYINT:
                return fmt::format_to(ctx.out(), "TINYINT");

            case tds::sql_type::BIT:
                return fmt::format_to(ctx.out(), "BIT");

            case tds::sql_type::SMALLINT:
                return fmt::format_to(ctx.out(), "SMALLINT");

            case tds::sql_type::INT:
                return fmt::format_to(ctx.out(), "INT");

            case tds::sql_type::DATETIM4:
                return fmt::format_to(ctx.out(), "DATETIM4");

            case tds::sql_type::REAL:
                return fmt::format_to(ctx.out(), "REAL");

            case tds::sql_type::MONEY:
                return fmt::format_to(ctx.out(), "MONEY");

            case tds::sql_type::DATETIME:
                return fmt::format_to(ctx.out(), "DATETIME");

            case tds::sql_type::FLOAT:
                return fmt::format_to(ctx.out(), "FLOAT");

            case tds::sql_type::SMALLMONEY:
                return fmt::format_to(ctx.out(), "SMALLMONEY");

            case tds::sql_type::BIGINT:
                return fmt::format_to(ctx.out(), "BIGINT");

            default:
                return fmt::format_to(ctx.out(), "{:x}", (uint8_t)t);
        }
    }
};

template<>
struct fmt::formatter<tds::datetime> {
    unsigned int len = 7;
    int len_arg = -1;

    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end()) {
            if (*it >= '0' && *it <= '7') {
                len = *it - '0';
                it++;
            } else if (*it == '{') {
                it++;

                if (it == ctx.end() || *it != '}')
                    throw format_error("invalid format");

                len_arg = ctx.next_arg_id();

                it++;
            }
        }

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::datetime& dt, format_context& ctx) const {
        auto len2 = len;
        auto hms = std::chrono::hh_mm_ss{dt.t};

        if (len_arg != -1) {
            auto arg = ctx.arg(len_arg);

            fmt::visit_format_arg([&](auto&& v) {
                if constexpr (std::is_integral_v<std::remove_reference_t<decltype(v)>>) {
                    len2 = (unsigned int)v;

                    if (len2 > 7)
                        throw format_error("size out of range");
                } else
                    throw format_error("invalid size argument");
            }, arg);
        }

        if (len2 == 0) {
            return fmt::format_to(ctx.out(), "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                            (int)dt.d.year(), (unsigned int)dt.d.month(), (unsigned int)dt.d.day(),
                            hms.hours().count(), hms.minutes().count(), hms.seconds().count());
        }

        double s = (double)hms.seconds().count() + ((double)hms.subseconds().count() / 10000000.0);

        return fmt::format_to(ctx.out(), "{:04}-{:02}-{:02} {:02}:{:02}:{:0{}.{}f}",
                         (int)dt.d.year(), (unsigned int)dt.d.month(), (unsigned int)dt.d.day(),
                         hms.hours().count(), hms.minutes().count(), s, len2 + 3, len2);
    }
};

template<>
struct fmt::formatter<tds::datetimeoffset> {
    unsigned int len = 7;
    int len_arg = -1;

    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end()) {
            if (*it >= '0' && *it <= '7') {
                len = *it - '0';
                it++;
            } else if (*it == '{') {
                it++;

                if (it == ctx.end() || *it != '}')
                    throw format_error("invalid format");

                len_arg = ctx.next_arg_id();

                it++;
            }
        }

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::datetimeoffset& dto, format_context& ctx) const {
        auto len2 = len;
        auto hms = std::chrono::hh_mm_ss{dto.t};

        if (len_arg != -1) {
            auto arg = ctx.arg(len_arg);

            fmt::visit_format_arg([&](auto&& v) {
                if constexpr (std::is_integral_v<std::remove_reference_t<decltype(v)>>) {
                    len2 = (unsigned int)v;

                    if (len2 > 7)
                        throw format_error("size out of range");
                } else
                    throw format_error("invalid size argument");
            }, arg);
        }

        if (len2 == 0) {
            return fmt::format_to(ctx.out(), "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {:+03}:{:02}",
                             (int)dto.d.year(), (unsigned int)dto.d.month(), (unsigned int)dto.d.day(),
                             hms.hours().count(), hms.minutes().count(), hms.seconds().count(),
                             dto.offset / 60, abs(dto.offset) % 60);
        }

        double s = (double)hms.seconds().count() + ((double)hms.subseconds().count() / 10000000.0);

        return fmt::format_to(ctx.out(), "{:04}-{:02}-{:02} {:02}:{:02}:{:0{}.{}f} {:+03}:{:02}",
                         (int)dto.d.year(), (unsigned int)dto.d.month(), (unsigned int)dto.d.day(),
                         hms.hours().count(), hms.minutes().count(),
                         s, len2 + 3, len2,
                         dto.offset / 60, abs(dto.offset) % 60);
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
    auto format(const tds::value& p, format_context& ctx) const {
        if (p.is_null)
            return fmt::format_to(ctx.out(), "NULL");
        else if (p.type == tds::sql_type::VARBINARY || p.type == tds::sql_type::BINARY || p.type == tds::sql_type::IMAGE) {
            std::string s = "0x";

            for (auto c : p.val) {
                s += fmt::format("{:02x}", (uint8_t)c);
            }

            return fmt::format_to(ctx.out(), "{}", s);
        } else
            return fmt::format_to(ctx.out(), "{}", (std::string)p);
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
    auto format(const tds::output_param<T>& p, format_context& ctx) const {
        return fmt::format_to(ctx.out(), "{}", static_cast<tds::value>(p));
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
    auto format(const tds::column& c, format_context& ctx) const {
        return fmt::format_to(ctx.out(), "{}", static_cast<tds::value>(c));
    }
};


template<unsigned N>
struct fmt::formatter<tds::numeric<N>> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const tds::numeric<N>& n, format_context& ctx) const {
        uint8_t scratch[38];
        char s[80], *p;
        unsigned int pos;

        // double dabble

        *(uint64_t*)scratch = n.low_part;
        *(uint64_t*)&scratch[sizeof(uint64_t)] = n.high_part;
        memset(&scratch[2 * sizeof(uint64_t)], 0, sizeof(scratch) - (2 * sizeof(uint64_t)));

        for (unsigned int iter = 0; iter < 16 * 8; iter++) {
            for (unsigned int i = 16; i < 38; i++) {
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

            bool carry = false;

            for (unsigned int i = 0; i < sizeof(scratch); i++) {
                bool b = scratch[i] & 0x80;

                scratch[i] <<= 1;

                if (carry)
                    scratch[i] |= 1;

                carry = b;
            }
        }

        p = s;
        pos = 0;
        for (unsigned int i = 37; i >= 16; i--) {
            *p = (char)((scratch[i] >> 4) + '0');
            p++;
            pos++;

            if (pos == 77 - (16 * 2) - N - 1) {
                *p = '.';
                p++;
            }

            *p = (char)((scratch[i] & 0xf) + '0');
            p++;
            pos++;

            if (pos == 77 - (16 * 2) - N - 1) {
                *p = '.';
                p++;
            }
        }
        *p = 0;

        auto dot = &s[77 - (16 * 2) - N - 1];

        // remove leading zeroes

        for (p = s; p < dot - 1; p++) {
            if (*p != '0')
                break;
        }

        if constexpr (N == 0) // remove trailing dot
            p[strlen(p) - 1] = 0;

        return fmt::format_to(ctx.out(), "{}{}", n.neg ? "-" : "", p);
    }
};

#ifdef _MSC_VER
#define pragma warning(pop)
#endif
