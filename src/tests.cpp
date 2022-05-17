#include "tdscpp.h"

using namespace std;

constexpr bool value_test(const tds::value& v, enum tds::sql_type type, bool null, const vector<uint8_t>& exp) {
    if (v.type != type)
        return false;

    if ((v.is_null && !null) || (!v.is_null && null))
        return false;

    if (null)
        return true;

    if (exp.size() != v.val.size())
        return false;

    for (unsigned int i = 0; i < exp.size(); i++) {
        if (exp[i] != v.val[i])
            return false;
    }

    return true;
}

static_assert(value_test(tds::value{}, (enum tds::sql_type)0, false, { })); // default
static_assert(value_test(tds::value{nullptr}, tds::sql_type::SQL_NULL, true, { })); // typeless NULL

static_assert(value_test(tds::value{(int32_t)0x12345678}, tds::sql_type::INTN, false, { 0x78, 0x56, 0x34, 0x12 })); // int32_t
static_assert(value_test(tds::value{optional<int32_t>(0x12345678)}, tds::sql_type::INTN, false, { 0x78, 0x56, 0x34, 0x12 })); // optional<int32_t>
static_assert(value_test(tds::value{optional<int32_t>(nullopt)}, tds::sql_type::INTN, true, { })); // optional<int32_t>
static_assert(value_test(tds::value{(int64_t)0x123456789abcdef0}, tds::sql_type::INTN, false, { 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12 })); // int64_t
static_assert(value_test(tds::value{optional<int64_t>(0x123456789abcdef0)}, tds::sql_type::INTN, false, { 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12 })); // optional<int64_t>
static_assert(value_test(tds::value{optional<int64_t>(nullopt)}, tds::sql_type::INTN, true, { })); // optional<int64_t>
static_assert(value_test(tds::value{(uint32_t)0x12345678}, tds::sql_type::INTN, false, { 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 })); // uint32_t
static_assert(value_test(tds::value{optional<uint32_t>(0x12345678)}, tds::sql_type::INTN, false, { 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 })); // uint32_t
static_assert(value_test(tds::value{optional<uint32_t>(nullopt)}, tds::sql_type::INTN, true, { })); // uint32_t

static_assert(value_test(tds::value{"hello"s}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // string
static_assert(value_test(tds::value{"hello"sv}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // string_view
static_assert(value_test(tds::value{"hello"}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // const char*
static_assert(value_test(tds::value{optional<string>("hello")}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // optional<string>
static_assert(value_test(tds::value{optional<string>(nullopt)}, tds::sql_type::VARCHAR, true, { })); // optional<string>
static_assert(value_test(tds::value{optional<string_view>("hello")}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // optional<string_view>
static_assert(value_test(tds::value{optional<string_view>(nullopt)}, tds::sql_type::VARCHAR, true, { })); // optional<string_view>
// FIXME - optional<char*>?

static_assert(value_test(tds::value{u8"hello"s}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // u8string
static_assert(value_test(tds::value{u8"h\u00e9llo"s}, tds::sql_type::VARCHAR, false, { 0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f })); // u8string
static_assert(value_test(tds::value{u8"h\U0001f525llo"s}, tds::sql_type::VARCHAR, false, { 0x68, 0xf0, 0x9f, 0x94, 0xa5, 0x6c, 0x6c, 0x6f })); // u8string
static_assert(value_test(tds::value{u8"hello"sv}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // u8string_view
static_assert(value_test(tds::value{u8"h\u00e9llo"sv}, tds::sql_type::VARCHAR, false, { 0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f })); // u8string_view
static_assert(value_test(tds::value{u8"h\U0001f525llo"sv}, tds::sql_type::VARCHAR, false, { 0x68, 0xf0, 0x9f, 0x94, 0xa5, 0x6c, 0x6c, 0x6f })); // u8string_view
static_assert(value_test(tds::value{u8"hello"}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // const char8_t*
static_assert(value_test(tds::value{u8"h\u00e9llo"}, tds::sql_type::VARCHAR, false, { 0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f })); // const char8_t*
static_assert(value_test(tds::value{u8"h\U0001f525llo"}, tds::sql_type::VARCHAR, false, { 0x68, 0xf0, 0x9f, 0x94, 0xa5, 0x6c, 0x6c, 0x6f })); // const char8_t*
static_assert(value_test(tds::value{optional<u8string>(u8"hello")}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // optional<u8string>
static_assert(value_test(tds::value{optional<u8string>(u8"h\u00e9llo")}, tds::sql_type::VARCHAR, false, { 0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f })); // optional<u8string>
static_assert(value_test(tds::value{optional<u8string>(u8"h\U0001f525llo")}, tds::sql_type::VARCHAR, false, { 0x68, 0xf0, 0x9f, 0x94, 0xa5, 0x6c, 0x6c, 0x6f })); // optional<u8string>
static_assert(value_test(tds::value{optional<u8string>(nullopt)}, tds::sql_type::VARCHAR, true, { })); // optional<u8string>
static_assert(value_test(tds::value{optional<u8string_view>(u8"hello")}, tds::sql_type::VARCHAR, false, { 0x68, 0x65, 0x6c, 0x6c, 0x6f })); // optional<u8string_view>
static_assert(value_test(tds::value{optional<u8string_view>(u8"h\u00e9llo")}, tds::sql_type::VARCHAR, false, { 0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f })); // optional<u8string_view>
static_assert(value_test(tds::value{optional<u8string_view>(u8"h\U0001f525llo")}, tds::sql_type::VARCHAR, false, { 0x68, 0xf0, 0x9f, 0x94, 0xa5, 0x6c, 0x6c, 0x6f })); // optional<u8string_view>
static_assert(value_test(tds::value{optional<u8string_view>(nullopt)}, tds::sql_type::VARCHAR, true, { })); // optional<u8string_view>
// FIXME - optional<char8_t*>?

static_assert(value_test(tds::value{u"hello"s}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string
static_assert(value_test(tds::value{u"h\u00e9llo"s}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string
static_assert(value_test(tds::value{u"h\U0001f525llo"s}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x3d, 0xd8, 0x25, 0xdd, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string
static_assert(value_test(tds::value{u"hello"sv}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string_view
static_assert(value_test(tds::value{u"h\u00e9llo"sv}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string_view
static_assert(value_test(tds::value{u"h\U0001f525llo"sv}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x3d, 0xd8, 0x25, 0xdd, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // u16string_view
static_assert(value_test(tds::value{u"hello"}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // char16_t*
static_assert(value_test(tds::value{u"h\u00e9llo"}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // char16_t*
static_assert(value_test(tds::value{u"h\U0001f525llo"}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x3d, 0xd8, 0x25, 0xdd, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // char16_t*
static_assert(value_test(tds::value{optional<u16string>(u"hello")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string>(u"h\u00e9llo")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string>(u"h\U0001f525llo")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x3d, 0xd8, 0x25, 0xdd, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string>(nullopt)}, tds::sql_type::NVARCHAR, true, { })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string_view>(u"hello")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string_view>(u"h\u00e9llo")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string_view>(u"h\U0001f525llo")}, tds::sql_type::NVARCHAR, false, { 0x68, 0x00, 0x3d, 0xd8, 0x25, 0xdd, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00 })); // optional<u16string>
static_assert(value_test(tds::value{optional<u16string_view>(nullopt)}, tds::sql_type::NVARCHAR, true, { })); // optional<u16string>
// FIXME - optional<char16_t*>?

static_assert(value_test(tds::value{1.0f}, tds::sql_type::FLTN, false, { 0x00, 0x00, 0x80, 0x3f })); // float
static_assert(value_test(tds::value{optional<float>(1.0f)}, tds::sql_type::FLTN, false, { 0x00, 0x00, 0x80, 0x3f })); // optional<float>
static_assert(value_test(tds::value{optional<float>(nullopt)}, tds::sql_type::FLTN, true, { })); // optional<float>
static_assert(value_test(tds::value{1.0}, tds::sql_type::FLTN, false, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f })); // double
static_assert(value_test(tds::value{optional<double>(1.0)}, tds::sql_type::FLTN, false, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f })); // optional<double>
static_assert(value_test(tds::value{optional<double>(nullopt)}, tds::sql_type::FLTN, true, { })); // optional<double>
