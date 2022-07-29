#include "tdscpp.h"

#ifndef _WIN32
#include <codecvt>
#endif

using namespace std;

static void show_msg(const string_view&, const string_view& message, const string_view&, int32_t msgno, int32_t, int16_t,
                     uint8_t severity, bool) {
    if (severity > 10)
        fmt::print(FMT_STRING("\x1b[31;1mError {}: {}\x1b[0m\n"), msgno, message);
    else if (msgno == 50000) // match SSMS by not displaying message no. if 50000 (RAISERROR etc.)
        fmt::print(FMT_STRING("{}\n"), message);
    else
        fmt::print(FMT_STRING("{}: {}\n"), msgno, message);
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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tdscpp-test <server> [username] [password]\n");
        return 1;
    }

    try {
        string server = argv[1];
        string username = argc >= 3 ? argv[2] : "";
        string password = argc >= 4 ? argv[3] : "";

        // FIXME - prompt for password if username set but password isn't

        tds::tds n(server, username, password, "test program", "", show_msg);

#if 0
        fmt::print("{}\n", (tds::datetime)tds::value("2020-10-29T01:23:45.0-03:00"));

        fmt::print("{}\n", (tds::date)tds::value("2020-10-29"));
        fmt::print("{}\n", (tds::date)tds::value("29/10/2020"));
        fmt::print("{}\n", (tds::date)tds::value("29/10/20"));
        fmt::print("{}\n", (tds::date)tds::value("29/Oct/2020"));
        fmt::print("{}\n", (tds::date)tds::value("29/Oct/20"));
        fmt::print("{}\n", (tds::date)tds::value("Oct 29, 2020"));
        fmt::print("{}\n", (tds::date)tds::value("Oct 2020"));
        fmt::print("{}\n", (tds::date)tds::value("2000-02-29"));

        fmt::print("{}\n", (tds::time)tds::value("01:23:45.0"));
        fmt::print("{}\n", (tds::time)tds::value("01:23:45"));
        fmt::print("{}\n", (tds::time)tds::value("01:23"));
        fmt::print("{}\n", (tds::time)tds::value("1AM"));
        fmt::print("{}\n", (tds::time)tds::value("2 pm"));
        fmt::print("{}\n", (tds::time)tds::value("2:56:34.0 pm"));
        fmt::print("{}\n", (tds::time)tds::value("2:56:34 pm"));
        fmt::print("{}\n", (tds::time)tds::value("2:56 pm"));
#endif
        {
            tds::query sq(n, "SELECT SYSTEM_USER AS [user], ? AS answer, ? AS greeting, ? AS now, ? AS pi, ? AS test", 42, "Hello", tds::datetimeoffset{2010y, chrono::October, 28d, 17, 58, 50, -360}, 3.1415926f, true);

            for (uint16_t i = 0; i < sq.num_columns(); i++) {
                fmt::print(FMT_STRING("{}\t"), utf16_to_utf8(sq[i].name));
            }
            fmt::print("\n");

            while (sq.fetch_row()) {
                for (uint16_t i = 0; i < sq.num_columns(); i++) {
                    fmt::print(FMT_STRING("{}\t"), sq[i]);
                }
                fmt::print(FMT_STRING("\n"));
            }
        }

        {
            tds::trans t(n);
            tds::trans t2(n);

            n.run("DROP TABLE IF EXISTS dbo.test2; CREATE TABLE dbo.test2(b VARCHAR(10));");

            t2.commit();
            t.commit();
        }

        {
            tds::batch b(n, u"SELECT SYSTEM_USER AS [user], 42 AS answer, @@TRANCOUNT AS tc ORDER BY 1");

            for (uint16_t i = 0; i < b.num_columns(); i++) {
                fmt::print(FMT_STRING("{}\t"), utf16_to_utf8(b[i].name));
            }
            fmt::print("\n");

            while (b.fetch_row()) {
                for (uint16_t i = 0; i < b.num_columns(); i++) {
                    fmt::print(FMT_STRING("{}\t"), b[i]);
                }
                fmt::print(FMT_STRING("\n"));
            }
        }

        {
            tds::query sq(n, "SELECT CONVERT(HIERARCHYID, '/10000000000.20000000000/40000000000.1000000000000/') AS hier, CONVERT(HIERARCHYID, '/10000.20000/40000.1000000/'), CONVERT(HIERARCHYID, '/1998.2001/2077.2101/'), CONVERT(HIERARCHYID, '/80.171/229.1066/'), CONVERT(HIERARCHYID, '/16.21/79/'), CONVERT(HIERARCHYID, '/8.9/10/'), CONVERT(HIERARCHYID, '/4.5/6/'), CONVERT(HIERARCHYID, '/1.2/'), CONVERT(HIERARCHYID, '/-7.-6/-5.-4/'), CONVERT(HIERARCHYID, '/-72.-69/-18.-14/'), CONVERT(HIERARCHYID, '/-3000.-2000/-1000.-100/'), CONVERT(HIERARCHYID, '/-10000.-20000/-40000.-1000000/'), CONVERT(HIERARCHYID, '/-10000000000.-20000000000/-40000000000.-1000000000000/')");

            while (sq.fetch_row()) {
                for (uint16_t i = 0; i < sq.num_columns(); i++) {
                    fmt::print("{}\t", sq[i]);
                }
                fmt::print("\n");
            }
        }

        n.run("RAISERROR('Hello, world!', 0, 1)");

        n.run("DROP TABLE IF EXISTS dbo.test;");
        n.run("CREATE TABLE dbo.test(a VARCHAR(10));");
        n.bcp(u"dbo.test", vector{u"a"}, vector<vector<tds::value>>{{"1"}, {true}, {nullptr}});
    } catch (const exception& e) {
        fmt::print(stderr, FMT_STRING("Exception: {}\n"), e.what());
        return 1;
    }

    return 0;
}
