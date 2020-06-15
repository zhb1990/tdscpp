#include "tdscpp.h"
#include <iostream>

using namespace std;

void message_handler(const string_view& server, const string_view& message, const string_view& proc_name,
					const string_view& sql_state, int32_t msgno, int32_t line_number, int16_t state,
					uint8_t priv_msg_type, uint8_t severity, int oserr) {
	if (msgno == 5701) // Skip "Changed database context to 'master'"
		return;

	if (msgno == 5703) // Skip "Changed language setting to us_english"
		return;

	if (severity > 10)
		cout << "\x1b[31;1mError " << msgno << ": " << message << "\x1b[0m" << endl;
	else if (msgno == 50000) // match SSMS by not displaying message no. if 50000 (RAISERROR etc.)
		cout << message << endl;
	else
		cout << msgno << ": " << message << endl;
}

template<typename... Args>
static void do_query(tds::Conn& conn, const string& q, Args... args) {
	tds::Query sq(conn, q, forward<Args>(args)...);

	bool b = sq.fetch_row();

	for (size_t i = 0; i < sq.num_columns(); i++) {
		cout << sq[i].name << "\t";
	}
	cout << endl;

	while (b) {
		for (size_t i = 0; i < sq.num_columns(); i++) {
			cout << (string)sq[i] << "\t";
		}
		cout << endl;

		b = sq.fetch_row();
	}
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

		tds::Conn conn(server, username, password, "test program", message_handler);

		do_query(conn, "SELECT SYSTEM_USER AS [user], ? AS answer, ? AS greeting, GETDATE() AS now, ? AS pi", 42, "Hello"s, 3.1415926f);

		conn.run("RAISERROR('Hello, world!', 0, 1)");

		conn.run("DROP TABLE IF EXISTS dbo.test;");
		conn.run("CREATE TABLE dbo.test(a INT);");

		conn.bcp("dbo.test", {"a"}, {{"229"}, {"171"}});

		do_query(conn, "SELECT a FROM dbo.test");
	} catch (const exception& e) {
		cerr << e.what() << endl;
	}

	return 0;
}
