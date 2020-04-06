/* Copyright (c) Mark Harmstone 2020
 *
 * This file is part of tdscpp.
 *
 * tdscpp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * tdscpp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with tdscpp.  If not, see <http://www.gnu.org/licenses/>. */

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <functional>

struct tds_context;
struct tds_socket;
struct tds_message;
struct tds_login;
struct tds_column;
struct tds_dynamic;
struct tds_bcpinfo;
struct tds_result_info;

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace tds {
	typedef std::function<void(const std::string_view& server, const std::string_view& message, const std::string_view& proc_name,
							    const std::string_view& sql_state, int32_t msgno, int32_t line_number, int16_t state, uint8_t priv_msg_type,
							    uint8_t severity, int oserr)> msg_handler;

	// taken from freetds
	enum class server_type {
		SYBCHAR = 47,		/* 0x2F */
		SYBVARCHAR = 39,	/* 0x27 */
		SYBINTN = 38,		/* 0x26 */
		SYBINT1 = 48,		/* 0x30 */
		SYBINT2 = 52,		/* 0x34 */
		SYBINT4 = 56,		/* 0x38 */
		SYBFLT8 = 62,		/* 0x3E */
		SYBDATETIME = 61,	/* 0x3D */
		SYBBIT = 50,		/* 0x32 */
		SYBTEXT = 35,		/* 0x23 */
		SYBNTEXT = 99,		/* 0x63 */
		SYBIMAGE = 34,		/* 0x22 */
		SYBMONEY4 = 122,	/* 0x7A */
		SYBMONEY = 60,		/* 0x3C */
		SYBDATETIME4 = 58,	/* 0x3A */
		SYBREAL = 59,		/* 0x3B */
		SYBBINARY = 45,		/* 0x2D */
		SYBVOID = 31,		/* 0x1F */
		SYBVARBINARY = 37,	/* 0x25 */
		SYBBITN = 104,		/* 0x68 */
		SYBNUMERIC = 108,	/* 0x6C */
		SYBDECIMAL = 106,	/* 0x6A */
		SYBFLTN = 109,		/* 0x6D */
		SYBMONEYN = 110,	/* 0x6E */
		SYBDATETIMN = 111,	/* 0x6F */

							/*
							* MS only types
							*/
		SYBNVARCHAR = 103,	/* 0x67 */
		SYBINT8 = 127,		/* 0x7F */
		XSYBCHAR = 175,		/* 0xAF */
		XSYBVARCHAR = 167,	/* 0xA7 */
		XSYBNVARCHAR = 231,	/* 0xE7 */
		XSYBNCHAR = 239,	/* 0xEF */
		XSYBVARBINARY = 165,	/* 0xA5 */
		XSYBBINARY = 173,	/* 0xAD */
		SYBUNIQUE = 36,		/* 0x24 */
		SYBVARIANT = 98, 	/* 0x62 */
		SYBMSUDT = 240,		/* 0xF0 */
		SYBMSXML = 241,		/* 0xF1 */
		SYBMSDATE = 40,  	/* 0x28 */
		SYBMSTIME = 41,  	/* 0x29 */
		SYBMSDATETIME2 = 42,  	/* 0x2a */
		SYBMSDATETIMEOFFSET = 43,/* 0x2b */

								 /*
								 * Sybase only types
								 */
		SYBLONGBINARY = 225,	/* 0xE1 */
		SYBUINT1 = 64,		/* 0x40 */
		SYBUINT2 = 65,		/* 0x41 */
		SYBUINT4 = 66,		/* 0x42 */
		SYBUINT8 = 67,		/* 0x43 */
		SYBBLOB = 36,		/* 0x24 */
		SYBBOUNDARY = 104,	/* 0x68 */
		SYBDATE = 49,		/* 0x31 */
		SYBDATEN = 123,		/* 0x7B */
		SYB5INT8 = 191,		/* 0xBF */
		SYBINTERVAL = 46,	/* 0x2E */
		SYBLONGCHAR = 175,	/* 0xAF */
		SYBSENSITIVITY = 103,	/* 0x67 */
		SYBSINT1 = 176,		/* 0xB0 */
		SYBTIME = 51,		/* 0x33 */
		SYBTIMEN = 147,		/* 0x93 */
		SYBUINTN = 68,		/* 0x44 */
		SYBUNITEXT = 174,	/* 0xAE */
		SYBXML = 163,		/* 0xA3 */
		SYB5BIGDATETIME = 187,	/* 0xBB */
		SYB5BIGTIME = 188,	/* 0xBC */
	};

	class Proc;
	class Query;
	class Trans;

	class TDSCPP Conn {
	public:
		Conn(const std::string& server, const std::string& username, const std::string& password, const std::string& app = "",
			 const msg_handler& message_handler = nullptr, const msg_handler& error_handler = nullptr);
		~Conn();
		void bcp(const std::string_view& table, const std::vector<std::string>& np, const std::vector<std::vector<std::optional<std::string>>>& vp);
		uint16_t spid() const;
		void kill();

		template<typename... Args>
		void run(const std::string& s, const Args&... args) const;

		friend Proc;
		friend Query;
		friend Trans;

	private:
		int bcp_get_column_data(struct tds_column* bindcol, int offset);
		int handle_msg(struct tds_message* msg);
		int handle_err(struct tds_message* msg);

		struct tds_login* login = nullptr;
		struct tds_context* context = nullptr;
		struct tds_socket* sock = nullptr;

		std::vector<std::string> bcp_names;
		const std::vector<std::vector<std::optional<std::string>>>* bcp_data;
		msg_handler message_handler;
		msg_handler error_handler;
		mutable int in_dtor = 0;
	};

	class TDSCPP Proc {
	public:
		Proc(const Conn& tds, const std::string& q, const std::function<void(uint64_t)>& rows_func = nullptr);
	};

	class TDSCPP Date {
	public:
		Date() : dn(0) { }
		Date(unsigned int year, unsigned int month, unsigned int day);
		Date(int dn) : dn(dn) { }

		unsigned int year() const;
		unsigned int month() const;
		unsigned int day() const;
		std::string to_string() const;

		int dn;

	private:
		void calc_date() const;

		mutable unsigned int Y, M, D;
		mutable bool date_calculated = false;
	};

	class TDSCPP Time {
	public:
		Time() : h(0), m(0), s(0) { }
		Time(uint8_t hour, uint8_t minute, uint8_t second) : h(hour), m(minute), s(second) { }

		std::string to_string() const;

		uint8_t h, m, s;
	};

	class TDSCPP DateTime {
	public:
		std::string to_string() const;

		Date d;
		Time t;
	};

	class TDSCPP Field {
	public:
		Field(const std::string& name, server_type type) : name(name), type(type) {
		}

		operator std::string() const;
		explicit operator int64_t() const;
		explicit operator double() const;

		explicit operator float() const {
			return (float)operator double();
		}

		explicit operator int32_t() const {
			return (int32_t)operator int64_t();
		}

		explicit operator uint32_t() const {
			return (uint32_t)operator int64_t();
		}

		explicit operator uint16_t() const {
			return (uint16_t)operator int64_t();
		}

		explicit operator Date() const;
		explicit operator Time() const;
		explicit operator DateTime() const;

		operator std::optional<std::string>() const {
			if (null)
				return std::nullopt;
			else
				return operator std::string();
		}

		bool operator==(const std::string& s) const {
			return std::string() == s;
		}

		bool is_null() const {
			return null;
		}

		std::string name;
		server_type type;

		friend Query;

	private:
		std::string strval;
		int64_t intval;
		Date date;
		Time time;
		double doubval;
		bool null;
	};

	class TDSCPP Param {
	public:
		Param(const std::string& s) : null(false), s(s) {
		}

		Param(nullptr_t) : null(true) {
		}

		bool null;
		std::string s;
	};

	class binary_string {
	public:
		binary_string(std::string s) {
			this->s = s;
		}

		std::string s;
	};

	class TDSCPP Query {
	public:
		Query(const Conn& tds, const std::string& q) : tds(tds) {
			end_query(q);
		}

		template<typename... Args>
		Query(const Conn& tds, const std::string& q, const Args&... args) : tds(tds) {
			add_param(0, args...);
			end_query(q);
		}

		~Query();

		bool fetch_row();

		const Field& operator[](unsigned int i) const {
			return cols.at(i);
		}

		size_t num_columns() const {
			return cols.size();
		}

	private:
		void add_param2(unsigned int i, const std::string_view& param);
		void add_param2(unsigned int i, int64_t v);
		void add_param2(unsigned int i, const binary_string& bs);
		void add_param2(unsigned int i, const Param& p);
		void add_param2(unsigned int i, const std::vector<std::string>& v);
		void add_param2(unsigned int i, nullptr_t);
		void add_param2(unsigned int i, double f);

		void add_param2(unsigned int i, int32_t v) {
			add_param2(i, (int64_t)v);
		}

		void add_param2(unsigned int i, uint32_t v) {
			add_param2(i, (int64_t)v);
		}

		void add_param2(unsigned int i, const std::string& param) {
			add_param2(i, std::string_view(param));
		}

		template<typename T>
		void add_param2(unsigned int i, const std::optional<T>& t) {
			if (!t.has_value())
				add_param2(i, nullptr);
			else
				add_param2(i, (const T&)t);
		}

		template<typename T>
		void add_param(unsigned int i, const T& param) {
			add_param2(i, param);
		}

		template<typename T, typename... Args>
		void add_param(unsigned int i, const T& param, const Args&... args) {
			add_param2(i, param);
			add_param(i + 1, args...);
		}

		void end_query(const std::string& q);

		std::vector<Field> cols;
		const Conn& tds;
		struct tds_dynamic* dyn = nullptr;
		struct tds_result_info* dyn_params = nullptr;
	};

	template<typename... Args>
	void Conn::run(const std::string& s, const Args&... args) const {
		Query q(*this, s, args...);

		while (q.fetch_row()) { }
	}

	class TDSCPP Trans {
	public:
		Trans(const Conn& tds);
		~Trans();
		void commit();

		bool committed = false;

	private:
		struct tds_socket* sock = nullptr;
	};
}

#ifdef _MSC_VER
#define pragma warning(pop)
#endif
