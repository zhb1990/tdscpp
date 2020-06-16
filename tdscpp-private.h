#pragma once

#include "tdscpp.h"

struct tds_context;
struct tds_message;
struct tds_login;
struct tds_column;
struct tds_bcpinfo;
struct tds_dynamic;
struct tds_result_info;

namespace tds {
	class Conn_impl {
	public:
		Conn_impl(const std::string& server, const std::string& username, const std::string& password, const std::string& app,
			const msg_handler& message_handler, const msg_handler& error_handler,
			const tbl_handler& table_handler, const tbl_row_handler& row_handler,
			const tbl_row_count_handler& row_count_handler);
		~Conn_impl();

		void bcp_get_column_data(struct tds_column* bindcol, int offset);
		int handle_msg(struct tds_message* msg);
		int handle_err(struct tds_message* msg);
		void bcp_send_record(struct tds_bcpinfo* bcpinfo, int offset);
		uint16_t spid() const;
		void kill();

		struct tds_login* login = nullptr;
		struct tds_context* context = nullptr;
		struct tds_socket* sock = nullptr;

		const std::vector<std::vector<std::optional<std::string>>>* bcp_data;
		msg_handler message_handler;
		msg_handler error_handler;
		tbl_handler table_handler;
		tbl_row_handler row_handler;
		tbl_row_count_handler row_count_handler;
		mutable int in_dtor = 0;
	};

	class Query_impl {
	public:
		Query_impl(const Conn& tds) : tds(tds) {
		}

		~Query_impl();

		const Field& operator[](unsigned int i) const {
			return cols.at(i);
		}

		size_t num_columns() const {
			return cols.size();
		}

		void add_param2(unsigned int i, const std::string_view& param);
		void add_param2(unsigned int i, const binary_string& param);
		void add_param2(unsigned int i, int64_t v);
		void add_param2(unsigned int i, nullptr_t);
		void add_param2(unsigned int i, double d);
		void end_query(const std::string& q);
		bool fetch_row(bool call_callbacks);

		const Conn& tds;
		std::vector<Field> cols;
		struct tds_dynamic* dyn = nullptr;
		struct tds_result_info* dyn_params = nullptr;
	};
};
