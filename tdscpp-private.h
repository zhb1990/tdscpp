#pragma once

#include "tdscpp.h"

struct tds_context;
struct tds_message;
struct tds_login;
struct tds_column;
struct tds_bcpinfo;

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
};
