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

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include "pushvis.h"
#include "tdscpp.h"
#include "popvis.h"
#include <sstream>
#include <iomanip>
#include "config.h"
extern "C" {
#include "tds.h"
#include "convert.h"
}
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

using namespace std;

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)((uint8_t*)(address) - (uintptr_t)(&((type *)0)->field)))
#endif

#include "pushvis.h"
struct conn_context {
	struct tds_context ctx;
	tds::Conn* conn;
};
#include "popvis.h"

namespace tds {
	Conn::Conn(const string& server, const string& username, const string& password, const string& app,
			   const msg_handler& message_handler, const msg_handler& error_handler,
			   const tbl_handler& table_handler, const tbl_row_handler& row_handler) {
#ifdef _WIN32
		if (tds_socket_init())
			throw runtime_error("tds_socket_init failed.");
#endif

		login = tds_alloc_login(1);
		if (!login)
			throw runtime_error("tds_alloc_login failed.");

		try {
			{
				struct tds_context* ctx;

				ctx = tds_alloc_context(nullptr);
				if (!ctx)
					throw runtime_error("tds_alloc_context failed.");

				auto ctx2 = (conn_context*)malloc(sizeof(conn_context));

				if (!ctx2) {
					tds_free_context(ctx);
					throw runtime_error("Out of memory.");
				}

				memcpy(&ctx2->ctx, ctx, sizeof(struct tds_context));
				ctx2->conn = this;

				context = (tds_context*)ctx2;

				free(ctx);
			}

			if (context->locale && !context->locale->date_fmt)
				context->locale->date_fmt = strdup(STD_DATETIME_FMT);

			try {
				this->message_handler = message_handler;
				this->error_handler = error_handler;
				this->table_handler = table_handler;
				this->row_handler = row_handler;

				context->msg_handler = [](const TDSCONTEXT* context, TDSSOCKET* sock, TDSMESSAGE* msg) {
					auto cc = (conn_context*)context;

					return cc->conn->handle_msg(msg);
				};

				context->err_handler = [](const TDSCONTEXT* context, TDSSOCKET* sock, TDSMESSAGE* msg) {
					auto cc = (conn_context*)context;

					return cc->conn->handle_err(msg);
				};

				if (!tds_set_server(login, server.c_str()))
					throw runtime_error("tds_set_server failed.");

				if (!tds_set_user(login, username.c_str()))
					throw runtime_error("tds_set_user failed.");

				if (!tds_set_passwd(login, password.c_str()))
					throw runtime_error("tds_set_passwd failed.");

				if (!tds_set_client_charset(login, "UTF-8"))
					throw runtime_error("tds_set_client_charset failed.");

				if (!app.empty()) {
					if (!tds_set_app(login, app.c_str()))
						throw runtime_error("tds_set_app failed.");
				}

				sock = tds_alloc_socket(context, 512);
				if (!sock)
					throw runtime_error("tds_alloc_socket failed.");

				try {
					auto con = tds_read_config_info(sock, login, context->locale);
					if (!con)
						throw runtime_error("tds_read_config_info failed.");

					if (TDS_FAILED(tds_connect_and_login(sock, con))) {
						tds_free_login(con);
						throw runtime_error("tds_connect_and_login failed.");
					}

					tds_free_login(con);
				} catch (...) {
					tds_free_socket(sock);
					throw;
				}
			} catch (...) {
				tds_free_context(context);
				throw;
			}
		} catch (...) {
			tds_free_login(login);
			throw;
		}
	}

	Conn::~Conn() {
		if (sock)
			tds_free_socket(sock);

		if (context)
			tds_free_context(context);

		if (login)
			tds_free_login(login);
	}

	uint16_t Conn::spid() const {
		return sock->conn->spid;
	}

	void Conn::kill() {
		if (sock->conn->s != INVALID_SOCKET)
#ifdef _WIN32
			closesocket(sock->conn->s);
#else
			close(sock->conn->s);
#endif
	}

	int Conn::handle_msg(struct tds_message* msg) {
		try {
			if (message_handler) {
				message_handler(msg->server ? msg->server : "", msg->message ? msg->message : "", msg->proc_name ? msg->proc_name : "",
								msg->sql_state ? msg->sql_state : "", msg->msgno, msg->line_number, msg->state, msg->priv_msg_type,
								msg->severity, msg->oserr);
			} else {
				if (msg->severity > 10)
					throw runtime_error(msg->message);
			}
		} catch (...) {
			if (in_dtor == 0)
				throw;
		}

		return 0;
	}

	int Conn::handle_err(struct tds_message* msg) {
		if (error_handler) {
			error_handler(msg->server ? msg->server : "", msg->message ? msg->message : "", msg->proc_name ? msg->proc_name : "",
						  msg->sql_state ? msg->sql_state : "", msg->msgno, msg->line_number, msg->state, msg->priv_msg_type,
						  msg->severity, msg->oserr);
		} else {
			if (msg->severity > 10)
				throw runtime_error(msg->message);
		}

		return 0;
	}

	Proc::Proc(const Conn& tds, const string& q, const function<void(uint64_t)>& rows_func) {
		TDSRET rc;
		TDS_INT result_type;

		rc = tds_submit_query(tds.sock, q.c_str());
		if (TDS_FAILED(rc))
			throw runtime_error("tds_submit_query failed.");

		while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, TDS_TOKEN_RESULTS)) == TDS_SUCCESS) {
			const int stop_mask = TDS_STOPAT_ROWFMT | TDS_RETURN_DONE | TDS_RETURN_ROW | TDS_RETURN_COMPUTE;

			switch (result_type) {
				case TDS_COMPUTE_RESULT:
				case TDS_ROW_RESULT:
					while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, stop_mask)) == TDS_SUCCESS) {
						if (result_type != TDS_ROW_RESULT && result_type != TDS_COMPUTE_RESULT)
							break;

						if (!tds.sock->current_results)
							continue;
					}
					break;

				case TDS_DONE_RESULT:
					if (rows_func && tds.sock->rows_affected != TDS_NO_COUNT)
						rows_func(tds.sock->rows_affected);
				break;

				default:
					break;
			}
		}

		if (TDS_FAILED(rc))
			throw runtime_error("tds_process_tokens failed.");
	}

	Field::operator int64_t() const {
		if (null)
			return 0;

		switch (type) {
			case server_type::SYBMSDATE:
			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
				return date.dn;

			case server_type::SYBMSTIME:
				return 0;

			case server_type::SYBFLT8:
			case server_type::SYBFLTN:
				return static_cast<int64_t>(doubval);

			case server_type::SYBINTN:
			case server_type::SYBBITN:
				return intval;

			default:
				return stoll(operator string());
		}
	}

	Field::operator double() const {
		if (null)
			return 0.0f;

		switch (type) {
			case server_type::SYBFLT8:
			case server_type::SYBFLTN:
				return doubval;

			case server_type::SYBMSDATE:
			case server_type::SYBINTN:
			case server_type::SYBBITN:
				return static_cast<double>(operator int64_t());

			case server_type::SYBMSTIME:
				return static_cast<double>((time.h * 3600) + (time.m * 60) + time.s) / 86400.0;

			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
				return static_cast<double>(date.dn) + static_cast<double>((time.h * 3600) + (time.m * 60) + time.s) / 86400.0;

			default:
				return stod(operator string());
		}
	}

	Field::operator string() const {
		if (null)
			return "";

		switch (type) {
			case server_type::SYBINTN:
				return to_string(operator int64_t());

			case server_type::SYBMSDATE:
				return date.to_string();

			case server_type::SYBMSTIME:
				return time.to_string();

			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
				return date.to_string() + " " + time.to_string();

			case server_type::SYBFLT8:
			case server_type::SYBFLTN:
				return to_string(doubval);

			case server_type::SYBBITN:
				return intval ? "true" : "false";

			default:
				return strval;
		}
	}

	Field::operator Date() const {
		switch (type) {
			case server_type::SYBMSDATE:
			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
				return date;

			default:
				throw runtime_error("Could not cast field to Date.");
		}
	}

	Field::operator Time() const {
		switch (type) {
			case server_type::SYBMSTIME:
			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
				return time;

			default:
				throw runtime_error("Could not cast field to Time.");
		}
	}

	Field::operator DateTime() const {
		switch (type) {
			case server_type::SYBDATETIME:
			case server_type::SYBDATETIMN:
			{
				DateTime dt;

				dt.d = date;
				dt.t = time;

				return dt;
			}

			case server_type::SYBMSDATE:
			{
				DateTime dt;

				dt.d = date;

				return dt;
			}

			case server_type::SYBMSTIME:
			{
				DateTime dt;

				dt.t = time;

				return dt;
			}

			default:
				throw runtime_error("Could not cast field to DateTime.");
		}
	}

	static string dstr_to_string(DSTR ds) {
		return string(ds->dstr_s, ds->dstr_size);
	}

	void Query::add_param2(unsigned int i, const string_view& param) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], XSYBNVARCHAR);
		params->columns[i]->column_size = static_cast<TDS_INT>(param.size());
		params->columns[i]->column_cur_size = static_cast<TDS_INT>(param.size());
		params->columns[i]->column_varint_size = 8;

		tds_alloc_param_data(params->columns[i]);
		auto blob = (TDSBLOB*)params->columns[i]->column_data;

		blob->textvalue = (TDS_CHAR*)param.data();
	}

	void Query::add_param2(unsigned int i, const binary_string& param) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], XSYBVARBINARY);
		params->columns[i]->column_size = static_cast<TDS_INT>(param.s.size());
		params->columns[i]->column_cur_size = static_cast<TDS_INT>(param.s.size());
		params->columns[i]->column_varint_size = 8;

		tds_alloc_param_data(params->columns[i]);
		auto blob = (TDSBLOB*)params->columns[i]->column_data;

		blob->textvalue = (TDS_CHAR*)param.s.data();
	}

	void Query::add_param2(unsigned int i, int64_t v) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], SYBINT8);
		params->columns[i]->column_cur_size = sizeof(v);

		tds_alloc_param_data(params->columns[i]);
		memcpy(params->columns[i]->column_data, &v, sizeof(v));
	}

	void Query::add_param2(unsigned int i, const Param& p) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], SYBVARCHAR);

		if (p.null) {
			params->columns[i]->column_size = -1;
			params->columns[i]->column_cur_size = -1;
		} else {
			params->columns[i]->column_size = static_cast<TDS_INT>(p.s.size());
			params->columns[i]->column_cur_size = static_cast<TDS_INT>(p.s.size());
		}

		tds_alloc_param_data(params->columns[i]);
		memcpy(params->columns[i]->column_data, p.s.c_str(), p.s.size());
	}

	void Query::add_param2(unsigned int i, nullptr_t) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], SYBVARCHAR);

		params->columns[i]->column_size = -1;
		params->columns[i]->column_cur_size = -1;

		tds_alloc_param_data(params->columns[i]);
	}

	void Query::add_param2(unsigned int i, double d) {
		TDSPARAMINFO* params;

		params = tds_alloc_param_result(dyn_params);
		if (!params)
			throw runtime_error("tds_alloc_param_result failed.");

		dyn_params = params;
		tds_set_param_type(tds.sock->conn, params->columns[i], SYBFLT8);

		params->columns[i]->column_size = sizeof(double);
		params->columns[i]->column_cur_size = sizeof(double);

		tds_alloc_param_data(params->columns[i]);
		memcpy(params->columns[i]->column_data, &d, sizeof(d));
	}

	void Query::add_param2(unsigned int i, const vector<string>& v) {
		for (const auto& s : v) {
			add_param2(i, s);
			i++;
		}
	}

	void Query::end_query(const std::string& q) {
		TDSRET rc;
		TDS_INT result_type;

		rc = tds_submit_prepare(tds.sock, q.c_str(), nullptr, &dyn, dyn_params);
		if (TDS_FAILED(rc))
			throw runtime_error("tds_submit_prepare failed.");

		while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, TDS_TOKEN_RESULTS)) == TDS_SUCCESS) {
		}

		dyn->params = dyn_params;

		rc = tds_submit_execute(tds.sock, dyn);
		if (TDS_FAILED(rc))
			throw runtime_error("tds_submit_execute failed.");
	}

	bool Query::fetch_row(bool call_callbacks) {
		TDSRET rc;
		TDS_INT result_type;

		while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, TDS_TOKEN_RESULTS)) == TDS_SUCCESS) {
			const int stop_mask = TDS_STOPAT_ROWFMT | TDS_RETURN_DONE | TDS_RETURN_ROW | TDS_RETURN_COMPUTE;

			switch (result_type) {
				case TDS_ROWFMT_RESULT:
				{
					vector<pair<string, server_type>> ls;

					cols.clear();
					cols.reserve(tds.sock->current_results->num_cols);

					for (unsigned int i = 0; i < tds.sock->current_results->num_cols; i++) {
						string name = dstr_to_string(tds.sock->current_results->columns[i]->column_name);

						cols.emplace_back(name, (server_type)tds.sock->current_results->columns[i]->column_type);

						if (call_callbacks && tds.table_handler)
							ls.emplace_back(name, (server_type)tds.sock->current_results->columns[i]->column_type);
					}

					if (call_callbacks && tds.table_handler)
						tds.table_handler(ls);

					break;
				}

				case TDS_COMPUTE_RESULT:
				case TDS_ROW_RESULT:
					if ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, stop_mask)) == TDS_SUCCESS) {
						for (unsigned int i = 0; i < tds.sock->current_results->num_cols; i++) {
							auto& col = tds.sock->current_results->columns[i];

							// FIXME - other types
							cols[i].null = col->column_cur_size < 0;

							if (!cols[i].null) {
								if (cols[i].type == server_type::SYBVARCHAR || cols[i].type == server_type::SYBVARBINARY || cols[i].type == server_type::SYBBINARY) {
									if (is_blob_col(col)) {
										char* s = *(char**)col->column_data;

										cols[i].strval = string(s, col->column_cur_size);
									} else
										cols[i].strval = string(reinterpret_cast<char*>(col->column_data), col->column_cur_size);
								} else if (cols[i].type == server_type::SYBINTN) {
									if (col->column_cur_size == 8) // BIGINT
										cols[i].intval = *reinterpret_cast<int64_t*>(col->column_data);
									else if (col->column_cur_size == 4) // INT
										cols[i].intval = *reinterpret_cast<int32_t*>(col->column_data);
									else if (col->column_cur_size == 2) // SMALLINT
										cols[i].intval = *reinterpret_cast<int16_t*>(col->column_data);
									else if (col->column_cur_size == 1) // TINYINT
										cols[i].intval = *reinterpret_cast<uint8_t*>(col->column_data);
								} else if (cols[i].type == server_type::SYBMSDATE) {
									auto tdta = reinterpret_cast<TDS_DATETIMEALL*>(col->column_data);

									cols[i].date = Date(tdta->date);
								} else if (cols[i].type == server_type::SYBMSTIME) {
									auto tdta = reinterpret_cast<TDS_DATETIMEALL*>(col->column_data);

									unsigned long long tm = tdta->time / 10000000;

									cols[i].time = Time(static_cast<uint8_t>(tm / 3600), (tm / 60) % 60, tm % 60);
								} else if (cols[i].type == server_type::SYBDATETIME || cols[i].type == server_type::SYBDATETIMN) {
									auto tdt = reinterpret_cast<TDS_DATETIME*>(col->column_data);

									cols[i].date = Date(tdt->dtdays);

									unsigned int tm = tdt->dttime / 300;

									cols[i].time = Time(tm / 3600, (tm / 60) % 60, tm % 60);
								} else if (cols[i].type == server_type::SYBFLTN && col->column_cur_size == 4) {
									cols[i].doubval = *reinterpret_cast<float*>(col->column_data);
								} else if (cols[i].type == server_type::SYBFLT8 || (cols[i].type == server_type::SYBFLTN && col->column_cur_size == 8)) {
									cols[i].doubval = *reinterpret_cast<double*>(col->column_data);
								} else if (cols[i].type == server_type::SYBBITN) {
									cols[i].intval = col->column_data[0] & 0x1;
								} else {
									CONV_RESULT cr;
									TDS_INT len;
									TDS_SERVER_TYPE ctype;

									ctype = tds_get_conversion_type(col->column_type, col->column_size);

									len = tds_convert(tds.sock->conn->tds_ctx, ctype, (TDS_CHAR*)col->column_data,
													  col->column_cur_size, SYBVARCHAR, &cr);

									if (len < 0)
										throw runtime_error("Failed converting type " + to_string((unsigned int)cols[i].type) + " to string.");

									try {
										cols[i].strval = string(cr.c, len);

										free(cr.c);
									} catch (...) {
										free(cr.c);
										throw;
									}
								}
							}
						}

						if (call_callbacks && tds.row_handler)
							tds.row_handler(cols);

						return true;
					}

				default:
					break;
			}
		}

		return false;
	}

	Query::~Query() {
		TDSRET rc;
		TDS_INT result_type;

		tds.in_dtor++;

		while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, TDS_TOKEN_RESULTS)) == TDS_SUCCESS) {
			const int stop_mask = TDS_STOPAT_ROWFMT | TDS_RETURN_DONE | TDS_RETURN_ROW | TDS_RETURN_COMPUTE;

			switch (result_type) {
				case TDS_COMPUTE_RESULT:
				case TDS_ROW_RESULT:
					while ((rc = tds_process_tokens(tds.sock, &result_type, nullptr, stop_mask)) == TDS_SUCCESS) {
						if (result_type != TDS_ROW_RESULT && result_type != TDS_COMPUTE_RESULT)
							break;

						if (!tds.sock->current_results)
							continue;
					}
					break;

				default:
					break;
			}
		}

		tds_release_cur_dyn(tds.sock);

		tds.in_dtor--;
	}

	Date::Date(unsigned int year, unsigned int month, unsigned int day) {
		int m2 = ((int)month - 14) / 12;
		long long n;

		n = (1461 * ((int)year + 4800 + m2)) / 4;
		n += (367 * ((int)month - 2 - (12 * m2))) / 12;
		n -= (3 * (((int)year + 4900 + m2)/100)) / 4;
		n += day;
		n -= 2447096;

		dn = static_cast<int>(n);
	}

	void Date::calc_date() const {
		signed long long j, e, f, g, h;

		j = dn + 2415021;

		f = (4 * j) + 274277;
		f /= 146097;
		f *= 3;
		f /= 4;
		f += j;
		f += 1363;

		e = (4 * f) + 3;
		g = (e % 1461) / 4;
		h = (5 * g) + 2;

		D = ((h % 153) / 5) + 1;
		M = ((h / 153) + 2) % 12 + 1;
		Y = static_cast<unsigned int>((e / 1461) - 4716 + ((14 - M) / 12));
	}

	unsigned int Date::year() const {
		if (!date_calculated) {
			calc_date();
			date_calculated = true;
		}

		return Y;
	}

	unsigned int Date::month() const {
		if (!date_calculated) {
			calc_date();
			date_calculated = true;
		}

		return M;
	}

	unsigned int Date::day() const {
		if (!date_calculated) {
			calc_date();
			date_calculated = true;
		}

		return D;
	}

	string Date::to_string() const {
		auto y = year();
		auto m = month();
		auto d = day();

		char s[11];

		s[0] = '0' + ((y / 1000) % 10);
		s[1] = '0' + ((y / 100) % 10);
		s[2] = '0' + ((y / 10) % 10);
		s[3] = '0' + (y % 10);
		s[4] = '-';
		s[5] = '0' + ((m / 10) % 10);
		s[6] = '0' + (m % 10);
		s[7] = '-';
		s[8] = '0' + ((d / 10) % 10);
		s[9] = '0' + (d % 10);
		s[10] = 0;

		return s;
	}

	string Time::to_string() const {
		char str[9];

		str[0] = '0' + ((h / 10) % 10);
		str[1] = '0' + (h % 10);
		str[2] = ':';
		str[3] = '0' + ((m / 10) % 10);
		str[4] = '0' + (m % 10);
		str[5] = ':';
		str[6] = '0' + ((s / 10) % 10);
		str[7] = '0' + (s % 10);
		str[8] = 0;

		return str;
	}

	string DateTime::to_string() const {
		return d.to_string() + "T" + t.to_string();
	}

	Trans::Trans(const Conn& tds) : sock(tds.sock) {
		if (TDS_FAILED(tds_submit_begin_tran(sock)))
			throw runtime_error("tds_submit_begin_tran failed.");

		if (TDS_FAILED(tds_process_simple_query(sock)))
			throw runtime_error("tds_process_simple_query failed.");
	}

	Trans::~Trans() {
		if (!committed) {
			if (TDS_SUCCEED(tds_submit_rollback(sock, 0))) {
				tds_process_simple_query(sock);
			}
		}
	}

	void Trans::commit() {
		if (TDS_FAILED(tds_submit_commit(sock, 0)))
			throw runtime_error("tds_submit_commit failed.");

		if (TDS_FAILED(tds_process_simple_query(sock)))
			throw runtime_error("tds_process_simple_query failed.");

		committed = true;
	}

	int Conn::bcp_get_column_data(TDSCOLUMN* bindcol, int offset) {
		if (bindcol->column_bindlen == 0) {
			bindcol->bcp_column_data->datalen = 0;
			bindcol->bcp_column_data->is_null = bindcol->column_nullable;
			return TDS_SUCCESS;
		}

		unsigned int n = bindcol->column_bindlen - 1;
		auto dest_type = tds_get_conversion_type(bindcol->column_type, bindcol->column_size);
		bool variable = is_variable_type(dest_type);
		const auto& v = (*bcp_data)[offset][n];

		if (!v.has_value() && bindcol->column_nullable) {
			bindcol->bcp_column_data->datalen = 0;
			bindcol->bcp_column_data->is_null = true;
			return TDS_SUCCESS;
		}

		bindcol->bcp_column_data->is_null = 0;

		if (!v.has_value())
			bindcol->bcp_column_data->datalen = 0;
		else if (variable) {
			CONV_RESULT cr;

			if (tds_convert(sock->conn->tds_ctx, SYBVARCHAR, v->c_str(), static_cast<TDS_UINT>(v->length()), dest_type, &cr) < 0)
				throw runtime_error("tds_convert failed.");

			free(bindcol->bcp_column_data->data);
			bindcol->bcp_column_data->data = (TDS_UCHAR*)cr.c;
			bindcol->bcp_column_data->datalen = static_cast<TDS_INT>(v->length());
		} else {
			if (tds_convert(sock->conn->tds_ctx, SYBVARCHAR, v->c_str(), static_cast<TDS_UINT>(v->length()), dest_type, (CONV_RESULT*)bindcol->bcp_column_data->data) < 0)
				throw runtime_error("tds_convert failed.");

			bindcol->bcp_column_data->datalen = bindcol->column_size;
		}

		return TDS_SUCCESS;
	}

#include "pushvis.h"
	struct bcp_holder {
		struct tds_bcpinfo bcpinfo;
		Conn* conn;
	};
#include "popvis.h"

	void Conn::bcp(const string_view& table, const vector<string>& np, const vector<vector<optional<string>>>& vp) {
		bcp_holder bcph;

		memset(&bcph.bcpinfo, 0, sizeof(struct tds_bcpinfo));
		bcph.conn = this;

		tds_dstr_init(&bcph.bcpinfo.tablename);

		bcph.bcpinfo.direction = TDS_BCP_IN;
		bcph.bcpinfo.bind_count = 0;

		if (!tds_dstr_copyn(&bcph.bcpinfo.tablename, table.data(), table.length()))
			throw runtime_error("tds_dstr_copyn failed.");

		if (TDS_FAILED(tds_bcp_init(sock, &bcph.bcpinfo)))
			throw runtime_error("tds_bcp_init failed.");

		try {
			unsigned int i = 0;
			for (const auto& n : np) {
				bool found = false;

				for (unsigned int j = 0; j < bcph.bcpinfo.bindinfo->num_cols; j++) {
					if (bcph.bcpinfo.bindinfo->columns[j]->column_name->dstr_size == n.length() && !memcmp(bcph.bcpinfo.bindinfo->columns[j]->column_name->dstr_s, n.c_str(), n.length())) {
						found = true;
						bcph.bcpinfo.bindinfo->columns[j]->column_bindlen = i + 1;
						break;
					}
				}

				if (!found)
					throw runtime_error("Could not find column \"" + n + "\".");

				i++;
			}

			if (TDS_FAILED(tds_bcp_start_copy_in(sock, &bcph.bcpinfo)))
				throw runtime_error("tds_bcp_start_copy_in failed.");

			bcp_names = np;
			bcp_data = &vp;

			auto gcd = [](TDSBCPINFO* bcpinfo, TDSCOLUMN* bindcol, int offset) {
				auto bcph = CONTAINING_RECORD(bcpinfo, struct bcp_holder, bcpinfo);

				return bcph->conn->bcp_get_column_data(bindcol, offset);
			};

			for (unsigned int i = 0; i < vp.size(); i++) {
				if (TDS_FAILED(tds_bcp_send_record(sock, &bcph.bcpinfo, gcd, nullptr, i)))
					throw runtime_error("tds_bcp_send_record failed.");
			}

			int rows_copied;
			if (TDS_FAILED(tds_bcp_done(sock, &rows_copied)))
				throw runtime_error("tds_bcp_done failed.");
		} catch (...) {
			tds_deinit_bcpinfo(&bcph.bcpinfo);
			throw;
		}

		tds_deinit_bcpinfo(&bcph.bcpinfo);
	}
}
