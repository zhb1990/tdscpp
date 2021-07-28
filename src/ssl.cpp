#include "tdscpp.h"
#include "tdscpp-private.h"

using namespace std;

static const char PREFERRED_CIPHERS[] = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

class ssl_error : public exception {
public:
    ssl_error(const char* func, unsigned long err) {
        auto str = ERR_reason_error_string(err);

        if (str)
            msg = str;
        else
            msg = func + " failed: "s + to_string(err);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

static int ssl_bio_read(BIO* bio, char* data, int len) noexcept {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    try {
        return t.ssl_read_cb(data, len);
    } catch (...) {
        t.exception = current_exception();
        return -1;
    }
}

static int ssl_bio_write(BIO* bio, const char* data, int len) noexcept {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    try {
        return t.ssl_write_cb(string_view{data, (size_t)len});
    } catch (...) {
        t.exception = current_exception();
        return -1;
    }
}

static long ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) noexcept {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    try {
        return t.ssl_ctrl_cb(cmd, num, ptr);
    } catch (...) {
        t.exception = current_exception();
        return -1;
    }
}

namespace tds {
    int tds_ssl::ssl_read_cb(char* data, int len) {
        int copied = 0;

        if (len == 0)
            return 0;

        if (!ssl_recv_buf.empty()) {
            auto to_copy = min(len, (int)ssl_recv_buf.length());

            memcpy(data, ssl_recv_buf.data(), to_copy);
            ssl_recv_buf = ssl_recv_buf.substr(to_copy);

            if (len == to_copy)
                return len;

            len -= to_copy;
            copied = to_copy;
            data += to_copy;
        }

        if (established) {
            tds.recv_raw((uint8_t*)data, len);
            copied += len;

            return copied;
        } else {
            enum tds_msg type;
            string payload;

            tds.wait_for_msg(type, payload);

            if (type != tds_msg::prelogin)
                throw formatted_error("Received message type {}, expected prelogin", (int)type);

            auto to_copy = min(len, (int)payload.length());

            memcpy(data, payload.data(), to_copy);
            copied += to_copy;

            if (payload.length() > (size_t)to_copy)
                ssl_recv_buf.append(payload.substr(to_copy));

            return copied;
        }
    }

    int tds_ssl::ssl_write_cb(const string_view& sv) {
        if (established)
            tds.send_raw(sv);
        else
            tds.send_msg(tds_msg::prelogin, sv, false);

        return (int)sv.length();
    }

    long tds_ssl::ssl_ctrl_cb(int cmd, long, void*) {
        switch (cmd) {
            case BIO_CTRL_FLUSH:
                return 1;

            case BIO_C_DO_STATE_MACHINE: {
                auto ret = SSL_do_handshake(ssl.get());

                if (ret != 1)
                    throw formatted_error("SSL_do_handshake failed (error {})", SSL_get_error(ssl.get(), ret));

                return 1;
            }
        }

        return 0;
    }

    tds_ssl::tds_ssl(tds_impl& tds) : tds(tds) {
        ctx.reset(SSL_CTX_new(SSLv23_method()));
        if (!ctx)
            throw ssl_error("SSL_CTX_new", ERR_get_error());

        // FIXME - verify certificate?
//         ctx.set_verify(SSL_VERIFY_PEER, verify_callback);
//         ctx.set_verify_depth(5);

        SSL_CTX_set_options(ctx.get(), SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

        meth.reset(BIO_meth_new(BIO_TYPE_MEM, "tdscpp"));
        if (!meth)
            throw ssl_error("BIO_meth_new", ERR_get_error());

        BIO_meth_set_read(meth.get(), ssl_bio_read);
        BIO_meth_set_write(meth.get(), ssl_bio_write);
        BIO_meth_set_ctrl(meth.get(), ssl_bio_ctrl);
        BIO_meth_set_destroy(meth.get(), [](BIO*) {
            return 1;
        });

        bio = BIO_new(meth.get());
        if (!bio)
            throw ssl_error("BIO_new", ERR_get_error());

        BIO_set_data(bio, this);

        ssl.reset(SSL_new(ctx.get()));
        if (!ssl) {
            BIO_free_all(bio);
            throw ssl_error("SSL_new", ERR_get_error());
        }

        SSL_set_bio(ssl.get(), bio, bio);

        if (SSL_set_cipher_list(ssl.get(), PREFERRED_CIPHERS) != 1)
            throw ssl_error("SSL_set_cipher_list", ERR_get_error());

        // FIXME - SSL_set_tlsext_host_name?

        SSL_set_connect_state(ssl.get());

        SSL_connect(ssl.get());
        if (exception)
            rethrow_exception(exception);

        if (BIO_do_connect(bio) != 1) {
            if (exception)
                rethrow_exception(exception);

            throw ssl_error("BIO_do_connect", ERR_get_error());
        }

        if (BIO_do_handshake(bio) != 1) {
            if (exception)
                rethrow_exception(exception);

            throw ssl_error("BIO_do_handshake", ERR_get_error());
        }

        established = true;
    }

    void tds_ssl::send(std::string_view sv) {
        while (!sv.empty()) {
            auto ret = SSL_write(ssl.get(), sv.data(), (int)sv.length());

            if (ret <= 0) {
                if (exception)
                    rethrow_exception(exception);

                throw formatted_error("SSL_write failed (error {})", SSL_get_error(ssl.get(), ret));
            }

            sv = sv.substr(ret);
        }
    }

    void tds_ssl::recv(uint8_t* ptr, size_t left) {
        while (left > 0) {
            auto ret = SSL_read(ssl.get(), ptr, (int)left);

            if (ret <= 0) {
                if (exception)
                    rethrow_exception(exception);

                throw formatted_error("SSL_read failed (error {})", SSL_get_error(ssl.get(), ret));
            }

            ptr += ret;
            left -= ret;
        }
    }
};
