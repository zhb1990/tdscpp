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

class ssl_ctx {
public:
    ssl_ctx(const SSL_METHOD* method) {
        ctx = SSL_CTX_new(method);
        if (!ctx)
            throw ssl_error("SSL_CTX_new", ERR_get_error());
    }

    ~ssl_ctx() {
        SSL_CTX_free(ctx);
    }

    void set_verify(int mode, SSL_verify_cb verify_callback) noexcept {
        SSL_CTX_set_verify(ctx, mode, verify_callback);
    }

    void set_verify_depth(int depth) noexcept {
        SSL_CTX_set_verify_depth(ctx, depth);
    }

    long set_options(long options) noexcept {
        return SSL_CTX_set_options(ctx, options);
    }

    operator SSL_CTX*() noexcept {
        return ctx;
    }

private:
    SSL_CTX* ctx;
};

static int ssl_bio_read(BIO* bio, char* data, int len) {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    return t.ssl_read_cb(data, len);
}

static int ssl_bio_write(BIO* bio, const char* data, int len) {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    return t.ssl_write_cb(string_view{data, (size_t)len});
}

static long ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) {
    auto& t = *(tds::tds_ssl*)BIO_get_data(bio);

    return t.ssl_ctrl_cb(cmd, num, ptr);
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

        // FIXME - don't throw exceptions

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

    int tds_ssl::ssl_write_cb(const string_view& sv) {
        // FIXME - don't throw exceptions

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
                auto ret = SSL_do_handshake(ssl);

                if (ret != 1)
                    throw formatted_error("SSL_do_handshake failed (error {})", SSL_get_error(ssl, ret));

                return 1;
            }
        }

        return 0;
    }

    tds_ssl::tds_ssl(tds_impl& tds) : tds(tds) {
        ssl_ctx ctx(SSLv23_method());

        // FIXME - verify certificate?
//         ctx.set_verify(SSL_VERIFY_PEER, verify_callback);
//         ctx.set_verify_depth(5);

        ctx.set_options(SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

        auto meth = BIO_meth_new(BIO_TYPE_MEM, "tdscpp"); // FIXME - free with BIO_meth_free?
        if (!meth)
            throw ssl_error("BIO_meth_new", ERR_get_error());

        BIO_meth_set_read(meth, ssl_bio_read);
        BIO_meth_set_write(meth, ssl_bio_write);
        BIO_meth_set_ctrl(meth, ssl_bio_ctrl);
        BIO_meth_set_destroy(meth, [](BIO*) {
            return 1;
        });

        bio.reset(BIO_new(meth));
        if (!bio)
            throw ssl_error("BIO_new", ERR_get_error());

        BIO_set_data(bio.get(), this);

        ssl = SSL_new(ctx); // FIXME - free
        if (!ssl)
            throw ssl_error("SSL_new", ERR_get_error());

        SSL_set_bio(ssl, bio.get(), bio.get());

        if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1)
            throw ssl_error("SSL_set_cipher_list", ERR_get_error());

        // FIXME - SSL_set_tlsext_host_name?

        SSL_set_connect_state(ssl);
        SSL_connect(ssl);

        if (BIO_do_connect(bio.get()) != 1)
            throw ssl_error("BIO_do_connect", ERR_get_error());

        if (BIO_do_handshake(bio.get()) != 1)
            throw ssl_error("BIO_do_handshake", ERR_get_error());

        established = true;
    }

    void tds_ssl::send(std::string_view sv) {
        while (!sv.empty()) {
            auto ret = SSL_write(ssl, sv.data(), (int)sv.length());

            if (ret <= 0)
                throw formatted_error("SSL_write failed (error {})", SSL_get_error(ssl, ret));

            sv = sv.substr(ret);
        }
    }
};
