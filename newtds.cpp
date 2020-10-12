#include <iostream>
#include <string>
#include <fmt/format.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

static const string db_server = "luthien", db_user = "sa", db_password = "Password1$";
static const uint16_t db_port = 1433;

class formatted_error : public exception {
public:
    template<typename T, typename... Args>
    formatted_error(const T& s, Args&&... args) {
        msg = fmt::format(s, forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

enum class newtds_msg : uint8_t {
    sql_batch = 1,
    pretds7_login,
    rpc,
    tabular_result,
    attention_signal = 6,
    bulk_load_data,
    federated_auth_token,
    trans_man_req = 14,
    tds7_login = 16,
    sspi,
    prelogin
};

struct tds_header {
    enum newtds_msg type;
    uint8_t status;
    uint16_t length;
    uint16_t spid;
    uint8_t packet_id;
    uint8_t window;
};

static_assert(sizeof(tds_header) == 8, "tds_header has wrong size");

enum class newtds_login_opt_type : uint8_t {
    version = 0,
    encryption,
    instopt,
    threadid,
    mars,
    traceid,
    fedauthrequired,
    nonceopt,
    terminator = 0xff
};

struct login_opt {
    login_opt(enum newtds_login_opt_type type, const string_view& payload) : type(type), payload(payload) { }

    enum newtds_login_opt_type type;
    string payload;
};

struct login_opt_version {
    uint8_t major;
    uint8_t minor;
    uint16_t build;
    uint16_t subbuild;
};

static_assert(sizeof(login_opt_version) == 6, "login_opt_version has wrong size");

#pragma pack(push,1)

struct tds_login_opt {
    enum newtds_login_opt_type type;
    uint16_t offset;
    uint16_t length;
};

#pragma pack(pop)

static_assert(sizeof(tds_login_opt) == 5, "tds_login_opt has wrong size");

enum class tds_encryption_type : uint8_t {
    ENCRYPT_OFF,
    ENCRYPT_ON,
    ENCRYPT_NOT_SUP,
    ENCRYPT_REQ
};

class newtds {
public:
    newtds(const string& server, uint16_t port, const string_view& user, const string_view& password) {
        connect(server, port);

        send_prelogin_msg();
    }

    ~newtds() {
        if (sock != 0)
            close(sock);
    }

private:
    void connect(const string& server, uint16_t port) {
        struct addrinfo hints;
        struct addrinfo* res;
        struct addrinfo* orig_res;
        int ret;

        // FIXME - make sure this works with both IPv4 and IPv6

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        ret = getaddrinfo(server.c_str(), nullptr, &hints, &res);

        if (ret != 0)
            throw formatted_error(FMT_STRING("getaddrinfo returned {}"), ret);

        orig_res = res;
        sock = 0;

        do {
            sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

            if (sock < 0)
                continue;

            if (res->ai_family == AF_INET)
                ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(port);
            else if (res->ai_family == AF_INET6)
                ((struct sockaddr_in6*)res->ai_addr)->sin6_port = htons(port);
            else {
                close(sock);
                sock = 0;
                continue;
            }

            if (::connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
                close(sock);
                sock = 0;
                continue;
            }

            break;
        } while (res = res->ai_next);

        freeaddrinfo(orig_res);

        if (sock <= 0)
            throw formatted_error(FMT_STRING("Could not connect to {}:{}."), server, port);
    }

    void send_prelogin_msg() {
        string msg;
        vector<login_opt> opts;
        login_opt_version lov;
        size_t size, off;
        enum tds_encryption_type enc;
        uint8_t mars;

        // FIXME - allow the user to specify this
        static const char instance[] = "MSSQLServer";

        // version

        lov.major = 9;
        lov.minor = 0;
        lov.build = 0;
        lov.subbuild = 0;

        opts.emplace_back(newtds_login_opt_type::version, string_view{(char*)&lov, sizeof(lov)});

        // encryption
        // FIXME - actually support encryption

        enc = tds_encryption_type::ENCRYPT_NOT_SUP;

        opts.emplace_back(newtds_login_opt_type::encryption, string_view{(char*)&enc, sizeof(enc)});

        // instopt

        opts.emplace_back(newtds_login_opt_type::instopt, instance);

        // MARS

        mars = 0;
        opts.emplace_back(newtds_login_opt_type::mars, string_view{(char*)&mars, sizeof(mars)});

        size = (sizeof(tds_login_opt) * opts.size()) + sizeof(enum newtds_login_opt_type);
        off = size;

        for (const auto& opt : opts) {
            size += opt.payload.size();
        }

        msg.resize(size);

        auto tlo = (tds_login_opt*)msg.data();

        for (const auto& opt : opts) {
            tlo->type = opt.type;
            tlo->offset = htons(off);
            tlo->length = htons(opt.payload.size());

            memcpy(msg.data() + off, opt.payload.data(), opt.payload.size());
            off += opt.payload.size();

            tlo++;
        }

        tlo->type = newtds_login_opt_type::terminator;

        send_msg(newtds_msg::prelogin, msg);
    }

    void send_msg(enum newtds_msg type, const string_view& msg) {
        string payload;

        payload.resize(msg.length() + sizeof(tds_header));

        auto h = (tds_header*)payload.data();

        h->type = type;
        h->status = 1; // last message
        h->length = htons(msg.length() + sizeof(tds_header));
        h->spid = 0;
        h->packet_id = 0; // FIXME?
        h->window = 0;

        if (!msg.empty())
            memcpy(payload.data() + sizeof(tds_header), msg.data(), msg.size());

        auto ret = send(sock, payload.data(), payload.length(), 0);

        if (ret == -1)
            throw formatted_error(FMT_STRING("send failed (error {})"), errno);

        if (ret < payload.length())
            throw formatted_error(FMT_STRING("send sent {} bytes, expected {}"), ret, payload.length());
    }

    int sock = 0;
};

int main() {
    try {
        newtds n(db_server, db_port, db_user, db_password);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
