#include "SocketServerTLS.hh"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "SecEntData.hh"
#define CERT_HASH_LEN 8

SocketServerTLS::SocketServerTLS(std::shared_ptr<Socket> s, const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
: SocketTLS(s)
, appId_(appId)
, cryptoHandle_(clientHandle)
{
    if (type_ != Socket::Type::SERVER) {
        throw std::runtime_error("Invalid socket type - SocketServerTLS has to be of server type");
    }
}

SocketServerTLS::~SocketServerTLS()
{
}

std::unique_ptr<Socket> SocketServerTLS::acceptClientConnection()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketServerTLS>(std::move(connectedSocket), appId_, cryptoHandle_);
}

std::unique_ptr<SocketTLS> SocketServerTLS::acceptClientConnectionTLS()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketServerTLS>(std::move(connectedSocket), appId_, cryptoHandle_);
}

void SocketServerTLS::connectToServer()
{
    throw std::runtime_error("Server socket cannot connect to servers");
}

bool SocketServerTLS::attemptHandshakeAsClient(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
{
    throw std::runtime_error("Server socket cannot attemptHandshakeAsClient");
}

bool SocketServerTLS::checkHandshakeAsServer()
{
    std::cerr << "SocketServerTLS::checkHandshakeAsServer\n";
    ssl_ = SSL_Wrapper(this->ssl_ctx_);
    if (!*ssl_) {
        fprintf(stderr, "SSL_new failed\n");
        return false;
    }
    if (!SSL_set_1609_sec_ent_addr(*ssl_, SecEntData::sec_ent_port, SecEntData::sec_ent_ip)) {
        fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
        ERR_print_errors_fp(stderr);
        return false;
    }
    int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    bool force_x509 = false;
    if (force_x509) {
        server_support = SSL_RFC8902_X509;
    }
    if (!this->ssl_set_RFC8902_values(server_support, client_support, appId_, cryptoHandle_)) {
        return false;
    }
    if (!SSL_set_fd(*ssl_, this->getFd())) {
        fprintf(stderr, "SSL_set_fd failed\n");
        return false;
    }
    std::cerr << "SSL accept " << this->getFd() << "\n";
    int retval = SSL_accept(*ssl_);
    std::cerr << "SSL accept done\n";
    if (retval <= 0) {
        fprintf(stderr, "SSL_accept failed ssl_err=%d errno=%s\n",
                SSL_get_error(*ssl_, retval), strerror(errno));
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cerr << "SSL accepted.\n";

    uint64_t psid;
	size_t ssp_len;
	uint8_t *ssp = NULL;
    std::array<uint8_t, CERT_HASH_LEN> hashed_id;
	if(SSL_get_1609_psid_received(*ssl_, &psid, &ssp_len, &ssp, hashed_id.data()) <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_get_1609_psid_received failed\n");
		return false;
	}
    std::vector<uint8_t> cert(hashed_id.begin(), hashed_id.end());
    this->setPeerCertificate(cert);

    return true;
}

void SocketServerTLS::closeSocket()
{
}
