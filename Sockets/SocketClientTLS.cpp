#include "SocketClientTLS.hh"

#include "SecEntData.hh"

SocketClientTLS::SocketClientTLS(std::shared_ptr<Socket> s, const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
: SocketTLS(s)
, appId_(appId)
, cryptoHandle_(clientHandle)
{
    if (type_ != Socket::Type::CLIENT) {
        throw std::runtime_error("Invalid socket type - SocketClientTLS has to be of client type");
    }
}

SocketClientTLS::~SocketClientTLS()
{
}

void SocketClientTLS::connectToServer()
{
    SocketTLS::connectToServer();
}

bool SocketClientTLS::attemptHandshakeAsClient(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
{
    std::cerr << "SocketTLS::attemptHandshakeAsClient\n";
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
    if (!this->ssl_set_RFC8902_values(server_support, client_support, appId, clientHandle)) {
        return false;
    }
    if (!SSL_set_fd(*ssl_, this->getFd())) {
        fprintf(stderr, "SSL_set_fd failed\n");
        return false;
    }
    std::cerr << "SSL_connect\n";
    if (SSL_connect(*ssl_) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_connect failed\n");
        return false;
    }
    std::cerr << "SSL_connect done\n";
    return true;
}

std::unique_ptr<Socket> SocketClientTLS::acceptClientConnection()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketClientTLS>(std::move(connectedSocket), appId_, cryptoHandle_);
}

std::unique_ptr<SocketTLS> SocketClientTLS::acceptClientConnectionTLS()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketClientTLS>(std::move(connectedSocket), appId_, cryptoHandle_);
}

bool SocketClientTLS::checkHandshakeAsServer()
{
    throw std::runtime_error("SocketClientTLS::checkHandshakeAsServer");
}
