#include "SocketClientTLS.hh"

#define CERT_HASH_LEN 8

SocketClientTLS::SocketClientTLS(std::shared_ptr<Socket> s, const std::string& host, int port,
        const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
: SocketTLS(s, host, port)
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

std::unique_ptr<Socket> SocketClientTLS::acceptClientConnection()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketClientTLS>(std::move(connectedSocket), this->sec_ent_host_, this->sec_ent_port_, appId_, cryptoHandle_);
}

std::unique_ptr<SocketTLS> SocketClientTLS::acceptClientConnectionTLS()
{
    auto connectedSocket = SocketTLS::acceptClientConnection();
    std::cerr << "SocketServerTLS::acceptClientConnection " << connectedSocket->getFd() << "\n";
    return std::make_unique<SocketClientTLS>(std::move(connectedSocket), this->sec_ent_host_, this->sec_ent_port_, appId_, cryptoHandle_);
}

bool SocketClientTLS::checkHandshakeAsServer()
{
    throw std::runtime_error("SocketClientTLS::checkHandshakeAsServer");
}

void SocketClientTLS::setStateSSL()
{
    SSL_set_connect_state(*ssl_);
}
