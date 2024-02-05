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

bool SocketServerTLS::checkHandshakeAsServer()
{
    return this->attemptHandshake(appId_, cryptoHandle_);
}

void SocketServerTLS::closeSocket()
{
}

void SocketServerTLS::setStateSSL()
{
    SSL_set_accept_state(*ssl_);
}
