#pragma once

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "OpenSSLWrappers.hh"

#include "SocketTLS.hh"
#include "BaseTypes.hh"

class SocketServerTLS : public SocketTLS {
public:
    SocketServerTLS(std::shared_ptr<Socket> s, const std::string& host, int port,
        const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle);
    ~SocketServerTLS();
    virtual std::unique_ptr<Socket> acceptClientConnection();
    virtual std::unique_ptr<SocketTLS> acceptClientConnectionTLS();
    virtual void connectToServer();
    virtual bool checkHandshakeAsServer();
    virtual void closeSocket();
    virtual void setStateSSL();
private:
    const BaseTypes::AppId appId_;
    const BaseTypes::CryptomaterialHandle cryptoHandle_;
};