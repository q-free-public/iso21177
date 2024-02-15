#pragma once

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "OpenSSLWrappers.hh"

#include "Socket.hh"
#include "BaseTypes.hh"

class SocketTLS : public Socket {
public:
    SocketTLS(std::shared_ptr<Socket> s, const std::string& host, int port);
    virtual ~SocketTLS();
    virtual std::unique_ptr<Socket> acceptClientConnection();
    virtual std::unique_ptr<SocketTLS> acceptClientConnectionTLS() = 0;
    virtual void connectToServer();
    virtual bool checkHandshakeAsServer() = 0;
    virtual int getData(std::vector<uint8_t>& data);
    virtual int sendData(const std::vector<uint8_t>& data);
    virtual void closeSocket();
    virtual int getFd();
    virtual void setStateSSL() = 0;
    bool attemptHandshake(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle);
    virtual BaseTypes::Certificate getPeerCertificate();
    virtual BaseTypes::CredentialBasedAuthState getPeerAuthState();
protected:
    virtual void setPeerCertificate(const BaseTypes::Certificate& cert);
    int ssl_set_RFC8902_values(int server_support, int client_support,
            const BaseTypes::AID &aidToUse,
            const BaseTypes::CryptomaterialHandle& cryptoHandle);
    SSL_CTX_Wrapper ssl_ctx_;
    SSL_Wrapper ssl_;
    std::shared_ptr<BaseTypes::Certificate> peerCert_;
    std::shared_ptr<BaseTypes::CredentialBasedAuthState> peerAuthState_;
    int sec_ent_port_;
    std::string sec_ent_host_;
    
private:
    std::shared_ptr<Socket> socketBase_;
    std::unique_ptr<int> x_;
};