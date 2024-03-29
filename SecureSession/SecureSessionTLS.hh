#pragma once

#include <memory>
#include <map>

#include "SecureSessionSecSubAPI.hh"
#include "SecureSessionALAPI.hh"
#include "SecureSession.hh"

#include "Sockets/SocketTLS.hh"

#include "sec_ent_comm/sec_ent_api.hh"

class SecureSessionTLS : 
        public SecureSession {
public:
    SecureSessionTLS(SecEnt::SecEntCommunicator& comm);

    virtual void SecSessConfigureRequest(
        const BaseTypes::AppId& appId,
        BaseTypes::Role role,
        const BaseTypes::Socket socket,
        BaseTypes::SessionType sessionType, // Always External
        bool proxied, // Always False
        const BaseTypes::SessionId& sessionId, // only used if role == CLIENT
        // Only for Type == EXTERNAL start
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle& cryptomaterialHandle,
        const BaseTypes::CertPermissionsPattern& certPermPattern,
        BaseTypes::TimePeriod inactivityTimeout,
        BaseTypes::TimePeriod sessionTimeout,
        // Only for Type == EXTERNAL end
        bool requireClientAuth, // only used for server role
        BaseTypes::TimePeriod incomingRequestTimeout,
        int64_t maxIncomingSessions,
        const BaseTypes::NameConstraints& nameConstraints,
        const BaseTypes::IssuerConstraints& issuerConstraints
    );

    virtual void ALSessDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apduToSend
    );

    virtual void ALSessEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    virtual void SecSessDeactivateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secSessInstanceId
    );

    virtual void getAuthState(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId);

    // This should be triggered by TLS handshake completion
    void afterHandshake();
    // This is what comes from a socket
    void receiveData(const std::vector<uint8_t>& data);
    // This is called when a session is lost
    void sessionTerminated();
    bool waitForNetworkInput();

private:
    enum class SocketState { CREATED, BEFORE_HANDSHAKE, AFTER_HANDSHAKE, OTHER_SIDE_CLOSED, SERVER_SOCKET};
    typedef std::pair<BaseTypes::AppId, BaseTypes::SessionId> key_t;
    typedef std::pair<std::shared_ptr<SocketTLS>, SocketState> SocketWithState;
    struct sessionData {
        BaseTypes::Role role;
        SocketWithState socket;
        // non-empty only in server role
        std::vector<SocketWithState> clientSockets;

    };
    std::map<key_t, sessionData> data_;
    SecEnt::SecEntCommunicator& sec_ent_comm_;

    void waitForData(SocketWithState sock, BaseTypes::Data& readData);
    void afterHandshake(const BaseTypes::AppId& appId, 
            const BaseTypes::SessionId& sessionId, const BaseTypes::Certificate& cert);
};