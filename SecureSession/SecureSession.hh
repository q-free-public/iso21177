#pragma once

#include <memory>
#include <map>

#include "SecureSessionSecSubAPI.hh"
#include "SecureSessionALAPI.hh"

class SecureSession : 
        public SecureSessionSecSubAPI,
        public SecureSessionALAPI {
public:
    SecureSession();

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

    // This should be triggered by TLS handshake completion
    virtual void afterHandshake();
    // This is what comes from a socket
    virtual void receiveData(const std::vector<uint8_t>& data);
    // This is called when a session is lost
    virtual void sessionTerminated();
    virtual bool waitForNetworkInput();

private:
    enum class SocketState { CREATED, BEFORE_HANDSHAKE, AFTER_HANDSHAKE, OTHER_SIDE_CLOSED, SERVER_SOCKET};
    typedef std::pair<BaseTypes::AppId, BaseTypes::SessionId> key_t;
    typedef std::pair<BaseTypes::Socket, SocketState> SocketWithState;
    struct sessionData {
        BaseTypes::Role role;
        SocketWithState socket;
        // non-empty only in server role
        std::vector<SocketWithState> clientSockets;
    };
    std::map<key_t, sessionData> data_;

    virtual void attemptHandshake(BaseTypes::AppId appId, BaseTypes::SessionId sessId);
    virtual void waitForData(SocketWithState sock, BaseTypes::Data& readData);
};