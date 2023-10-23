#include "SecureSession.hh"

#include <iostream>

SecureSession::SecureSession()
{
}

void SecureSession::SecSessConfigureRequest(
        const BaseTypes::AppId &appId, BaseTypes::Role role,
        const BaseTypes::Socket socket,
        BaseTypes::SessionType sessionType, bool proxied,
        const BaseTypes::SessionId &sessionId,
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle &cryptomaterialHandle,
        const BaseTypes::CertPermissionsPattern &certPermPattern,
        BaseTypes::TimePeriod inactivityTimeout,
        BaseTypes::TimePeriod sessionTimeout,
        bool requireClientAuth,
        BaseTypes::TimePeriod incomingRequestTimeout,
        int64_t maxIncomingSessions,
        const BaseTypes::NameConstraints &nameConstraints,
        const BaseTypes::IssuerConstraints &issuerConstraints)
{
    std::cerr << "SecureSession::SecSessConfigureRequest" << " APP ID " << appId << "\n";
    std::cerr << "SecureSession will now establish a connection with external ITS-S" << " AID: " << appId << " Cert: " << cryptomaterialHandle << "\n";
    if (secSessConfigureConfirmCB) {
        secSessConfigureConfirmCB();
    }
}

void SecureSession::ALSessDataRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId, const BaseTypes::Data &apduToSend)
{
    std::cerr << "SecureSession::ALSessDataRequest" << "\n";
    if (aLSessDataConfirmCB) {
        aLSessDataConfirmCB();
    } else {
        std::cerr << "!!!! aLSessDataConfirmCB unregistered !!!!!\n";
    }
    //TODO: fragments and cryptographically protects
    // passes to the network for transmission
}

void SecureSession::ALSessEndSessionRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecureSession::ALSessEndSessionRequest" << "\n";
    if (!aLSessEndSessionConfirmCB) {
        std::cerr << "!!!!!!! aLSessEndSessionConfirmCB unregistered\n";
    }
    aLSessEndSessionConfirmCB();
}

void SecureSession::afterHandshake()
{
    BaseTypes::AppId appId = 1;
    BaseTypes::SessionId sessionId = 1;
    BaseTypes::Certificate cert = {0x01, 0x03, 0x05, 0x06};
    if (secSessionStartIndicationCB) {
        secSessionStartIndicationCB(appId, sessionId,
                cert);
    }
}

void SecureSession::receiveData(const std::vector<uint8_t> &data)
{
    // Check if session timed out
    if (!aLSessDataIndicationCB) {
        std::cerr << "!!!!! aLSessDataIndicationCB not registered\n";
    }
    BaseTypes::AppId appId = 10;
    BaseTypes::SessionId sessionId = 11;
    aLSessDataIndicationCB(appId, sessionId, data);
}
