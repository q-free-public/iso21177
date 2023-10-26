#include "SecureSession.hh"

#include <array>
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

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
    sessionData data;
    data.socket = socket;
    data.role = role;
    key_t key(appId, sessionId);
    data_[key] = data;
    call_function(secSessConfigureConfirmCB);
}

void SecureSession::ALSessDataRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &apduToSend)
{
    std::cerr << "SecureSession::ALSessDataRequest" << "\n";
    call_function(aLSessDataConfirmCB);
    //TODO: fragments and cryptographically protects
    // passes to the network for transmission
    key_t key(appId, sessionId);
    auto it = data_.find(key);
    if (it == data_.end()) {
        std::cerr << "No session found\n";
        return;
    }
    BaseTypes::Socket sock = it->second.socket;
    std::cerr << "====SecureSession::ALSessDataRequest sock: " << sock << "\n";
    int sent = send(sock, apduToSend.data(), apduToSend.size(), 0);
    std::cerr << "SecureSession::ALSessDataRequest : sent " << sent << " data size: " << apduToSend.size() << "\n";
}

void SecureSession::ALSessEndSessionRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecureSession::ALSessEndSessionRequest" << "\n";
    call_function(aLSessEndSessionConfirmCB);
}

void SecureSession::SecSessDeactivateRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SecureSessionInstanceId &secSessInstanceId)
{
    std::cerr << "SecureSession::SecSessDeactivateRequest\n";
    // No more new connections
    call_function(secSessDeactivateConfirmCB);
    // TODO: IF server -> stop accepting incorming connections
    // TODO: IF client -> stop attempting new outgoing connections
    
    // TODO: delete all state relevant to new sessions
}

void SecureSession::afterHandshake()
{
    BaseTypes::AppId appId = 1;
    BaseTypes::SessionId sessionId = 1;
    BaseTypes::Certificate cert = {0x01, 0x03, 0x05, 0x06};
    call_function(secSessionStartIndicationCB,
            appId, sessionId, cert);
}

void SecureSession::checkForData()
{
    std::array<uint8_t, 1024> buffer;
    int count;
    for (auto it : data_) {
        std::cerr << "trying " << it.first.first << " " << it.first.second << " | sock: " << it.second.socket << "\n";
        BaseTypes::Socket sock = it.second.socket;
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        if (it.second.role == BaseTypes::Role::SERVER) {
            int client = accept(sock, (struct sockaddr*)&addr, &len);
            if (client < 0) {
                perror("accept");
                continue;
            }
            sock = client;
        }
        int result = ioctl(sock, FIONREAD, &count);
        std::cerr << "data available " << count << " result: " << result << "\n";
        if (result < 0) {
            perror("ioctl");
        }
        if (count > 0) {
            int received = recv(sock, buffer.data(), buffer.size(), 0);
            std::cerr << "received " << received << "\n";
            BaseTypes::Data data;
            std::copy(buffer.begin(), buffer.begin() + received, std::back_inserter(data));
            call_function(aLSessDataIndicationCB, it.first.first, it.first.second, data);
        }
    }
}

void SecureSession::receiveData(const std::vector<uint8_t> &data)
{
    // Check if session timed out
    BaseTypes::AppId appId = 10;
    BaseTypes::SessionId sessionId = 11;
    call_function(aLSessDataIndicationCB, appId, sessionId, data);
}

void SecureSession::sessionTerminated()
{
    BaseTypes::AppId appId(16);
    BaseTypes::SessionId sessionId(8);
    call_function(secSessEndSessionIndicationCB, appId, sessionId);
}
