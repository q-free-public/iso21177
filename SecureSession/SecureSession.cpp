#include "SecureSession.hh"

#include <array>
#include <iostream>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>

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
    std::cerr << "SecureSession will now establish a connection with external ITS-S" << " AID: " << appId << " Cert: " << hex_string(cryptomaterialHandle) << "\n";
    if (data_.size() >= 1) {
        // TODO: For now, only a single session is allowed
        std::cerr << "Reached max allowed sessions: " << data_.size() << "\n";
    } else {
        sessionData data;
        data.socket = SocketWithState(socket, SocketState::CREATED);
        data.role = role;
        key_t key(appId, sessionId);
        if (role == BaseTypes::Role::CLIENT) {
            data.socket.first->connectToServer();
            data.socket.first->attemptHandshake(appId, cryptomaterialHandle);
            //attemptHandshake(appId, sessionId);
            data.socket.second = SocketState::BEFORE_HANDSHAKE;
            // TODO: for now we assume that client handshake always works
            data.socket.second = SocketState::AFTER_HANDSHAKE;
        }
        if (role == BaseTypes::Role::SERVER) {
            data.socket.second = SocketState::SERVER_SOCKET;
        }
        data_[key] = data;
    }
    call_function_wptr(secSubSecureSessionAPI, [](auto sptr) {
        sptr->SecSessConfigureConfirm();
    });
}

void SecureSession::ALSessDataRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &apduToSend)
{
    std::cerr << "SecureSession::ALSessDataRequest" << "\n";
    if (auto sptr = alSecureSessionAPI.lock()) {
        sptr->ALSessDataConfirm();
    }
    //TODO: fragments and cryptographically protects
    // passes to the network for transmission
    key_t key(appId, sessionId);
    auto it = data_.find(key);
    if (it == data_.end()) {
        std::cerr << "No session found\n";
        return;
    }
    SocketWithState sockWithState = it->second.socket;
    if (it->second.role == BaseTypes::Role::SERVER) {
        if (it->second.clientSockets.size() != 1) {
            std::cerr << "Wrong number of clients connected to server " << it->second.clientSockets.size() << "\n";
            return;
        }
        sockWithState = *(it->second.clientSockets.begin());
    }
    std::cerr << "====SecureSession::ALSessDataRequest sock: " << sockWithState.first << "\n";
    if (sockWithState.second != SocketState::AFTER_HANDSHAKE) {
        std::cerr << "!!!!!! invalid socket state : " << (int)(sockWithState.second) << "\n";
        return;
    }
    auto sock_ptr = sockWithState.first;
    if (!sock_ptr) {
        std::cerr << "invalid socket ptr\n";
        return;
    }
    int sent = sock_ptr->sendData(apduToSend);
    std::cerr << "SecureSession::ALSessDataRequest : sent " << sent << " data size: " << apduToSend.size() <<  hex_string(apduToSend) << "\n";
}

void SecureSession::ALSessEndSessionRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecureSession::ALSessEndSessionRequest" << "\n";
    if (data_.size() != 1) {
        std::cerr << "No sessions registered, exiting\n";
    }
    auto it = data_.begin();
    //TODO: End session if supported in protocol
    switch (it->second.role) {
    case BaseTypes::Role::CLIENT: {
        // in client case we do nothing now
        break;
    }
    case BaseTypes::Role::SERVER: {
        // in server case we close client socket (if open)
        if (it->second.clientSockets.size() == 1) {
            auto ptr = it->second.clientSockets.begin();
            // TODO: maybe terminate a session here if necessary
            std::cerr << "closing client socket in server\n";
            it->second.clientSockets.erase(ptr);
        }
        break;
    }
    }
    call_function_wptr(alSecureSessionAPI,[](auto sptr) {
        sptr->ALSessEndSessionConfirm();
    });
}

void SecureSession::SecSessDeactivateRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SecureSessionInstanceId &secSessInstanceId)
{
    std::cerr << "SecureSession::SecSessDeactivateRequest\n";
    // No more new connections
    call_function_wptr(secSubSecureSessionAPI, [](auto sptr) {
        sptr->SecSessDeactivateConfirm();
    });
    // TODO: IF server -> stop accepting incorming connections
    // TODO: IF client -> stop attempting new outgoing connections
    
    // TODO: delete all state relevant to new sessions
}

void SecureSession::getAuthState(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecureSession::getAuthState\n"; 
}

void SecureSession::afterHandshake()
{
    BaseTypes::AppId appId = 1;
    BaseTypes::SessionId sessionId = 1;
    BaseTypes::Certificate cert = {0x01, 0x03, 0x05, 0x06};
    call_function_wptr(secSubSecureSessionAPI, [&](auto sptr) {
        sptr->SecSessionStartIndication(appId, sessionId, cert);
    });
}

void SecureSession::receiveData(const std::vector<uint8_t> &data)
{
    // Check if session timed out
    BaseTypes::AppId appId = 10;
    BaseTypes::SessionId sessionId = 11;
    call_function_wptr(alSecureSessionAPI, [&](std::shared_ptr<ALSecureSessionAPI> sptr) {
        sptr->ALSessDataIndication(appId, sessionId, data);
    });
}

void SecureSession::sessionTerminated()
{
    BaseTypes::AppId appId(16);
    BaseTypes::SessionId sessionId(8);
    call_function_wptr(secSubSecureSessionAPI, [&](auto sptr) {
        sptr->SecSessEndSessionIndication(appId, sessionId);
    });
}

bool SecureSession::waitForNetworkInput()
{
    // Currently there is just a simple implementation which waits for a single socket.
    // in case of client this is a socket with connection to the server
    // in case of server this is the server socket if no clients are connected
    // in case of server this is the client socket if the client is connected

    if (data_.size() != 1) {
        std::cerr << "No sessions registered, exiting\n";
    }
    auto it = data_.begin();
    // in server case - we wait for clients here
    // in client case - we wait for handshake response here
    std::cerr << "processing " << it->first.first << " " << it->first.second << " | sock: " << it->second.socket.first << "\n";
    switch (it->second.role) {
    case BaseTypes::Role::CLIENT: {
            // Connected to server, wait for data
            BaseTypes::Data data;
            waitForData(it->second.socket, data);
            if (data.size() > 0) {
                call_function_wptr(alSecureSessionAPI, 
                [&](std::shared_ptr<ALSecureSessionAPI> sptr) {
                    sptr->ALSessDataIndication(it->first.first, it->first.second, data);
                });
            }
            if (data.size() == 0) {
                std::cerr << "Socket is closed on the other side\n";

                call_function_wptr(secSubSecureSessionAPI, 
                [&](std::shared_ptr<SecSubSecureSessionAPI> sptr) {
                    sptr->SecSessEndSessionIndication(it->first.first, it->first.second);
                });
            };
        break;
    }
    case BaseTypes::Role::SERVER: {
        if (it->second.clientSockets.size() == 0) {
            std::cerr << "SERVER : no clients connected, waiting for the 1st\n";
            // No clients are connected, wait for the 1st connection
            BaseTypes::Socket sock = it->second.socket.first;
            if (!sock) {
                std::cerr << "invalid socket\n";
                return false;
            }
            auto client_sock = sock->acceptClientConnection();
            //TODO: here handshake check should happen
            it->second.clientSockets.push_back(SocketWithState(std::move(client_sock), SocketState::AFTER_HANDSHAKE));
        } else if (it->second.clientSockets.size() == 1) {
            // Client is connected, wait for data
            std::cerr << "SERVER : Client is connected, wait for data\n";
            BaseTypes::Data data;
            auto sockWithStatePtr = it->second.clientSockets.begin();
            waitForData(*sockWithStatePtr, data);
            if (data.size() > 0) {
                call_function_wptr(alSecureSessionAPI, 
                [&](std::shared_ptr<ALSecureSessionAPI> sptr) {
                    sptr->ALSessDataIndication(it->first.first, it->first.second, data);
                });
            }
            if (data.size() == 0) {
                std::cerr << "Socket is closed on the other side\n";
                sockWithStatePtr->second = SocketState::OTHER_SIDE_CLOSED;
                // Accepted socket is opened here, will be closed when ptr is destroyed
                it->second.clientSockets.erase(sockWithStatePtr);
                call_function_wptr(secSubSecureSessionAPI, [&](auto sptr) {
                    sptr->SecSessEndSessionIndication(it->first.first, it->first.second);
                });
            };
        } else {
            std::cerr << "More than one client connected, this should not happen\n";
        }
        break;
    }
    }
    return true;
}

void SecureSession::attemptHandshake(BaseTypes::AppId appId, BaseTypes::SessionId sessId)
{
    //TODO: this is the fake implementation
    std::cerr << "SecureSession::attemptHandshake\n";
    BaseTypes::Data data({0x99, 0x98, 0x97, 0x96});
    this->ALSessDataRequest(appId, sessId, data);
}

void SecureSession::waitForData(SecureSession::SocketWithState sock, BaseTypes::Data &readData)
{
    auto sock_ptr = sock.first;
    if (!sock_ptr) {
        std::cerr << "invalid socket ptr\n";
    }
    sock_ptr->getData(readData);
}
