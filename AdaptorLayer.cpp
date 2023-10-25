#include "AdaptorLayer.hh"

#include <iostream>

void AdaptorLayer::AppALDataRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &data)
{
    std::cerr << "AdaptorLayer::AppALDataRequest " << appId <<"\n";
    call_function(appALDataConfirmCB);
    BaseTypes::SignedData apduToSend(data);
    // Add Session non-repudiation (not supported in current standard)
    // TODO: add Data header (8.2)
    if (auto sptr = secSessALAPI.lock()) {
        sptr->ALSessDataRequest(
            appId,
            sessionId,
            apduToSend
        );
    } else {
        std::cerr << "!!!!!!! unable to lock secSess API !!!\n";
    }
}

void AdaptorLayer::ALSessDataConfirm()
{
    std::cerr << " AdaptorLayer::ALSessDataConfirm" << "\n";
}

void AdaptorLayer::ALSessDataIndication(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &alpduReceived)
{
    std::cerr << "AdaptorLayer::ALSessDataIndication" << "\n";
    // TODO: check type of received data
    // 1. TLS Handshake proxy PDU - unsupported
    // 2. Access Control PDU - TODO: implement
    // 3. APDU : Application data
    call_function(appALDataIndicationCB, appId, sessionId, alpduReceived);
}

void AdaptorLayer::ALSessEndSessionConfirm()
{
    std::cerr << "AdaptorLayer::ALSessEndSessionConfirm" << "\n";
}

void AdaptorLayer::SecALAccessControlRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    std::cerr << "AdaptorLayer::SecALAccessControlRequest\n";
}

void AdaptorLayer::SecALEndSessionRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    std::cerr << "AdaptorLayer::SecALEndSessionRequest\n";
    call_function(secALEndSessionConfirmCB);
    if (auto sptr = secSessALAPI.lock()) {
        sptr->ALSessEndSessionRequest(appId, sessionId);
    }
}

void AdaptorLayer::registerSecSessAPI(std::weak_ptr<SecureSessionALAPI> ptr)
{
    this->secSessALAPI = ptr;
    if (auto sptr = secSessALAPI.lock()) {
        sptr->registerALCallbacks(
            std::bind(&AdaptorLayer::ALSessDataConfirm, this),
            std::bind(&AdaptorLayer::ALSessDataIndication, this,
                std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
            std::bind(&AdaptorLayer::ALSessEndSessionConfirm, this)
        );
    }
}
