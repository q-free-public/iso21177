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
    enum class ALPDUDataType { ProxyPDU, AccessControlPDU, APDU};
    // TODO: check type of received data
    ALPDUDataType PduType = ALPDUDataType::APDU;
    if (alpduReceived.size() > 0) {
        if (alpduReceived.data()[0] == 0x00) {
            PduType = ALPDUDataType::ProxyPDU;
        }
        if (alpduReceived.data()[0] == 0x01) {
            PduType = ALPDUDataType::AccessControlPDU;
        }
        if (alpduReceived.data()[0] == 0x02) {
            PduType = ALPDUDataType::APDU;
        }
    }

    switch (PduType) {
        // 1. TLS Handshake proxy PDU - unsupported
        case ALPDUDataType::ProxyPDU:
            std::cerr << "Unsupported PDU type - ProxyPDU\n";
            break;
        // 2. Access Control PDU - TODO: implement
        case ALPDUDataType::AccessControlPDU:
            call_function(secALAccessControlIndictationCB, appId, sessionId, alpduReceived);
            break;
        // 3. APDU : Application data
        case ALPDUDataType::APDU:
            call_function(appALDataIndicationCB, appId, sessionId, alpduReceived);
    }
}

void AdaptorLayer::ALSessEndSessionConfirm()
{
    std::cerr << "AdaptorLayer::ALSessEndSessionConfirm" << "\n";
}

void AdaptorLayer::SecALAccessControlRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data& data)
{
    std::cerr << "AdaptorLayer::SecALAccessControlRequest\n";
    call_function(secALAccessControlConfirmCB);
    // TODO: create ALPDU Iso21177AdaptorLayerPDUA
    BaseTypes::Data alpdu(data);
    if (auto sptr = secSessALAPI.lock()) {
        sptr->ALSessDataRequest(appId, sessionId, alpdu);
    }
}

void AdaptorLayer::SecALEndSessionRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    //XXX: This has an issue - in some cases it should not call SecSession, but it has no way of knowing
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
