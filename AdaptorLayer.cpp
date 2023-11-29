#include "AdaptorLayer.hh"
#include "asn1/AdaptorLayerPDU.hh"

#include <iostream>

void AdaptorLayer::AppALDataRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &data)
{
    std::cerr << "AdaptorLayer::AppALDataRequest " << appId <<"\n";
    call_function(appALDataConfirmCB);
    // Add Session non-repudiation (not supported in current standard)
    // add Data header (8.2)
    AdaptorLayerPdu alPdu(
            std::integral_constant<
                AdaptorLayerPdu::type,
                AdaptorLayerPdu::type::APDU
            >(), data);
    if (auto sptr = secSessALAPI.lock()) {
        sptr->ALSessDataRequest(
            appId,
            sessionId,
            alPdu.getEncodedBuffer()
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
    AdaptorLayerPdu alPdu(alpduReceived);

    switch (alPdu.getType()) {
        // 1. TLS Handshake proxy PDU - unsupported
        default:
            std::cerr << "Unsupported PDU type - ProxyPDU\n";
            break;
        // 2. Access Control PDU - TODO: implement
        case AdaptorLayerPdu::type::AccessControl:
            call_function(secALAccessControlIndictationCB, appId, sessionId, alPdu.getPayload());
            break;
        // 3. APDU : Application data
        case AdaptorLayerPdu::type::APDU:
            call_function(appALDataIndicationCB, appId, sessionId, alPdu.getPayload());
            break;
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
