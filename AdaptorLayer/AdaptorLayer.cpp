#include "AdaptorLayer.hh"
#include "asn1/AdaptorLayerPDU.hh"

#include <iostream>

void AdaptorLayer::AppALDataRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &data)
{
    std::cerr << "AdaptorLayer::AppALDataRequest AppId" << appId  << " SessionId " << sessionId <<"\n";
    call_function_wptr(appALAPI, [](std::shared_ptr<AppAdaptorLayerAPI> sptr) {
        sptr->AppALDataConfirm();
    });
    // Add Session non-repudiation (not supported in current standard)
    // add Data header (8.2)
    Asn1Helpers::AdaptorLayerPdu alPdu(
            std::integral_constant<
                Asn1Helpers::AdaptorLayerPdu::type,
                Asn1Helpers::AdaptorLayerPdu::type::APDU
            >(), data);
    call_function_wptr(secSessALAPI, [&](std::shared_ptr<SecureSessionALAPI> sptr ) {
        sptr->ALSessDataRequest(
            appId,
            sessionId,
            alPdu.getEncodedBuffer()
        );
    });
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
    Asn1Helpers::AdaptorLayerPdu alPdu(alpduReceived);
    alPdu.debugPrint();

    switch (alPdu.getType()) {
        // 1. TLS Handshake proxy PDU - unsupported
        default:
            std::cerr << "Unsupported PDU type - ProxyPDU\n";
            break;
        // 2. Access Control PDU - TODO: implement
        case Asn1Helpers::AdaptorLayerPdu::type::AccessControl:
            call_function_wptr(secSubALAPI, [&](auto sptr) {
                sptr->SecALAccessControlIndictation(appId, sessionId, alPdu.getPayload());
            });
            break;
        // 3. APDU : Application data
        case Asn1Helpers::AdaptorLayerPdu::type::APDU:
            call_function_wptr(appALAPI, 
            [&](std::shared_ptr<AppAdaptorLayerAPI> sptr) {
                sptr->AppALDataIndication(appId, sessionId, alPdu.getPayload());
            });
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
    call_function_wptr(secSubALAPI, [](auto sptr) {
        sptr->SecALAccessControlConfirm();
    });
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
    call_function_wptr(secSubALAPI, [](auto sptr){
        sptr->SecALEndSessionConfirm();
    });
    if (auto sptr = secSessALAPI.lock()) {
        sptr->ALSessEndSessionRequest(appId, sessionId);
    }
}

void AdaptorLayer::registerSecSessAPI(std::weak_ptr<SecureSessionALAPI> ptr)
{
    this->secSessALAPI = ptr;
}
