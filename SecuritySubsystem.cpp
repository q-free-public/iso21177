#include "SecuritySubsystem.hh"

#include <memory>
#include <iostream>
#include <functional>

#include "SecuritySubsystemAppAPI.hh"

SecuritySubsystem::SecuritySubsystem()
{
}

void SecuritySubsystem::registerAdaptorLayerSecSubAPI(
        std::weak_ptr<AdaptorLayerSecSubAPI> aLSecSubAPI)
{
    alAPI = aLSecSubAPI;
    if (auto sptr = alAPI.lock()) {
        sptr->registerAppCallBacks(
            std::bind(&SecuritySubsystem::SecALAccessControlConfirm, this),
            std::bind(&SecuritySubsystem::SecALAccessControlIndictation, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&SecuritySubsystem::SecALEndSessionConfirm, this)
        );
    }
}

void SecuritySubsystem::registerSecureSessionSecSubAPI(
        std::weak_ptr<SecureSessionSecSubAPI> secSessAPI)
{
    this->secSessAPI = secSessAPI;
    if (auto sptr = this->secSessAPI.lock()) {
        sptr->registerSecSubCallbacks(
            std::bind(&SecuritySubsystem::SecSessConfigureConfirm, this),
            std::bind(&SecuritySubsystem::SecSessStartIndication, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3),
            std::bind(&SecuritySubsystem::SecSessEndSessionIndication, this,
                    std::placeholders::_1, std::placeholders::_2),
            std::bind(&SecuritySubsystem::SecSessDeactivateConfirm, this)
        );
    }
}

void SecuritySubsystem::SecSessConfigureConfirm()
{
    std::cerr << "SecuritySubsystem::SecSessConfigureConfirm" << "\n";
}

void SecuritySubsystem::SecSessStartIndication(
        const BaseTypes::AppId & appId,
        const BaseTypes::SessionId & sessId,
        const BaseTypes::Certificate & cert)
{
    std::cerr << "SecuritySubsystem::SecSessStartIndication" << "\n";
    // TODO: check access control policy
    // Access control policy == SUCCESS
    if (true /* role == SERVER */) {
        //AppSecStartSessionIndication
    }
    // Access control policy == More authentication required
    // ????
    // Access control policy == FAILURE
    // End Session 

}

void SecuritySubsystem::AppSecConfigureRequest(
        const BaseTypes::AppId &appId, BaseTypes::Role role,
        const BaseTypes::Socket &socket,
        BaseTypes::SessionType sessionType,
        bool proxied, const BaseTypes::SessionId &sessionId,
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle &cryptomaterialHandle)
{
    std::cerr << "SecuritySubsystemAppAPI::AppSecConfigureRequest " << "AID " << appId << "\n";
    AppSecConfigureConfirmResult result = AppSecConfigureConfirmResult::SUCCESS;
    if (proxied) {
        std::cerr << "unsupported proxied value : True\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }
    if (transportMechanismType == BaseTypes::TransportMechanismType::UNRELIABLE) {
        std::cerr << "unsupported transportMechanismType : unreliable\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }
    if (sessionType == BaseTypes::SessionType::INTERNAL) {
        std::cerr << "unsupported SessionType : internal\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }

    std::cerr << "SecureSessionSecSubAPI::SecSessConfigureRequest" << " APP ID " << appId << "\n";
    if (this->appSecConfigureConfirmCB) {
        this->appSecConfigureConfirmCB(result);
    }
    if (sessionType == BaseTypes::SessionType::EXTERNAL) {
        // Cryptographic session is required
        std::cerr << "Will configure external session \n";
        if (auto sptr = secSessAPI.lock()) {
            std::cerr << "Configuring external session \n";
            BaseTypes::CertPermissionsPattern certPermPattern;
            BaseTypes::TimePeriod inactivityTimeout = 100;
            BaseTypes::TimePeriod sessionTimeout = 100;
            bool requireClientAuth = true;
            BaseTypes::TimePeriod incomingRequestTimeout = 100;
            int64_t maxIncomingSessions = 1;
            BaseTypes::NameConstraints nameConstraints;
            BaseTypes::IssuerConstraints issuerConstraints;
            sptr->SecSessConfigureRequest(
                appId, role, socket, sessionType, 
                proxied, sessionId, transportMechanismType,
                cryptomaterialHandle, 
                certPermPattern, inactivityTimeout, sessionTimeout,
                requireClientAuth, incomingRequestTimeout,
                maxIncomingSessions, nameConstraints,
                issuerConstraints
            );
        }
    }
}

void SecuritySubsystem::AppSecDataRequest(
        const BaseTypes::AppId &appId,
        const BaseTypes::SessionId &sessionId,
        const BaseTypes::CryptomaterialHandle &cryptoHandle,
        const BaseTypes::Data &data,
        const BaseTypes::SigningParameters &signingParams)
{
    std::cerr << "SecuritySubsystem::AppSecDataRequest " << appId << "\n";
    // TODO: Call SecEnt to sign the data
    SecuritySubsystemAppAPI::AppSecDataConfirmResult result = SecuritySubsystemAppAPI::AppSecDataConfirmResult::SUCCESS;
    if (appSecDataConfirmCB) {
        appSecDataConfirmCB(result, data);
    }
}

void SecuritySubsystem::AppSecIncomingRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &apdu,
    bool isIeee1609Dot2Data,
    const BaseTypes::SignedDataVerificationParams &signVerParams)
{
    typedef SecuritySubsystemAppAPI::AppSecIncomingConfirmResult Result;
    Result result = Result::SUCCESS;
    bool dataIsSignedType = true;
    if (!isIeee1609Dot2Data) {
        // Not supported now
        result = Result::INVALID_APDU_AS_PER_ACCESS_CONTROL_POLICY_NO_REQUEST_SENT;
    } else{
        if (dataIsSignedType) {
            // TODO: verify with sec_ent - if failed, set result
        } else {
            // TODO: type unsigned is okay, but other (e.g. encrypted) are not
            bool dataIsUnsignedType = true;
            if (!dataIsUnsignedType) {
                result = Result::INVALID_IEEE1609DOT2DATA_TYPE;
            }
        }
    }
    if (result == Result::SUCCESS) {
        // TODO: apply the access control policy
    }
    if (!appSecIncomingConfirmCB) {
        std::cerr << "!!!!! appSecIncomingConfirmCB unregistered !!!\n";
    }
    appSecIncomingConfirmCB(result);
}


// Triggered by the APP
void SecuritySubsystem::AppSecEndSessionRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecuritySubsystem::AppSecEndSessionRequest\n";
    if (!appSecEndSessionIndicationCB) {
        std::cerr << "!!!!!!!!!1\n";
    }
    appSecEndSessionIndicationCB(appId, sessionId,
        BaseTypes::EnumeratedSecLayer::APPLICATION);
    // TODO: SEC_AL_END_SESSION
    if (auto sptr = alAPI.lock()) {
        sptr->SecALEndSessionRequest(appId, sessionId);
    }
}

// Trigerred internally
void SecuritySubsystem::forceEndSession(
    const BaseTypes::AppId& appId,
    const BaseTypes::SessionId& sessionId)
{
    std::cerr << "SecuritySubsystem::forceEndSession\n";
    if (!appSecEndSessionIndicationCB) {
        std::cerr << "!!!!!!!!!1\n";
    }
    appSecEndSessionIndicationCB(appId, sessionId,
        BaseTypes::EnumeratedSecLayer::SECURITY_SUBSYSTEM);
}

void SecuritySubsystem::endSession()
{
    BaseTypes::AppId appId(11);
    BaseTypes::SecureSessionInstanceId secSessId(99);
    call_function(appSecDeactivateIndicationCB, appId, secSessId);
    if (auto sptr = secSessAPI.lock()) {
        sptr->SecSessDeactivateRequest(appId, secSessId);
    }
}

void SecuritySubsystem::AppSecDeactivateRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SecureSessionInstanceId &secureSessionId)
{
    std::cerr << "SecuritySubsystem::AppSecDeactivateRequest\n";
    call_function(appSecDeactivateConfirmCB);
    if (auto sptr = secSessAPI.lock()) {
        sptr->SecSessDeactivateRequest(appId, secureSessionId);
    }
}

void SecuritySubsystem::SecALAccessControlConfirm()
{
    std::cerr << "SecuritySubsystem::SecALAccessControlConfirm\n";
}

void SecuritySubsystem::SecALAccessControlIndictation(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &data)
{
    std::cerr << "SecuritySubsystem::SecALAccessControlIndictation\n";
    // TODO: apply Access Control Policy to determine what action to take
    bool pduIsValidAndRelevant = true;
    if (data.size() > 2 && data.data()[1] == 0x07) {
        pduIsValidAndRelevant = false;
    }
    if (pduIsValidAndRelevant) {
        std::cerr << "PDU is valid and relevant - update SecuritySubsystem state\n";
    } else {
        std::cerr << "PDU is not valid or not relevant - will be ignored\n";
    }
}

void SecuritySubsystem::SecALEndSessionConfirm()
{
    std::cerr << "SecuritySubsystem::SecALEndSessionConfirm\n";
}

void SecuritySubsystem::SecSessEndSessionIndication(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecuritySubsystem::SecSessEndSessionIndication\n";
    call_function(appSecEndSessionIndicationCB, 
        appId, sessionId, BaseTypes::EnumeratedSecLayer::SECURE_SESSION_SERVICE);
    if (auto sptr = alAPI.lock()) {
        sptr->SecALEndSessionRequest(appId, sessionId);
    }
}

void SecuritySubsystem::SecSessDeactivateConfirm()
{
    std::cerr << "SecuritySubsystem::SecSessDeactivateConfirm\n";
}

void SecuritySubsystem::SecAuthStateRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId, const BaseTypes::DateAndTime &notBefore, const BaseTypes::Location &location)
{
    std::cerr << "SecuritySubsystem::SecAuthStateRequest\n";

}

void SecuritySubsystem::SecAuthStateConfirm(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId, const BaseTypes::CredentialBasedAuthState &credentialBasedAuthState, const BaseTypes::DateAndTime &receptionTime)
{
    std::cerr << "SecuritySubsystem::SecAuthStateConfirm\n";
}

void SecuritySubsystem::sendAccessControlPdu()
{
    BaseTypes::AppId appId(100);
    BaseTypes::SessionId sessionId(11);
    BaseTypes::Data data({0x05, 0x06});
    if (auto sptr = alAPI.lock()) {
        sptr->SecALAccessControlRequest(appId, sessionId, data);
    }
}
