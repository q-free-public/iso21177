#include "SecuritySubsystem.hh"

#include <memory>
#include <iostream>
#include <functional>

#include "SecuritySubsystemAppAPI.hh"
#include "asn1/Ieee1609Dot2Data.hh"
#include "sec_ent_comm/sec_ent_api.hh"
#include "asn1/ToBeSignedData.hh"

SecuritySubsystem::SecuritySubsystem(SecEnt::SecEntCommunicator& secEntComm)
: secEntComm_(secEntComm)
{
}

void SecuritySubsystem::registerAdaptorLayerSecSubAPI(
        std::weak_ptr<AdaptorLayerSecSubAPI> aLSecSubAPI)
{
    alAPI = aLSecSubAPI;
}

void SecuritySubsystem::registerSecureSessionSecSubAPI(
        std::weak_ptr<SecureSessionSecSubAPI> secSessAPI)
{
    this->secSessAPI = secSessAPI;
}

void SecuritySubsystem::SecSessConfigureConfirm()
{
    std::cerr << "SecuritySubsystem::SecSessConfigureConfirm" << "\n";
}

void SecuritySubsystem::SecSessionStartIndication(
        const BaseTypes::AppId & appId,
        const BaseTypes::SessionId & sessId,
        const BaseTypes::Certificate & cert)
{
    std::cerr << "SecuritySubsystem::SecSessStartIndication" << "\n";
    // TODO: check access control policy
    // Access control policy == SUCCESS
    if (role_ == BaseTypes::Role::SERVER) {
        call_function_wptr(appSecuritySubsystemAPI, [&](std::shared_ptr<AppSecuritySubsystemAPI>& sptr) {
            sptr->AppSecStartSessionIndictation(appId, sessId);
        }); 
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
    role_ = role;
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
    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
        sptr->AppSecConfigureConfirm(result);
    });
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
    Asn1Helpers::Ieee1609Dot2Data signedData(std::integral_constant<Asn1Helpers::Ieee1609Dot2Data::type, Asn1Helpers::Ieee1609Dot2Data::type::NOTHING>{});
    // Call SecEnt to sign the data
    Asn1Helpers::HeaderInfo hdrInfo(signingParams.aid);
    Asn1Helpers::ToBeSignedData tbsData(std::move(hdrInfo), data);

    SecEnt::SigningStatus signStatusInternal = secEntComm_.signData(tbsData, signingParams.certId, signedData);
    SecuritySubsystemAppAPI::AppSecDataConfirmResult result 
        = SecuritySubsystemAppAPI::AppSecDataConfirmResult::SUCCESS;
    if (signStatusInternal != SecEnt::SigningStatus::OK) {
        result = SecuritySubsystemAppAPI::AppSecDataConfirmResult::FAILURE;
    }
    call_function_wptr(appSecuritySubsystemAPI, [&](std::shared_ptr<AppSecuritySubsystemAPI> sptr) {
        sptr->AppSecDataConfirm(result, signedData);
    });
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
    } else {
        Asn1Helpers::Ieee1609Dot2Data ieeeDot2Data(apdu);
        switch (ieeeDot2Data.getType()) {
            case Asn1Helpers::Ieee1609Dot2Data::type::SignedData: {
                SecEnt::VerificationStatus status =
                    secEntComm_.verifyIeee1609Dot2DataSigned(ieeeDot2Data);
                if (status != SecEnt::VerificationStatus::OK) {
                    result = Result::INVALID_SIGNED_IEEE1609DOT2_DATA;
                    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
                        sptr->AppSecIncomingConfirm(result);
                    });
                    return;
                }
                break;
            };
            case Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData: {
                break;
            }
            default: {
                result = Result::INVALID_IEEE1609DOT2DATA_TYPE;
                break;
            }
        }
    }
    if (result == Result::SUCCESS) {
        // TODO: apply the access control policy
    }
   call_function_wptr(appSecuritySubsystemAPI, 
   [&](std::shared_ptr<AppSecuritySubsystemAPI> sptr) {
        sptr->AppSecIncomingConfirm(result);
   });
}


// Triggered by the APP
void SecuritySubsystem::AppSecEndSessionRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId)
{
    std::cerr << "SecuritySubsystem::AppSecEndSessionRequest\n";
    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
        sptr->AppSecEndSessionIndication( 
            appId, sessionId, BaseTypes::EnumeratedSecLayer::APPLICATION);
    });
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
    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
        sptr->AppSecEndSessionIndication(
                appId, sessionId, BaseTypes::EnumeratedSecLayer::SECURITY_SUBSYSTEM
        );
    });
}

void SecuritySubsystem::endSession()
{
    BaseTypes::AppId appId(11);
    BaseTypes::SecureSessionInstanceId secSessId(99);
    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
        sptr->AppSecDeactivateIndication(appId, secSessId);
    });
    if (auto sptr = secSessAPI.lock()) {
        sptr->SecSessDeactivateRequest(appId, secSessId);
    }
}

void SecuritySubsystem::AppSecDeactivateRequest(
    const BaseTypes::AppId &appId,
    const BaseTypes::SecureSessionInstanceId &secureSessionId)
{
    std::cerr << "SecuritySubsystem::AppSecDeactivateRequest\n";
    call_function_wptr(appSecuritySubsystemAPI, [](auto sptr) {
        sptr->AppSecDeactivateConfirm();
    });
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
    call_function_wptr(appSecuritySubsystemAPI, [&](auto sptr) {
        sptr->AppSecEndSessionIndication(
                appId, sessionId, BaseTypes::EnumeratedSecLayer::SECURE_SESSION_SERVICE
        );
    });
    if (auto sptr = alAPI.lock()) {
        sptr->SecALEndSessionRequest(appId, sessionId);
    }
}

void SecuritySubsystem::SecSessDeactivateConfirm()
{
    std::cerr << "SecuritySubsystem::SecSessDeactivateConfirm\n";
}

void SecuritySubsystem::getAuthStateReply(const BaseTypes::AppId &appid, const BaseTypes::SessionId &sessionId, 
        const BaseTypes::CredentialBasedAuthState &authState)
{
    std::cerr << "SecuritySubsystem::getAuthStateReply\n";
    std::cerr << appid << " : " << sessionId <<  " CredentialBasedAuthState: " << authState.aid << " | " 
            << hex_string(authState.ssp) << " | " << hex_string(authState.certId) << " | " << authState.receptionTime << "\n";
    if (this->authStateCb_) {
        this->authStateCb_(appid, sessionId, authState);
    }
}

void SecuritySubsystem::SecAuthStateRequest(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId,
        const BaseTypes::DateAndTime &notBefore,
        const BaseTypes::Location &location)
{
    std::cerr << "SecuritySubsystem::SecAuthStateRequest\n";
    BaseTypes::CredentialBasedAuthState state;
    BaseTypes::DateAndTime receptionTime = "now";
    call_function_wptr(secSessAPI, [&](std::shared_ptr<SecureSessionSecSubAPI> sptr){
        sptr->getAuthState(appId, sessionId);
    });
    this->SecAuthStateConfirm(appId, sessionId, state, receptionTime);

}

void SecuritySubsystem::SecAuthStateConfirm(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId,
        const BaseTypes::CredentialBasedAuthState &credentialBasedAuthState,
        const BaseTypes::DateAndTime &receptionTime)
{
    std::cerr << "SecuritySubsystem::SecAuthStateConfirm\n";
    std::cerr << appId << " " << sessionId << " " << credentialBasedAuthState.aid << " " << hex_string(credentialBasedAuthState.certId) << "\n";
}

void SecuritySubsystem::registerAuthStateCallback(AuthStateCallback_t authCb)
{
    this->authStateCb_ = authCb;
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
