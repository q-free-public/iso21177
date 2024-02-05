#include <memory>
#include <iostream>

#include "AppFullInstance.hh"
#include "ApplicationTLS.hh"
#include "SecureSession/SecureSessionTLS.hh"
#include "option_parsing/option_parsing.hh"

int main(int argc, const char *argv[]) {
    OptionParsing options;
    bool parsed = options.parseOptions(argc, argv);
    std::cerr << "Options parsed " << parsed << "\n";
    if (!parsed) {
        options.print_help();
        return 1;
    }
    if (options.helpWanted()) {
        options.print_help();
        return 0;
    }

    SecEnt::SecEntCommunicator secEntComm(options.getSecEntHost(), options.getSecEntPort());
    std::shared_ptr<ApplicationTLS> appTls = std::make_shared<ApplicationTLS>();
    std::shared_ptr<SecureSessionTLS> secSess = std::make_shared<SecureSessionTLS>(secEntComm);
    std::shared_ptr<SecuritySubsystem> secSub = std::make_shared<SecuritySubsystem>(secEntComm);
    std::shared_ptr<AdaptorLayer> adaptorLayer = std::make_shared<AdaptorLayer>();

    BaseTypes::CryptomaterialHandle cryptoHandle = BaseTypes::CryptomaterialHandle(parse_hex_array<8>(options.getRfc8902Cert()));
    if (options.getRfc8902UseAT()) {
        std::cerr << "Using AT for RFC8902 cert\n";
        cryptoHandle = secEntComm.getCurrentATCert();
        std::cerr << hex_string(cryptoHandle) << "\n";
    }

    AppFullInstance appClient(
        secEntComm, 
        secSess,
        secSub,
        adaptorLayer,
        appTls);

    BaseTypes::SessionId sessionId = options.getIso2177SessionId();
    BaseTypes::Role role = BaseTypes::Role::CLIENT;
    BaseTypes::AppId appId = options.getRfc8902AID();
    try {
        appTls->configureApp(options.getAppPort(), sessionId, role, appId, cryptoHandle);
        std::cerr << "====> Client now configured\n";
    } catch (const std::exception &e) {
        std::cerr << "Failed to configure " << e.what() << "\n";
        return 1;
    }
    BaseTypes::HashedId8 signingCert = cryptoHandle;
    if (options.getMessageSigningCert().size() != 0) {
        signingCert = (parse_hex_array<8>(options.getMessageSigningCert()));
    }
    BaseTypes::DateAndTime notBefore = "not-used";
    BaseTypes::Location location = "not-used";
    // appClient.configureApplication(456, BaseTypes::Role::CLIENT);
    auto dataRecvCbFn = [](const std::vector<uint8_t>& data, SecuritySubsystemAppAPI::AppSecIncomingConfirmResult result) {
        std::cerr << "Data Received callback \n";
        Asn1Helpers::Ieee1609Dot2Data parsed_data(data);
        parsed_data.debugPrint();
        std::cerr << hex_string(parsed_data.getPayload()) << "\n";
    };
    appTls->registerDataReceivedCallback(dataRecvCbFn);
    auto authStateCb = [](const BaseTypes::AppId& appid,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CredentialBasedAuthState& authState) {
            std::cerr << "authStateCb\n";
            std::cerr << appid << " : " << sessionId << " CredentialBasedAuthState: " 
            << authState.aid << " | " 
            << hex_string(authState.ssp) << " | " 
            << hex_string(authState.certId) << " | " 
            << authState.receptionTime << "\n";
    };
    secSub->registerAuthStateCallback(authStateCb);
    secSub->SecAuthStateRequest(appId, sessionId, notBefore, location);
    std::cerr << "=> Type data to send, type exit to quit\n";
    std::cerr << "=> if 1st character is 1, the non-repudiation is applied (signing), otherwise not\n";
    for (std::string line; std::getline(std::cin, line);) {
        std::cout << "=> Sending " << line << std::endl;
        if (line == "exit") {
            break;
        }
        try {
            BaseTypes::Data clientMessage(line.begin(), line.end());
            bool sendSecure = false;
            if (line.size() > 0) {
                if (line[0] == '1') {
                    sendSecure = true;
                }
            }
            // Now client sends data
            if (sendSecure) {
                BaseTypes::SigningParameters signParams = {options.getMessageSigningAID(), signingCert};
                appTls->sendDataSecured(clientMessage, signParams);
            } else {
                appTls->sendDataUnsecured(clientMessage);
            }
            std::cerr << "=> Client wil receive data\n";
            if (!secSess->waitForNetworkInput()) {
                std::cerr << "=> Error waiting for server data \n";
                break;
            }
            std::cerr << "=> Type data to send, type exit to quit\n";
            std::cerr << "=> if 1st character is 1, the non-repudiation is applied (signing), otherwise not\n";
        } catch (std::exception& e) {
            std::cerr << "caught: " << e.what() << "\n";
            break;
        }
    }
}