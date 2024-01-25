#include <memory>
#include <iostream>

#include "AppFullInstance.hh"
#include "SecureSession/SecureSessionTLS.hh"
#include "ApplicationTLS.hh"
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

    std::shared_ptr<ApplicationTLS> appTls = std::make_shared<ApplicationTLS>();
    std::shared_ptr<SecureSessionTLS> secSess = std::make_shared<SecureSessionTLS>();

    SecEnt::SecEntCommunicator secEntComm(options.getSecEntHost(), options.getSecEntPort());
    BaseTypes::CryptomaterialHandle cryptoHandle = BaseTypes::CryptomaterialHandle(parse_hex_array<8>(options.getRfc8902Cert()));
    if (options.getRfc8902UseAT()) {
        std::cerr << "Using AT for RFC8902 cert\n";
        cryptoHandle = secEntComm.getCurrentATCert();
        std::cerr << hex_string(cryptoHandle) << "\n";
    }

    AppFullInstance appServ(
        secEntComm,
        secSess,
        appTls);

    BaseTypes::SessionId sessionId = options.getIso2177SessionId();;
    BaseTypes::Role role = BaseTypes::Role::SERVER;
    BaseTypes::AppId appId = options.getRfc8902AID();
    appTls->configureApp(options.getAppPort(), sessionId, role, appId, cryptoHandle);
    std::cerr << "App configured\n";
    auto dataRecvCbFn = [&](const std::vector<uint8_t>& data, SecuritySubsystemAppAPI::AppSecIncomingConfirmResult result) {
        std::cerr << "Data Received callback \n";
        Asn1Helpers::Ieee1609Dot2Data parsed_data(data);
        parsed_data.debugPrint();
        std::cerr << hex_string(parsed_data.getPayload()) << "\n";
        std::cerr << "====> Server will send out data\n";
        switch (parsed_data.getType()) {
            case Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData:
                appTls->sendDataUnsecured(parsed_data.getPayload());
                break;
            case Asn1Helpers::Ieee1609Dot2Data::type::SignedData:
                appTls->sendDataSecured(parsed_data.getPayload());
                break;
            default:
                break;
        }
        
    };
    appTls->registerDataReceivedCallback(dataRecvCbFn);
    //appServ.configureApplication(123, BaseTypes::Role::SERVER);
    while (true) {
        std::cerr << "====> Server will wait for incoming sessions\n";
        if (!secSess->waitForNetworkInput()) {
            std::cerr << "Incoming session failed, waiting for the next one\n";
            continue;
        }
        std::cerr << "Client connected to the server\n";
        while (true) {
            std::cerr << "====> Server wil receive data\n";
            if (!secSess->waitForNetworkInput()) {
                std::cerr << "client disconnected\n";
                break;
            }

            std::cerr << "====> Server will send out data\n";
            // BaseTypes::Data serverMessage = {0xAA, 0xBB, 0xCC, 0xDD};
            // appTls->sendDataUnsecured(serverMessage);
        }
    }
}