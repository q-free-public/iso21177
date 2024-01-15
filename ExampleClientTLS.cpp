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
    std::shared_ptr<SecureSessionTLS> secSess = std::make_shared<SecureSessionTLS>();

    BaseTypes::CryptomaterialHandle cryptoHandle = BaseTypes::CryptomaterialHandle(parse_hex_array<8>(options.getRfc8902Cert()));
    if (options.getRfc8902UseAT()) {
        std::cerr << "Using AT for RFC8902 cert\n";
        cryptoHandle = secEntComm.getCurrentATCert();
        std::cerr << hex_string(cryptoHandle) << "\n";
    }

    AppFullInstance appClient(
        secEntComm, 
        secSess,
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
    // appClient.configureApplication(456, BaseTypes::Role::CLIENT);
    // Now client sends data
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
            if (sendSecure) {
                appTls->sendDataSecured(clientMessage);
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