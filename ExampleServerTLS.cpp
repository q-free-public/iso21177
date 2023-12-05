#include <memory>
#include <iostream>

#include "AppFullInstance.hh"
#include "SecureSession/SecureSessionTLS.hh"
#include "ApplicationTLS.hh"


int main() {
    std::shared_ptr<ApplicationTLS> appTls = std::make_shared<ApplicationTLS>();
    std::shared_ptr<SecureSessionTLS> secSess = std::make_shared<SecureSessionTLS>();

    AppFullInstance appServ(
        secSess,
        appTls);

    appTls->configureApp(123, BaseTypes::Role::SERVER);
    std::cerr << "App configured\n";
    //appServ.configureApplication(123, BaseTypes::Role::SERVER);
    std::cerr << "====> Server will check for incoming sessions\n";
    secSess->waitForNetworkInput();
    std::cerr << "Client connected to the server\n";
    while (true) {
        std::cerr << "====> Server wil receive data\n";
        secSess->waitForNetworkInput();

        std::cerr << "====> Server will send out data\n";
        BaseTypes::Data serverMessage = {0x02, 0x04, 0x06};
        appTls->sendDataUnsecured(serverMessage);
    }
    // Now client sends data
}