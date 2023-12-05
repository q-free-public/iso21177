#include <memory>
#include <iostream>

#include "AppFullInstance.hh"
#include "SecureSession/SecureSessionTLS.hh"


int main() {
    AppFullInstance appClient(std::make_shared<SecureSessionTLS>(SecureSessionTLS()));

    appClient.configureApplication(456, BaseTypes::Role::CLIENT);
    std::cerr << "====> Client now configured\n";
    // Now client sends data
    std::cerr << "Type data to send, type exit to quit\n";
    for (std::string line; std::getline(std::cin, line);) {
        std::cout << "Sending " << line << std::endl;
        if (line == "exit") {
            break;
        }
        BaseTypes::Data clientMessage(line.begin(), line.end());
        appClient.sendData(clientMessage);
        std::cerr << "====> Client wil receive data\n";
        appClient.waitForNetworkInput();
    }
}