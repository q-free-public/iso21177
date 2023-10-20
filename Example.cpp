#include "ApplicationElementExample.hh"
#include "SecuritySubsystemAppAPI.hh"
#include "SecureSession.hh"
#include "SecuritySubsystem.hh"

#include <iostream>

int main() {
    std::shared_ptr<SecureSession> secureSession(new SecureSession());
    std::shared_ptr<SecuritySubsystem> secSubsystem(new SecuritySubsystem());
    std::shared_ptr<ApplicationElementExample> appEx(new ApplicationElementExample());

    appEx->registerSecuritySubsystemAPI(secSubsystem);
    secSubsystem->registerSecureSessionSecSubAPI(secureSession);

    std::cerr <<"Init DONE\n";

    auto fn = [](SecuritySubsystemAppAPI& secAPI) {
        secAPI.AppSecConfigureRequest(
            11,
            BaseTypes::Role::SERVER,
            12,
            BaseTypes::SessionType::EXTERNAL,
            false,
            13, BaseTypes::TransportMechanismType::RELIABLE,
            "Very Secure Certificate");
        secAPI.AppSecConfigureRequest(
            123,
            BaseTypes::Role::SERVER,
            12,
            BaseTypes::SessionType::INTERNAL,
            true,
            13, BaseTypes::TransportMechanismType::UNRELIABLE,
            "Very Secure Certificate");
    };
    appEx->executeWithSecAPI(fn);

    return 1;
}