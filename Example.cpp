#include "ApplicationElementExample.hh"
#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

int main() {
    SecuritySubsystemAppAPI secSubsystem;
    ApplicationElementExample appEx(secSubsystem);
    std::cerr <<"Init DONE\n";
    auto secAPI = appEx.getSecuritySubsystemAppAPI();
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
    return 1;
}