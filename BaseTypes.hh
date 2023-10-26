#pragma once

#include <cstdint>
#include <string>
#include <iostream>
#include <vector>
#include <functional>


namespace BaseTypes {
    // 7.7.1 App-Sec-Configure Request
    typedef uint64_t AppId;
    enum class Role { CLIENT, SERVER};
    typedef int Socket;
    enum class SessionType { INTERNAL, EXTERNAL };
    enum class TransportMechanismType { RELIABLE, UNRELIABLE};
    typedef std::string CryptomaterialHandle;
    typedef int SessionId;
    typedef std::vector<uint8_t> CertPermissionsPattern;
    typedef uint64_t TimePeriod;
    typedef std::string NameConstraints;
    typedef std::string IssuerConstraints;
    typedef std::vector<uint8_t> Data;
    typedef std::string SigningParameters;
    enum class EnumeratedSecLayer { SECURITY_SUBSYSTEM, SECURE_SESSION_SERVICE, APPLICATION};
    typedef int SecureSessionInstanceId;
    typedef std::string DateAndTime;
    typedef std::string Location;
    
    // 1609.2 Types
    typedef uint64_t AID;
    typedef std::vector<uint8_t> SSP;
    typedef std::vector<uint8_t> HashedId8;
    typedef std::vector<uint8_t> Certificate;
    typedef std::vector<uint8_t> SignedData;
    typedef std::vector<uint8_t> SignedDataVerificationParams;


    struct CredentialBasedAuthState {
        AID aid;
        SSP ssp;
        HashedId8 certId;
        DateAndTime receptionTime;
    };
} // namespace BaseTypes

template<class... Args1, class... Args2 >
void call_function(std::function<void(Args1...)> fn, Args2... args) {
    if (!fn) {
        std::cerr << "function not specified\n";
    } else {
        fn(args...);
    }
}

BaseTypes::Socket createServerSocket(int port);
BaseTypes::Socket createClientSocket(int port);