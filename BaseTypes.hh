#pragma once

#include <cstdint>
#include <string>
#include <iostream>


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
    
    // 1609.2 Types
    typedef std::vector<uint8_t> Certificate;
    typedef std::vector<uint8_t> SignedData;
    typedef std::vector<uint8_t> SignedDataVerificationParams;
} // namespace BaseTypes

template<class... Args1, class... Args2 >
void call_function(std::function<void(Args1...)> fn, Args2... args) {
    if (!fn) {
        std::cerr << "function not specified\n";
    } else {
        fn(args...);
    }
}