#pragma once

#include <cstdint>
#include <string>


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
    
    // 1609.2 Types
    typedef std::vector<uint8_t> Certificate;
    typedef std::vector<uint8_t> SignedData;
} // namespace BaseTypes