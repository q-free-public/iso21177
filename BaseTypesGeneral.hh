#pragma once

#include <cstdint>
#include <string>
#include <iostream>
#include <vector>
#include <functional>
#include <sstream>
#include <ostream>
#include <iomanip>
#include <memory>

namespace Asn1Helpers {
    class Ieee1609Dot2Data;
}

namespace BaseTypes {
    // 7.7.1 App-Sec-Configure Request
    typedef uint64_t AppId;
    enum class Role { CLIENT, SERVER};
    enum class SessionType { INTERNAL, EXTERNAL };
    enum class TransportMechanismType { RELIABLE, UNRELIABLE};
    typedef std::array<uint8_t, 8> CryptomaterialHandle;
    typedef int SessionId;
    typedef std::vector<uint8_t> CertPermissionsPattern;
    typedef uint64_t TimePeriod;
    typedef std::string NameConstraints;
    typedef std::string IssuerConstraints;
    typedef std::vector<uint8_t> Data;
    enum class EnumeratedSecLayer { SECURITY_SUBSYSTEM, SECURE_SESSION_SERVICE, APPLICATION};
typedef int SecureSessionInstanceId;
    typedef std::string DateAndTime;
    typedef std::string Location;
    
    // 1609.2 Types
    typedef uint64_t AID;
    typedef std::vector<uint8_t> SSP;
    typedef std::array<uint8_t, 8> HashedId8;
    typedef std::vector<uint8_t> Certificate;
    typedef Asn1Helpers::Ieee1609Dot2Data SignedData;
    typedef std::vector<uint8_t> SignedDataVerificationParams;
    typedef uint64_t Time32;


    struct SigningParameters {
        AID aid;
        HashedId8 certId;
    };
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

template<class T, class F>
void call_function_wptr(std::weak_ptr<T> el, F fn) {
    if (std::shared_ptr<T> sptr = el.lock()) {
        fn(sptr);
    } else {
        std::cerr << "Weak pointer is uninitialized\n";
        throw std::runtime_error("Unable to lock weak pointer");
    }
}

template <class T>
std::string hex_string(const T& data) {
    std::stringstream ss;
    ss << "[" << data.size() << "]";
    ss << std::hex << std::setfill('0');
    for (auto it : data) {
        ss << std::setw(2) << static_cast<unsigned>(it) << ":";
    }
    return ss.str();
}

