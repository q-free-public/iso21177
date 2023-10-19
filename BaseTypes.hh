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
} // namespace BaseTypes