#pragma once

#include "../asn1/Ieee1609Dot2Data.hh"
#include "asn1/ToBeSignedData.hh"
#include "sec_ent_comm.hh"

namespace SecEnt {
    enum class VerificationStatus {
        OK,
        FAILED,
    };

    enum class SigningStatus {
        OK,
        FAILED
    };

    class SecEntCommunicator {
    public:
        SecEntCommunicator(const std::string address = "127.0.0.1", int port = 3912);
        SecEntCommunicator(const SecEntCommunicator&) = delete;
        VerificationStatus verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data& data);
        SigningStatus signData(const Asn1Helpers::ToBeSignedData &tbsData,
            BaseTypes::CryptomaterialHandle cryptoHandle,
            Asn1Helpers::Ieee1609Dot2Data& signed_data);
        BaseTypes::CryptomaterialHandle getCurrentATCert();
        int getPort();
        std::string getHost();
    private:
        std::string address_;
        int port_;
        SecEntCommState comm_;
    };

}