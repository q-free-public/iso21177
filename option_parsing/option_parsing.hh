#pragma once
#include <boost/program_options.hpp>

#include "BaseTypes.hh"

class OptionParsing {
public:
    OptionParsing();
    bool parseOptions(int argc, const char *argv[]);
    void print_help();
    bool helpWanted();
    std::string getSecEntHost();
    int getSecEntPort();
    int getAppPort();
    std::string getRfc8902Cert();
    bool getRfc8902UseAT();
    uint64_t getRfc8902AID();
    int getIso2177SessionId();
    uint64_t getMessageSigningAID();
    std::string getMessageSigningCert();
    bool getMessageSigningCertUseDefault();
    bool getVerbose();
private:
    bool help_needed;
    std::string sec_ent_host;
    int sec_ent_port;
    int application_port;
    bool rfc_8902_AT;
    uint64_t rfc_8902_AID;
    std::string rfc_8902_CERT;
    std::string message_signing_CERT;
    uint64_t message_signing_AID;
    int sessionId;
    bool verbose;

    boost::program_options::options_description desc_;
};