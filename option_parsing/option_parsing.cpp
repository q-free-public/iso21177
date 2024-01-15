#include <boost/program_options.hpp>
#include <iostream>
#include "option_parsing.hh"

OptionParsing::OptionParsing()
: desc_(boost::program_options::options_description{"Options"})
, help_needed(false)
{
}

bool OptionParsing::parseOptions(int argc, const char *argv[])
{
    bool ret = true;
    try
    {
        //boost::program_options::options_description desc{"Options"};
        desc_.add_options()
            ("help,h", "Help screen")
            ("se-host", boost::program_options::value<std::string>(&sec_ent_host)->default_value("127.0.0.1"), "Security entity IPv4 address")
            ("se-port", boost::program_options::value<int>(&sec_ent_port)->default_value(3999), "Security entity port number")
            ("rfc8902-aid", boost::program_options::value<uint64_t>(&rfc_8902_AID)->default_value(36), "Specify AID to use for RFC8902")
            ("rfc8902-cert", boost::program_options::value<std::string>(&rfc_8902_CERT), "Specify certificate hash for RFC8902(if not specified current AT is used)")
            ("rfc8902-cert", boost::program_options::value<std::string>(&rfc_8902_CERT), "Specify certificate hash for RFC8902(if not specified current AT is used)")
            ("app-port", boost::program_options::value<int>(&application_port)->default_value(2337), "Specify port for the application to use")
            ("iso21177-sessionId", boost::program_options::value<int>(&sessionId)->default_value(456), "Specify port for the application to use");

        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
        boost::program_options::notify(vm);

        if (vm.count("help")) {
            this->help_needed = true;
            ret = false;
        }
        if (vm.count("rfc8902-cert") == 0) {
            this->rfc_8902_AT = true;
        }

    }   catch (const boost::program_options::error &ex) {
        std::cerr << ex.what() << '\n';
        ret = false;
    }
    return ret;
}

void OptionParsing::print_help()
{
    std::cerr << desc_ << "\n";
}

bool OptionParsing::helpWanted()
{
    return this->help_needed;
}

std::string OptionParsing::getSecEntHost()
{
    return this->sec_ent_host;
}

int OptionParsing::getSecEntPort()
{
    return this->sec_ent_port;
}

int OptionParsing::getAppPort()
{
    return application_port;
}

std::string OptionParsing::getRfc8902Cert()
{
    return rfc_8902_CERT;
}

bool OptionParsing::getRfc8902UseAT()
{
    return rfc_8902_AT;
}

uint64_t OptionParsing::getRfc8902AID()
{
    return rfc_8902_AID;
}

int OptionParsing::getIso2177SessionId()
{
    return sessionId;
}
