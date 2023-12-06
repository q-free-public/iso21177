#pragma once

#define HASHEDID8_LEN 8
#define MAX_SSP_LEN 100
#define SEC_ENT_MSG_HDR_LEN 5
#define SEC_ENT_MSG_TYPE_FAILURE 3
#define SEC_ENT_MSG_TYPE_SIGN_DATA 4
#define SEC_ENT_MSG_TYPE_GET_CERT 8
#define SEC_ENT_MSG_TYPE_VERIFY_DATA 10
#define SEC_ENT_MSG_TYPE_GET_AT 22

#define PSID_DEFAULT 36
#define SEC_ENT_ADDR_DEFAULT "127.0.0.1"
#define SEC_ENT_PORT_DEFAULT 3999

#include <vector>
#include <stdint.h>
#include <cstring>
#include <stdexcept>
#include <limits>

#include "netinet/in.h"

#include "asn1/SignerIdentifier.hh"
#include "asn1/Ieee1609Dot2Data.hh"

class sec_ent_msg {
private:
    sec_ent_msg(uint8_t msg_type, uint32_t msg_len, const std::vector<uint8_t>& payload);
public:
    sec_ent_msg(uint8_t msg_type, const std::vector<uint8_t>& payload);
    
    std::vector<uint8_t> serialize();

    static sec_ent_msg parse_all(const std::vector<uint8_t>& data);
    void parse_payload(const std::vector<uint8_t>& data);
    static sec_ent_msg parse_header(const std::vector<uint8_t>& data);

    static constexpr uint32_t max_body_len() {
		return ((uint32_t) std::numeric_limits<uint32_t>::max())/2;
	};

public:
    uint8_t msg_type;
    uint32_t msg_len;
    std::vector<uint8_t> payload;
};

template <class T>
std::vector<uint8_t> serialize_message(const T msg) {
    std::vector<uint8_t> payload = msg.serialize_payload();
    sec_ent_msg helper;
    helper.msg_type = msg.type();
    helper.msg_len = payload.size();
    helper.payload = payload;
    return helper.serialize();
}

template <class T>
T parse_message(const std::vector<uint8_t>& data) {
    sec_ent_msg msg_base = sec_ent_msg::parse_all(data);
    if (msg_base.msg_type != T::type()) {
        throw std::runtime_error("Type mismatch - expected " + std::to_string(T::type()) + 
        " got : " + std::to_string(msg_base.msg_type));
    }
    return T::parse_payload(msg_base.payload);
}

class sec_ent_msg_failure {
public:
    sec_ent_msg_failure(const std::string& msg);
    static sec_ent_msg_failure parse_payload(const std::vector<uint8_t> payload);
    static uint8_t type() { return SEC_ENT_MSG_TYPE_FAILURE; };
    const std::string& message() const { return message_; };
private:
	std::string message_;
};

class sec_ent_msg_sign_req {
public:
    sec_ent_msg_sign_req(const Asn1Helpers::SignerIdentifier& sig_id, const std::vector<uint8_t>& tbs_data);
    virtual std::vector<uint8_t> serialize_payload() const;
    static uint8_t type() { return SEC_ENT_MSG_TYPE_SIGN_DATA; };
private:
    Asn1Helpers::SignerIdentifier signer_id;
    std::vector<uint8_t> tbs_data;

};

class sec_ent_msg_sign_reply {
public:
    sec_ent_msg_sign_reply(const Asn1Helpers::Ieee1609Dot2Data& signed_data);
    static sec_ent_msg_sign_reply parse_payload(const std::vector<uint8_t> payload);
    static uint8_t type() { return SEC_ENT_MSG_TYPE_SIGN_DATA; };
private:
    Asn1Helpers::Ieee1609Dot2Data signed_data;
};
