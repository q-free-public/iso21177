#include "sec_ent_messages.hh"
#include "BaseTypes.hh"

sec_ent_msg::sec_ent_msg(uint8_t msg_type, uint32_t msg_len, const std::vector<uint8_t>& payload)
: msg_type(msg_type)
, msg_len(msg_len)
, payload(payload) {
    if (msg_len > max_body_len()) {
            throw std::runtime_error("sec_ent_msg too big, len: " + std::to_string(msg_len));
    }
    if (payload.size() != msg_len) {
        throw std::runtime_error("sec_ent_msg - len mismatch, payload len : " + std::to_string(payload.size()) + 
        " declared " + std::to_string(msg_len));
    }
}

sec_ent_msg::sec_ent_msg(uint8_t msg_type, uint32_t msg_len)
: msg_type(msg_type)
, msg_len(msg_len)
, payload() {
    if (msg_len > max_body_len()) {
            throw std::runtime_error("sec_ent_msg too big, len: " + std::to_string(msg_len));
    }
}

sec_ent_msg::sec_ent_msg(uint8_t msg_type, const std::vector<uint8_t>& payload)
: sec_ent_msg(msg_type, payload.size(), payload)
{
}

std::vector<uint8_t> sec_ent_msg::serialize()
{
    std::vector<uint8_t> ret(SEC_ENT_MSG_HDR_LEN + payload.size());
    ret[0] = msg_type;
    uint32_t network_int = htonl(msg_len);
    memcpy(&ret.data()[1], &network_int, sizeof(network_int));
    std::copy(payload.begin(), payload.end(), ret.begin() + SEC_ENT_MSG_HDR_LEN);
    return ret;
}

sec_ent_msg sec_ent_msg::parse_header(const std::vector<uint8_t> &data)
{
    if (data.size() < SEC_ENT_MSG_HDR_LEN) {
        throw std::runtime_error("Message to parse is shorter than the header");
    }
    uint8_t msg_type = data[0];
    uint32_t network_int;
    memcpy(&network_int, &data.data()[1], sizeof(network_int));
    uint32_t msg_len = ntohl(network_int);
    
    return sec_ent_msg(msg_type, msg_len);
}

sec_ent_msg sec_ent_msg::parse_all(const std::vector<uint8_t>& data)
{
    sec_ent_msg ret = parse_header(data);
    ret.parse_payload(std::vector<uint8_t>(data.begin() + SEC_ENT_MSG_HDR_LEN, data.end()));
    return ret;
}

void sec_ent_msg::parse_payload(const std::vector<uint8_t> &data)
{
    if (data.size() != msg_len) {
        throw std::runtime_error("sec_ent_msg - len mismatch, payload len : " + std::to_string(data.size()) + 
        " declared " + std::to_string(msg_len));
    }
    this->payload = data;
}

sec_ent_msg_sign_req::sec_ent_msg_sign_req(
        const Asn1Helpers::SignerIdentifier &sig_id, 
        const std::vector<uint8_t> &tbs_data)
: signer_id(sig_id)
, tbs_data(tbs_data)
{

}

std::vector<uint8_t> sec_ent_msg_sign_req::serialize_payload() const
{
    std::vector<uint8_t> signer_encoded = signer_id.getEncodedBuffer();
    std::vector<uint8_t> ret(signer_encoded.size() + tbs_data.size() + 1);
    std::copy(signer_encoded.begin(), signer_encoded.end(), ret.begin());
    std::copy(tbs_data.begin(), tbs_data.end(), ret.begin() + signer_encoded.size());
    // key_present == false
    ret[signer_encoded.size() + tbs_data.size()] = 0x00;

    return ret;
}

sec_ent_msg_sign_reply::sec_ent_msg_sign_reply(const Asn1Helpers::Ieee1609Dot2Data &signed_data)
: signed_data(signed_data)
{
}

sec_ent_msg_sign_reply sec_ent_msg_sign_reply::parse_payload(const std::vector<uint8_t> payload)
{
    Asn1Helpers::Ieee1609Dot2Data data(payload);
    return sec_ent_msg_sign_reply(data);
}

const Asn1Helpers::Ieee1609Dot2Data &sec_ent_msg_sign_reply::getSignedData()
{
    return signed_data;
}

sec_ent_msg_failure::sec_ent_msg_failure(const std::string &msg)
: message_(msg)
{
}

sec_ent_msg_failure sec_ent_msg_failure::parse_payload(const std::vector<uint8_t> data)
{
    std::string msg(data.begin(), data.end());
    return sec_ent_msg_failure(msg);
}

std::vector<uint8_t> sec_ent_get_at_req::serialize_payload() const
{
    return std::vector<uint8_t>();
}

sec_ent_get_at_reply::sec_ent_get_at_reply(const BaseTypes::HashedId8 &hash)
: at_hash_(hash)
{
}

sec_ent_get_at_reply sec_ent_get_at_reply::parse_payload(const std::vector<uint8_t>& payload)
{
    return sec_ent_get_at_reply(array_from_vector<8>(payload));
}

const BaseTypes::HashedId8 &sec_ent_get_at_reply::getATHash()
{
    return at_hash_;
}
