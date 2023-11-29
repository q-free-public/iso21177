#include "AdaptorLayerPDU.hh"

AdaptorLayerPdu::AdaptorLayerPdu(std::integral_constant<type, type::APDU> i, const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Iso21177AdaptorLayerPdu)
{
    data_->messageId = Iso21177AdaptorLayerPdu__value_PR_Apdu;
    data_->value.present = Iso21177AdaptorLayerPdu__value_PR_Apdu;
    OCTET_STRING_fromBuf(&data_->value.choice.Apdu, (const char *)(data.data()), data.size());
}

AdaptorLayerPdu::AdaptorLayerPdu(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Iso21177AdaptorLayerPdu, data)
{
}

AdaptorLayerPdu::type AdaptorLayerPdu::getType() const
{
    switch (data_->messageId) {
    case Iso21177AdaptorLayerPdu__value_PR_Apdu:
        return type::APDU;
    case Iso21177AdaptorLayerPdu__value_PR_AccessControl:
        return type::AccessControl;
    case Iso21177AdaptorLayerPdu__value_PR_TlsClientMsg1:
        return type::TlsClientMsg1;
    case Iso21177AdaptorLayerPdu__value_PR_TlsServerMsg1:
        return type::TlsServerMsg1;
    default:
        return type::NOTHING;
    }
}

const std::vector<uint8_t> AdaptorLayerPdu::getPayload() const
{
    std::vector<uint8_t> ret;

    switch (getType()) {
    case type::APDU:
    {
        OCTET_STRING_t *payload = &data_->value.choice.Apdu;
        ret.assign(payload->buf, payload->buf + payload->size);
        break;
    }
    case type::AccessControl: 
    {
        std::array<uint8_t, 65535> buffer;
        asn_enc_rval_t rval = oer_encode_to_buffer(&asn_DEF_Iso21177AccessControlPdu, nullptr,
            &data_->value.choice.AccessControl, buffer.data(), buffer.size());
        if (rval.encoded < 0) {
            return ret;
        }
        ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
        break;
    }
    //TODO: implement other types here
    default:
        break;
    }
    return ret;

}