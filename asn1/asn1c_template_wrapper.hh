#pragma once

#include <array>
#include <memory>
#include <stdexcept>

template <class T>
class asn1c_wrapper {
public:
    asn1c_wrapper(asn_TYPE_descriptor_t * def) 
    : asn1c_def_(def) {
        if (def == nullptr) {
            throw std::runtime_error("invalid asn_TYPE_descriptor_t");
        }
        data_ = std::unique_ptr<T>(static_cast<T *>(calloc(1, sizeof(T))));
        memset(data_.get(), 0, sizeof(T));
    }
    asn1c_wrapper(asn_TYPE_descriptor_t * def, const std::vector<uint8_t>& data)
    : asn1c_def_(def) {
        if (def == nullptr) {
            throw std::runtime_error("invalid asn_TYPE_descriptor_t");
        }
        T *el_ = 0;
        asn_dec_rval_t rval = oer_decode(0, asn1c_def_, (void**)&el_, data.data(), data.size());
        data_ = std::unique_ptr<T>(el_);
        if (rval.consumed != data.size()) {
            throw std::runtime_error("Mismatch in consumed data: " + std::to_string(rval.consumed) + " " + std::to_string(data.size()));
        }
    }
    ~asn1c_wrapper() {
        if (data_) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(*asn1c_def_, data_.get());
        }
    }
    std::vector<uint8_t> getEncodedBuffer() {
        std::array<uint8_t, 65535> buffer;

        asn_enc_rval_t rval = oer_encode_to_buffer(asn1c_def_, nullptr,
                data_.get(), buffer.data(), buffer.size());
        std::vector<uint8_t> ret;
        if (rval.encoded < 0) {
            return ret;
        }

        ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
        return ret;
    }

    void debugPrint() {
        xer_fprint(stdout, asn1c_def_, data_.get());
    }

protected:
    std::unique_ptr<T> data_;
private:
    asn_TYPE_descriptor_t *asn1c_def_;
};