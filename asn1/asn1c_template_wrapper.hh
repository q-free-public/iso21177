#pragma once

#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

#include "../BaseTypesGeneral.hh"

template <class T>
class asn1c_wrapper {
public:
    typedef T ASN1C_TYPE;
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
        this->parseFromBuff(data);
    }
    asn1c_wrapper(const asn1c_wrapper<T>& other)
    : asn1c_wrapper(other.asn1c_def_, other.getEncodedBuffer()) {
    }
    ~asn1c_wrapper() {
        if (data_) {
            ASN_STRUCT_FREE(*asn1c_def_, data_.release());
        }
    }
    void operator=(const asn1c_wrapper<T>& other) {
        if (data_) {
            ASN_STRUCT_FREE(*asn1c_def_, data_.release());
        }
        this->parseFromBuff(other.getEncodedBuffer());
    }
    std::vector<uint8_t> getEncodedBuffer() const {
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


    void debugPrint() const {
        xer_fprint(stdout, asn1c_def_, data_.get());
    }

    template <class ELEM_T>
    void setElement(typename ELEM_T::ASN1C_TYPE * destElem, ELEM_T&& value) {
        typename ELEM_T::ASN1C_TYPE * ptr = value.releaseAsn1cData();
        memcpy(destElem, ptr, sizeof(typename ELEM_T::ASN1C_TYPE));
        free(ptr);
    };

private:
    void parseFromBuff(const std::vector<uint8_t>& data) {
        if (asn1c_def_ == nullptr) {
            throw std::runtime_error("invalid asn_TYPE_descriptor_t");
        }
        T *el_ = 0;
        asn_dec_rval_t rval = oer_decode(0, asn1c_def_, (void**)&el_, data.data(), data.size());
        data_ = std::unique_ptr<T>(el_);
        if (rval.consumed != data.size()) {
            throw std::runtime_error("ASN.1: Mismatch in consumed data: " + std::to_string(rval.consumed) + " expected " + std::to_string(data.size()) + 
                "\n" + hex_string(data));
        }
    }

    T* releaseAsn1cData() {
        return data_.release();
    }

    template <class X>
    friend class asn1c_wrapper;

protected:
    std::unique_ptr<T> data_;
private:
    asn_TYPE_descriptor_t *asn1c_def_;
};