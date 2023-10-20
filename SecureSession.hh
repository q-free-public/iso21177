#pragma once

#include "SecureSessionSecSubAPI.hh"

class SecureSession {
public:
    SecureSession();
    SecureSessionSecSubAPI& getSecSubAPI();

private:
    SecureSessionSecSubAPI secSubAPI;
};