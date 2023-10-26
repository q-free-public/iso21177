#pragma once

#include "SecureSession.hh"

class SecureSessionSocketImpl : public SecureSession {
public:
    SecureSessionSocketImpl(int portNum);
private:
    int sock_fd;
};