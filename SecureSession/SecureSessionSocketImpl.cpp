#include "SecureSessionSocketImpl.hh"

#include <sys/socket.h>

SecureSessionSocketImpl::SecureSessionSocketImpl(int portNum)
{
    // Creating socket file descriptor
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
}