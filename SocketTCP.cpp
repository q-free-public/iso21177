#include "SocketTCP.hh"

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <stdexcept>
#include <iostream>


static int createServerSocket(int port)
{
    int s;
    struct sockaddr_in addr;
    int opt = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET,
                SO_REUSEADDR | SO_REUSEPORT, &opt,
                sizeof(opt))) {
        perror("setsockopt");
        return -1;
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        return -1;
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        return -1;
    }

    return s;
}

static int createClientSocket(int port)
{
    int s;
    struct sockaddr_in addr;
    int opt = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        return -1;
    }

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported \n");
        return -1;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection Failed \n");
        return -1;
    }

    return s;
}

SocketTCP::SocketTCP(Socket::Type type, int port)
: Socket(type)
{
    switch (type_) {
        case Socket::Type::CLIENT: {
            this->sock_ = std::make_unique<int>(createClientSocket(port));
            break;
        }
        case Socket::Type::SERVER: {
            this->sock_ = std::make_unique<int>(createServerSocket(port));
            break;
        }
    }
    if (!(this->sock_) || getFd() <= 0) {
        throw std::runtime_error("failed to create socket");
    }
}

SocketTCP::~SocketTCP()
{
    closeSocket();
}

SocketTCP::SocketTCP(std::unique_ptr<int>&& sock)
: Socket(Socket::Type::SERVER)
, sock_(std::move(sock))
{
}

void SocketTCP::getData(std::vector<uint8_t> &data)
{
    std::array<uint8_t, 1024> buffer;

    int received = recv(getFd(), buffer.data(), buffer.size(), 0);
    std::cerr << "received " << received << "\n";
    if (received < 0) {
        perror("recv failed\n");
        return;
    }
    std::copy(buffer.begin(), buffer.begin() + received, std::back_inserter(data));
}

std::unique_ptr<Socket> SocketTCP::acceptConnection()
{
    if (type_ != Socket::Type::SERVER) {
        std::cerr << "Unable to accept connection on a client socket\n";
        throw std::runtime_error("Unable to accept connection on a client socket");
    }
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    int client = accept(getFd(), (struct sockaddr*)&addr, &len);
    if (client < 0) {
        perror("accept");
    }
    return std::unique_ptr<SocketTCP>(new SocketTCP(std::move(std::make_unique<int>(client))));
}

int SocketTCP::sendData(const std::vector<uint8_t> &data)
{
    return send(getFd(), data.data(), data.size(), 0);
}

void SocketTCP::closeSocket()
{
    if (this->sock_) {
        std::cerr << "Closing socket\n";
        close(getFd());
        this->sock_.reset();
    }
}

int SocketTCP::getFd()
{
    return (*this->sock_.get());
}
