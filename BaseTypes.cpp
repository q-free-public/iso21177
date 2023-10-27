#include "BaseTypes.hh"

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

BaseTypes::Socket createServerSocket(int port)
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

    return BaseTypes::Socket(s);
}

BaseTypes::Socket createClientSocket(int port)
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

    return BaseTypes::Socket(s);
}

void testAccept(BaseTypes::Socket sock)
{
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    if (client < 0) {
        perror("TEST accept");
    } else {
        std::cerr << "TEST accept worked " << client << "\n";
    }
}
