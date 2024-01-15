#pragma once

#include <boost/asio.hpp>
#include "reconnecting_socket.hh"

class SecEntCommState {
public:
    SecEntCommState(const std::string addr, int port);
    reconnecting_socket& get_sock();

private:
    boost::asio::io_service io_service_;
    reconnecting_socket socket_;

};

template<class Tret, class Treq>
Tret send_recv(reconnecting_socket& socket, const Treq& req);
