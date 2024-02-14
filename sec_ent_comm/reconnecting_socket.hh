#pragma once

#include <boost/asio.hpp>

using boost::asio::ip::tcp;
#include <iostream>

#define SEC_ENT_ADDR "localhost"
#define SEC_ENT_PORT 3912

class reconnecting_socket {
public:
	reconnecting_socket(boost::asio::io_service& io_service, const std::string& ip, int port)
	: io_service_(io_service)
	, port_(port)
	, ip_(ip) {
	};

	void reconnect() {
		if (socket_) {
			socket_->close();
		}
		tcp::resolver resolver(io_service_);
		tcp::resolver::query query(ip_, std::to_string(port_));
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

		socket_.reset(new tcp::socket(io_service_));
		std::cerr << "Connect\n";
		boost::asio::connect(*socket_, endpoint_iterator);
	}

	tcp::socket& socket() {
		return *socket_;
	}
private:
	boost::asio::io_service& io_service_;
	int port_;
	std::string ip_;
	std::unique_ptr<tcp::socket> socket_;
};