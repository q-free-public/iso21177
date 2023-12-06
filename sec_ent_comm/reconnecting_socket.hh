#pragma once

#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class reconnecting_socket {
public:
	reconnecting_socket(boost::asio::io_service& io_service, int port)
	: io_service_(io_service)
	, port_(port) {
		reconnect();
	};

	void reconnect() {
		if (socket_) {
			socket_->close();
		}
		tcp::resolver resolver(io_service_);
		tcp::resolver::query query("localhost", std::to_string(port_));
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

		socket_.reset(new tcp::socket(io_service_));
		boost::asio::connect(*socket_, endpoint_iterator);
	}

	tcp::socket& socket() {
		return *socket_;
	}
private:
	boost::asio::io_service& io_service_;
	int port_;
	std::unique_ptr<tcp::socket> socket_;
};