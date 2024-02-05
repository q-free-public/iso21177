#include <boost/asio.hpp>

#include "reconnecting_socket.hh"
#include "sec_ent_messages.hh"
#include "sec_ent_comm.hh"

template<class Tret, class Treq>
Tret send_recv(reconnecting_socket& socket, const Treq& req) {
	static_assert(Treq::type() == Tret::type(), "Request and response have the same header value");
	socket.reconnect();

	boost::system::error_code ec;

	boost::asio::write(socket.socket(),
			boost::asio::buffer(serialize_message(req)),
			boost::asio::transfer_all());

	// read & decode header
    std::vector<uint8_t> recv_hdr(SEC_ENT_MSG_HDR_LEN);
	boost::asio::read(socket.socket(),
			boost::asio::buffer(recv_hdr.data(), recv_hdr.size()),
			boost::asio::transfer_all());
	sec_ent_msg recv_msg(sec_ent_msg::parse_header(recv_hdr));

	// read contents
    std::vector<uint8_t> recv_payload(recv_msg.msg_len);
	boost::asio::read(socket.socket(),
			boost::asio::buffer(recv_payload.data(), recv_payload.size()),
			boost::asio::transfer_all(), ec);

	if (ec != boost::system::errc::success && ec != boost::asio::error::eof) {
		throw boost::system::system_error(ec); // Some other error.
	}
	recv_msg.parse_payload(recv_payload);
//	std::cout << "Received message: " << recv_msg.to_string() << "\n";

	uint8_t header = recv_msg.msg_type;
	if (header != Tret::type()) {
		switch(header) {
		case SEC_ENT_MSG_TYPE_FAILURE: {
			sec_ent_msg_failure failure_msg = sec_ent_msg_failure::parse_payload(recv_msg.payload);
			throw std::runtime_error("Failure: \n"  + failure_msg.message());
			break;
		}
		default: {
			throw std::runtime_error("Unsupported message received : "  + std::to_string(recv_msg.msg_type));
		}
		}
	}
	return Tret::parse_payload(recv_msg.payload);
}

template
sec_ent_msg_sign_reply send_recv(reconnecting_socket& socket, const sec_ent_msg_sign_req& req);
template
sec_ent_get_at_reply send_recv(reconnecting_socket& socket, const sec_ent_get_at_req& req);
template
sec_ent_msg_verify_reply send_recv(reconnecting_socket& socket, const sec_ent_msg_verify_req& req);



SecEntCommState::SecEntCommState(const std::string addr, int port)
: socket_(io_service_, addr, port)
{
}

reconnecting_socket &SecEntCommState::get_sock()
{
    return this->socket_;
}
