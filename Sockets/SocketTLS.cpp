#include "SocketTLS.hh"

#include <iostream>

#include "SecEntData.hh"

#define CERT_HASH_LEN 8
bool set_cert_psid = false;
uint64_t __1609dot2_psid = 623;

SocketTLS::SocketTLS(std::shared_ptr<Socket> s)
: Socket(*s.get())
, ssl_ctx_(type_)
, ssl_()
, socketBase_(s)
{
}

SocketTLS::~SocketTLS()
{
}

bool SocketTLS::attemptHandshakeAsClient(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
{
    std::cerr << "SocketTLS::attemptHandshakeAsClient\n";
    ssl_ = SSL_Wrapper(this->ssl_ctx_);
    if (!*ssl_) {
        fprintf(stderr, "SSL_new failed\n");
        return false;
    }
    if (!SSL_set_1609_sec_ent_addr(*ssl_, SecEntData::sec_ent_port, SecEntData::sec_ent_ip)) {
        fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
        ERR_print_errors_fp(stderr);
        return false;
    }
    int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    bool force_x509 = false;
    if (force_x509) {
        server_support = SSL_RFC8902_X509;
    }
    if (!this->ssl_set_RFC8902_values(server_support, client_support, appId, clientHandle)) {
        return false;
    }
    if (!SSL_set_fd(*ssl_, socketBase_->getFd())) {
        fprintf(stderr, "SSL_set_fd failed\n");
        return false;
    }
    std::cerr << "Will connect \n";
    if (SSL_connect(*ssl_) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_connect failed\n");
        return false;
    }
    return true;
}

int SocketTLS::getData(std::vector<uint8_t> &data)
{
    int received;

    std::array<uint8_t, 1024> buffer;

	received = SSL_read(*ssl_, buffer.data(), buffer.size());
	printf("SSL_read returned %d\n", received);
    if (received < 0) {
        int ssl_err = SSL_get_error(*ssl_, received);
        fprintf(stderr, "SSL_read failed: ssl_error=%d: ", ssl_err);
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "\n");
        return received;
    }
	if (received > 0) {
        std::copy(buffer.begin(), buffer.begin() + received, std::back_inserter(data));
		std::cerr << "[recv:] " << hex_string(data) << "\n";
	}
	return received;
}

std::unique_ptr<Socket> SocketTLS::acceptClientConnection()
{
    return socketBase_->acceptClientConnection();
}

void SocketTLS::connectToServer()
{
    socketBase_->connectToServer();
}

int SocketTLS::sendData(const std::vector<uint8_t> &data)
{
	int processed = 0;

	std::cerr << "Sending [" << data.size() << "] " << hex_string(data) << "\n";
    auto it = data.begin();
    while (processed < data.size()) {
		int written = SSL_write(*ssl_, &(*it), data.size() - processed);
		fprintf(stderr, "Client SSL_write returned %d\n", written);
		if (written <= 0) {
			int ssl_err = SSL_get_error(*ssl_, written);
			if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
				fprintf(stderr, "ssl_send_message failed: ssl_error=%d: ", ssl_err);
				ERR_print_errors_fp(stderr);
				fprintf(stderr, "\n");
			}
            processed = written;
            break;
		} else {
            processed += written;
        }
	};

	return processed;
}

void SocketTLS::closeSocket()
{
    return socketBase_->closeSocket();
}

int SocketTLS::getFd()
{
    return socketBase_->getFd();
}

BaseTypes::Certificate SocketTLS::getPeerCertificate()
{
    if (!peerCert_) {
        throw std::runtime_error("No peer certificate present");
    }
    return *peerCert_;
}

void SocketTLS::setPeerCertificate(const BaseTypes::Certificate &cert)
{
    this->peerCert_ = std::make_shared<BaseTypes::Certificate>(cert);
}

int SocketTLS::ssl_set_RFC8902_values(int server_support, int client_support, const BaseTypes::AID &aidToUse, const BaseTypes::CryptomaterialHandle &cryptoHandle)
{
    bool force_x509 = false;
    bool use_AT_cert = false;
    if (!SSL_enable_RFC8902_support(*ssl_, server_support, client_support, use_AT_cert)) {
        fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (force_x509) {
        if (1 != SSL_use_PrivateKey_file(*ssl_, "client.key.pem", SSL_FILETYPE_PEM)) {
            fprintf(stderr, "SSL_CTX_use_PrivatKey_file failed: ");
            ERR_print_errors_fp(stderr);
            return 0;
        }
        if (1 != SSL_use_certificate_file(*ssl_, "client.cert.pem", SSL_FILETYPE_PEM)) {
            fprintf(stderr, "SSL_CTX_use_certificate_file failed: ");
            ERR_print_errors_fp(stderr);
            return 0;
        }
    } else {
        if (!SSL_use_1609_cert_by_hash(*ssl_, cryptoHandle.data())) {
            fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
            ERR_print_errors_fp(stderr);
            return 0;
        }
        if (!SSL_use_1609_PSID(*ssl_, aidToUse)) {
            fprintf(stderr, "SSL_use_1609_PSID failed\n");
            ERR_print_errors_fp(stderr);
            return 0;
        }
    }
    return 1;
}
