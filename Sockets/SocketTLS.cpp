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

bool SocketTLS::attemptHandshake(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
{
    std::cerr << "SocketTLS::attemptHandshake\n";

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
    if (!SSL_set_fd(*ssl_, this->getFd())) {
        fprintf(stderr, "SSL_set_fd failed\n");
        return false;
    }

    this->setStateSSL();
    std::cerr << "SSL_do_handshake is_server? " << SSL_is_server(*ssl_) << "\n";
    int retval = SSL_do_handshake(*ssl_);
    if (retval <= 0) {
        fprintf(stderr, "SSL_do_handshake failed ssl_err=%d errno=%s\n",
                SSL_get_error(*ssl_, retval), strerror(errno));
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cerr << "SSL string " << SSL_state_string_long(*ssl_) << "\n";
    SSL_SESSION_print_fp(stderr, SSL_get_session(*ssl_));
    std::cerr << "SSL_do_handshake done\n";

    uint64_t psid;
	size_t ssp_len;
	uint8_t *ssp = NULL;
    std::array<uint8_t, CERT_HASH_LEN> hashed_id;
	if(SSL_get_1609_psid_received(*ssl_, &psid, &ssp_len, &ssp, hashed_id.data()) <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_get_1609_psid_received failed\n");
		return false;
	}
    std::vector<uint8_t> cert(hashed_id.begin(), hashed_id.end());
    std::vector<uint8_t> ssp_vector(ssp, ssp + ssp_len);
    this->setPeerCertificate(cert);
    this->peerAuthState_ = std::make_shared<BaseTypes::CredentialBasedAuthState>(
        BaseTypes::CredentialBasedAuthState{psid, ssp_vector, hashed_id, "currrent-time"}
    );

    return true;
}

BaseTypes::Certificate SocketTLS::getPeerCertificate()
{
    if (!peerCert_) {
        throw std::runtime_error("No peer certificate present");
    }
    return *peerCert_;
}

BaseTypes::CredentialBasedAuthState SocketTLS::getPeerAuthState()
{
    if (!peerAuthState_) {
        throw std::runtime_error("No peer auth state present");
    }
    return *peerAuthState_;
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
