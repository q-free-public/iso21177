#include "SocketTLS.hh"

#include <iostream>

#include <arpa/inet.h>


char sec_ent_ip[INET_ADDRSTRLEN] = "192.168.21.247";
short unsigned int sec_ent_port = 3999;

bool force_x509 = false;
bool use_AT_cert = true;
#define CERT_HASH_LEN 8
unsigned char __1609dot2_ec_cert_hash[CERT_HASH_LEN] = {
	0xC4, 0x3B, 0x88, 0xB2, 0x35, 0x81, 0xDD, 0x3B
};
bool set_cert_psid = false;
uint64_t __1609dot2_psid = 623;

static int ssl_set_RFC8902_values(SSL *ssl, int server_support, int client_support) {
	if (!SSL_enable_RFC8902_support(ssl, server_support, client_support, use_AT_cert)) {
		fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (force_x509) {
		if (1 != SSL_use_PrivateKey_file(ssl, "client.key.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_PrivatKey_file failed: ");
			ERR_print_errors_fp(stderr);
			return 0;
		}
		if (1 != SSL_use_certificate_file(ssl, "client.cert.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_certificate_file failed: ");
			ERR_print_errors_fp(stderr);
			return 0;
		}
	} else {
		if (!use_AT_cert) {
			if (!SSL_use_1609_cert_by_hash(ssl, __1609dot2_ec_cert_hash)) {
				fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
		if (set_cert_psid) {
			if (!SSL_use_1609_PSID(ssl, __1609dot2_psid)) {
				fprintf(stderr, "SSL_use_1609_PSID failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
	}
	return 1;
}

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

bool SocketTLS::attemptHandshakeAsClient()
{
    std::cerr << "SocketTLS::attemptHandshakeAsClient\n";
    ssl_ = SSL_Wrapper(this->ssl_ctx_);
    if (!*ssl_) {
        fprintf(stderr, "SSL_new failed\n");
        return false;
    }
    if (!SSL_set_1609_sec_ent_addr(*ssl_, sec_ent_port, sec_ent_ip)) {
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
    if (!ssl_set_RFC8902_values(*ssl_, server_support, client_support)) {
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

bool SocketTLS::checkHandshakeAsServer()
{
    std::cerr << "SocketTLS::checkHandshakeAsServer\n";
    ssl_ = SSL_Wrapper(this->ssl_ctx_);
    if (!*ssl_) {
        fprintf(stderr, "SSL_new failed\n");
        return false;
    }
    if (!SSL_set_1609_sec_ent_addr(*ssl_, sec_ent_port, sec_ent_ip)) {
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
    if (!ssl_set_RFC8902_values(*ssl_, server_support, client_support)) {
        return false;
    }
    if (!SSL_set_fd(*ssl_, socketBase_->getFd())) {
        fprintf(stderr, "SSL_set_fd failed\n");
        return false;
    }
    int retval = SSL_accept(*ssl_);
    if (retval <= 0) {
        fprintf(stderr, "SSL_accept failed ssl_err=%d errno=%s\n",
                SSL_get_error(*ssl_, retval), strerror(errno));
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cerr << "SSL accepted.\n";
    return true;
}

void SocketTLS::getData(std::vector<uint8_t> &data)
{
}

std::unique_ptr<Socket> SocketTLS::acceptConnection()
{
    return socketBase_->acceptConnection();
}

int SocketTLS::sendData(const std::vector<uint8_t> &data)
{
    return 0;
}

void SocketTLS::closeSocket()
{
    return socketBase_->closeSocket();
}

int SocketTLS::getFd()
{
    return socketBase_->getFd();
}
