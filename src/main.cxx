#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <string>
#include <sys/socket.h>

#include <netdb.h>
#include <unistd.h>

void print_cert_info(X509 *cert, int depth) {
  // depth = position in the chain. 0 = lead (the server's own cert),
  // 1+ = intermediates that chain up toward the root CA.
  if (depth == 0)
    std::cout << "\n--- Depth " << depth << "(leaf) ---\n";
  else
    std::cout << "\n--- Depth " << depth << "(intermediate) ---\n";

  // X509_get_subject_name() returns a pointer to the cert's Subject field.
  // This is an X509_NAME struct — a structured list of key-value pairs like
  // C=US, O=Let's Encrypt, CN=R13.
  //
  // X509_NAME_oneline() flattens that struct into a single-line string like
  // "/C=US/O=Let's Encrypt/CN=R13". Not the prettiest format, but simple.
  // For production code you'd use X509_NAME_print_ex() for RFC2253 format.
  char subject[256];
  X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
  std::cout << "  Subject: " << subject << "\n";

  // Same thing for the issuer — who signed this cert.
  // For the leaf, this is usually an intermediate CA.
  // For an intermediate, this is usually a root CA.
  char issuer[256];
  X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
  std::cout << "  Issuer:  " << issuer << "\n";

  // Every cert has a serial number — a unique integer assigned by the CA.
  // No two certs from the same CA should share a serial.
  // Used for revocation (CRLs list revoked serial numbers).
  //
  // X509_get_serialNumber() returns an ASN1_INTEGER* — a bignum in ASN.1 format.
  // i2a_ASN1_INTEGER() converts it to a hex string and writes it to a BIO.
  //
  // BIO_s_mem() creates an in-memory BIO — think of it as a string buffer.
  // We write into it, then read back with BIO_get_mem_data().
  BIO *bio = BIO_new(BIO_s_mem());
  i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
  char *buf = nullptr;
  long len = BIO_get_mem_data(bio, &buf);
  std::cout << "  Serial:  " << std::string(buf, len) << "\n";
  BIO_free(bio);

  // SANs are THE mechanism for hostname verification in modern TLS.
  // The Subject CN is legacy — browsers and OpenSSL check SANs.
  //
  // SANs are stored as an X509v3 extension, not a top-level field.
  // X509_get_ext_d2i() fetches and decodes an extension by its NID
  // (Numeric ID). NID_subject_alt_name is the SAN extension.
  //
  // It returns a GENERAL_NAMES* — a stack (dynamic array) of GENERAL_NAME
  // entries. Each entry can be a DNS name, IP address, email, URI, etc.
  // We only care about GEN_DNS (DNS hostnames).
  //
  // ASN1_STRING_to_UTF8() converts the internal ASN1 string to a regular
  // C string. You must OPENSSL_free() the result.
  GENERAL_NAMES *sans = (GENERAL_NAMES *)X509_get_ext_d2i(
      cert, NID_subject_alt_name, nullptr, nullptr);
  if (sans) {
    std::cout << "  SANs:    ";
    int num_sans = sk_GENERAL_NAME_num(sans);
    for (int i = 0; i < num_sans; i++) {
      GENERAL_NAME *san = sk_GENERAL_NAME_value(sans, i);
      if (san->type == GEN_DNS) {
        unsigned char *dns = nullptr;
        ASN1_STRING_to_UTF8(&dns, san->d.dNSName);
        if (dns) {
          if (i > 0) std::cout << ", ";
          std::cout << dns;
          OPENSSL_free(dns);
        }
      }
    }
    std::cout << "\n";
    GENERAL_NAMES_free(sans);  // Free the whole stack
  }

  // X509_get_signature_nid() returns the NID of the algorithm used by the
  // ISSUER to sign this cert. Common values:
  //   - NID_sha256WithRSAEncryption (most common today)
  //   - NID_ecdsa_with_SHA256 (used by modern CAs)
  //
  // OBJ_nid2ln() converts the NID to a long human-readable name like
  // "sha256WithRSAEncryption". OBJ_nid2sn() gives the short name.
  int sig_nid = X509_get_signature_nid(cert);
  std::cout << "  Sig Alg: " << OBJ_nid2ln(sig_nid) << "\n";
}

// Resolve hostname and open a TCP connection
int connect_to_host(const std::string &hostname, const std::string &port) {
  struct addrinfo hints{}, *res;
  hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6, whichever works
  hints.ai_socktype = SOCK_STREAM; // TCP

  // DNS lookup: hostname -> IP Address
  if (getaddrinfo(hostname.c_str(), port.c_str(), &hints, &res) != 0) {
    std::cerr << "DNS resolution failed for: " << hostname << "\n";
    return -1;
  }

  // Create socket and connect
  int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd < 0 || connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
    std::cerr << "TCP connection failed to " << hostname << ":" << port << "\n";
    freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);
  // Raw TCP file descriptor -  we hand this to OpenSSL next
  return sockfd;
}

bool check_host(const std::string &hostname, const std::string &port) {
  // 1. Create SSL Context one per application, configures TLS behavior
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    std::cerr << "Failed to create SSL context.\n";
    ERR_print_errors_fp(stderr);
    return false;
  }

  // 2. Tell OpenSSL to verify the server's certificate
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

  // 3. Load the system CA trust store (on Linux: /etx/ssl/certs/)
  if (!SSL_CTX_set_default_verify_paths(ctx)) {
    std::cerr << "Failed to load system CA certificates.\n";
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return false;
  }

  int sockfd = connect_to_host(hostname, port);
  if (sockfd < 0) {
    SSL_CTX_free(ctx);
    return false;
  }

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);

  SSL_set_tlsext_host_name(ssl, hostname.c_str());
  SSL_set1_host(ssl, hostname.c_str());

  if (SSL_connect(ssl) != 1) {
    std::cerr << "TLS Handshake failed\n";
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return false;
  }

  long verify_result = SSL_get_verify_result(ssl);
  X509 *peer_cert = SSL_get1_peer_certificate(ssl);

  bool ok = (verify_result == X509_V_OK) && (peer_cert != nullptr);

  if (!ok) {
    std::cerr << "Certificate verification failed: "
              << X509_verify_cert_error_string(verify_result) << "\n";
    if (!peer_cert)
      std::cerr << "Server sent no certificate\n";
  } else {
      std::cout << "Certificate verification successful for: " << hostname << "\n";

      // SSL_get_peer_cert_chain() returns the chain the server sent during
      // the TLS handshake. This is a STACK_OF(X509)* — a dynamic array of
      // X509 pointers.
      //
      // Index 0 = leaf cert (the server's own cert)
      // Index 1 = first intermediate
      // Index N = last intermediate
      // The root CA is NOT in this chain (it's in your trust store already).
      //
      // You do NOT free this — it's owned by the SSL object.
      // sk_X509_num() = length of the stack
      // sk_X509_value(chain, i) = get cert at index i
      STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
      if (chain) {
        int chain_len = sk_X509_num(chain);
        std::cout << "Chain length: " << chain_len << "\n";
        for (int i = 0; i < chain_len; i++) {
          print_cert_info(sk_X509_value(chain, i), i);
        }
      }
  }

  if (peer_cert)
    X509_free(peer_cert);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  return ok;
}

// Load a certificate from a PEM file
X509 *load_cert(const std::string &filepath) {
  // TODO: Implement Bio_new_file and PEM_read_bio_X509
  BIO *bio = BIO_new_file(filepath.c_str(), "r");
  if (!bio) {
    std::cerr << "Error opening file: " << filepath << "\n";
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!cert) {
    std::cerr << "Error reading certificate from: " << filepath << "\n";
    ERR_print_errors_fp(stderr);
  }

  return cert;
}

X509 *load_certs(const std::string &filepath, STACK_OF(X509) * *intermediates) {
  BIO *bio = BIO_new_file(filepath.c_str(), "r");
  if (!bio) {
    std::cerr << "Error opening file. " << filepath << "\n";
    ERR_print_errors_fp(stderr);
    return nullptr;
  }

  X509 *leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  if (!leaf) {
    std::cerr << "Error reading certificate from: " << filepath << "\n";
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    return nullptr;
  }

  *intermediates = sk_X509_new_null();
  X509 *extra = nullptr;
  while ((extra = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) !=
         nullptr) {
    sk_X509_push(*intermediates, extra);
  }

  ERR_clear_error();
  BIO_free(bio);
  return leaf;
}

// Set up the trust store
X509_STORE *create_store(const std::string &ca_bundle_path) {
  // TODO: Create X509_STORE and load locations (X509_STORE_load_locations)
  X509_STORE *store = X509_STORE_new();
  if (!store) {
    std::cerr << "Error creating X509 store\n";
    return nullptr;
  }

  if (X509_STORE_load_locations(store, ca_bundle_path.c_str(), nullptr) != 1) {
    std::cerr << "Error loading CA bundle: " << ca_bundle_path << "\n";
    ERR_print_errors_fp(stderr);
    X509_STORE_free(store);
    return nullptr;
  }
  return store;
}

bool verify_certificates(const std::string &cert_path,
                         const std::string &ca_bundle_path) {
  STACK_OF(X509) *intermediates = nullptr;
  X509 *cert = load_certs(cert_path, &intermediates);
  X509_STORE *store = create_store(ca_bundle_path);

  if (!cert || !store) {
    std::cerr << "Failed to load certificate or CA bundle\n";
    if (cert)
      X509_free(cert);
    if (store)
      X509_STORE_free(store);
    if (intermediates)
      sk_X509_pop_free(intermediates, X509_free);
    return false;
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, cert, intermediates);

  // TODO: Perform verification using X509_verify_cert(ctx)
  // TODO: Retrieve and print verification error if it fails
  // X509_STORE_CTX_get_error

  int result = X509_verify_cert(ctx);

  if (result != 1) {
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    std::cerr << "Verification error at depth: " << depth << ": "
              << X509_verify_cert_error_string(err) << "\n";
  }

  // Cleanup
  X509_STORE_CTX_free(ctx);
  X509_free(cert);
  X509_STORE_free(store);
  sk_X509_pop_free(intermediates, X509_free);

  if (result == 1) {
    std::cout << "Certificate verified successfuly\n";
  } else {
    std::cout << "Certificate not valid.\n";
  }
  return result == 1;
}

void print_usage(const char *prog) {
  std::cout << "Usage\n"
            << " " << prog << "file <cert.pem> <ca-bundle.pem>\n"
            << " " << prog << "check <hostname> [port]\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  std::string mode = argv[1];

  if (mode == "file" && argc == 4) {
    return verify_certificates(argv[2], argv[3]) ? 0 : 1;
  } else if (mode == "check" && argc >= 3) {
    std::string port = (argc >= 4) ? argv[3] : "443";
    return check_host(argv[2], port) ? 0 : 1;
  } else {
    print_usage(argv[0]);
    return 1;
  }
}
