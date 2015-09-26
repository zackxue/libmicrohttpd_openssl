static ssize_t
recv_openssl_adapter (struct MHD_Connection *connection, void *other, size_t i)
{
  int res;
  res = SSL_read (connection->ssl, other, i);
  if ( res == 0){
      MHD_set_socket_errno_ (EINTR);
#if EPOLL_SUPPORT
      connection->epoll_state &= ~MHD_EPOLL_STATE_READ_READY;
#endif
      return -1;
  }
  if (res < 0){
      /* Likely 'GNUTLS_E_INVALID_SESSION' (client communication
	 disrupted); set errno to something caller will interpret
	 correctly as a hard error */
      MHD_set_socket_errno_ (ECONNRESET);
      return res;
    }
  return res;
}


/**
 * Callback for writing data to the socket.
 *
 * @param connection the MHD connection structure
 * @param other data to write
 * @param i number of bytes to write
 * @return actual number of bytes written
 */
static ssize_t
send_openssl_adapter (struct MHD_Connection *connection,
                  const void *other, size_t i)
{
  int res;

  res = SSL_write (connection->ssl, other, i);
  if ( res == 0){
      MHD_set_socket_errno_ (EINTR);
#if EPOLL_SUPPORT
      connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif
      return -1;
  }
  if (res < 0){
      /* some other GNUTLS error, should set 'errno'; as we do not
         really understand the error (not listed in GnuTLS
         documentation explicitly), we set 'errno' to something that
         will cause the connection to fail. */
      MHD_set_socket_errno_ (ECONNRESET);
      return -1;
  }
  return res;
}


/**
 * Initialize security aspects of the HTTPS daemon
 *
 * @param daemon handle to daemon to initialize
 * @return 0 on success
 */
static int
MHD_openssl_init (struct MHD_Daemon *daemon){
	SSL_library_init();
	SSL_METHOD *method;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = (SSL_METHOD*)TLSv1_server_method();  /* Create new client-method instance */
    daemon->ctx = SSL_CTX_new(method);   /* Create new context */
	SSL_CTX_set_options(daemon->ctx,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    if (daemon->ctx == NULL){
        ERR_print_errors_fp(stderr);
        return 1;
    }
	if (SSL_CTX_use_certificate_file(daemon->ctx, daemon->certpath, SSL_FILETYPE_PEM) <= 0 ){
		ERR_print_errors_fp(stderr);
		return 1;
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(daemon->ctx, daemon->keypath, SSL_FILETYPE_PEM) <= 0 ){
		ERR_print_errors_fp(stderr);
		return 1;
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(daemon->ctx) ){
		fprintf(stderr, "Private key does not match the public certificate\n");
		return 1;
	}
  return 0;
}
