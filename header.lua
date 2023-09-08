local ffi = require "ffi"

ffi.cdef [[
  // types
  typedef struct WOLFSSL          WOLFSSL;
  typedef struct WOLFSSL_SESSION  WOLFSSL_SESSION;
  typedef struct WOLFSSL_METHOD   WOLFSSL_METHOD;
  typedef struct WOLFSSL_CTX      WOLFSSL_CTX;

  int wolfSSL_Init(void);
  int wolfSSL_Cleanup(void);

  void wolfSSL_ERR_error_string_n(
    unsigned long e,
    char * buf,
    unsigned long sz
  );

  // Context functions
  WOLFSSL_CTX *wolfSSL_CTX_new(
    WOLFSSL_METHOD * method
  );

  void wolfSSL_CTX_free(
    WOLFSSL_CTX * ctx
  );

  int wolfSSL_CTX_load_verify_locations(
    WOLFSSL_CTX * ctx,
    const char * file,
    const char * path
  );

  int wolfSSL_CTX_load_system_CA_certs(
    WOLFSSL_CTX * ctx
  );

  void wolfSSL_free(WOLFSSL *ssl);
  int wolfSSL_shutdown(WOLFSSL *ssl);
  int wolfSSL_send(WOLFSSL *ssl, const void *data, int sz, int flags);
  int wolfSSL_recv(WOLFSSL *ssl, void *data, int sz, int flags);

  int wolfSSL_write(
    WOLFSSL * ssl,
    const void * data,
    int sz
  );

  int wolfSSL_read(
    WOLFSSL * ssl,
    void * data,
    int sz
  );

  // method
  WOLFSSL_METHOD *wolfSSLv23_method(void);

  WOLFSSL_METHOD *wolfSSLv3_server_method(void);
  
  WOLFSSL_METHOD *wolfSSLv3_client_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_server_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_client_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);
  
  WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);

  WOLFSSL_METHOD *wolfDTLSv1_client_method(void);

  // functions for loading certs
  int wolfSSL_CTX_load_verify_locations(
    WOLFSSL_CTX * ctx,
    const char * file,
    const char * path
  );

  // SSL functions
  WOLFSSL * wolfSSL_new(
    WOLFSSL_CTX * 
  );

  void wolfSSL_free(
    WOLFSSL *
  );

  int wolfSSL_set_fd(
    WOLFSSL * ssl,
    int fd
  );

  int wolfSSL_connect(
    WOLFSSL * ssl
  );

  int wolfSSL_accept(
    WOLFSSL * ssl
  );

  int wolfSSL_get_error(
    WOLFSSL * ssl,
    int ret
  );

  int wolfSSL_check_domain_name(
    WOLFSSL * ssl,
    const char * dn
  );

  int wolfSSL_write_early_data(
    WOLFSSL * ssl,
    const void * data,
    int sz,
    int * outSz
  );
]]