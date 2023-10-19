require "wolfssl-ffi.header"

local ffi = require "ffi"
local c = ffi.load "wolfssl"

-- wrapper types are needed to attach methods via ffi.metatype
ffi.cdef [[
  typedef struct {
    WOLFSSL_CTX *ctx;
  } ctx_wrapper_t;

  typedef struct {
    WOLFSSL *ssl;
  } ssl_wrapper_t;

  typedef struct {
    WOLFSSL_BIO *bio;
  } bio_wrapper_t;
]]

local SSL_SUCCESS = 1

--- Initializes wolfSSL. Must be called once and be deinitialized before program exit.
--- @return nil | string err
local function init()
  if c.wolfSSL_Init() ~= SSL_SUCCESS then
    return "failed initilazing WolfSSL"
  end

  return nil
end

--- Deinitializes wolfSSL.
local function deinit()
  c.wolfSSL_Cleanup()
end

--- Gives the last error as a string by error value `err`.
--- @param err integer
--- @return string
local function getErrorString(err)
  -- The maximum length of data is 80 characters by default,
  -- as defined by MAX_ERROR_SZ is wolfssl/wolfcrypt/error.h.
  local buffer = ffi.new "char[80]"
  -- no returns
  c.wolfSSL_ERR_error_string_n(err, buffer, 80)

  return ffi.string(buffer)
end

--- @class Context
--- @field public ctx userdata
local Context = {}
Context.__index = Context

--- Creates a new `WOLFSSL_CTX` object.
--- @return Context
function Context.new()
  local ContextWrapperType = ffi.typeof "ctx_wrapper_t"
  local mt = ffi.metatype(ContextWrapperType, Context)

  return mt(c.wolfSSL_CTX_new(c.wolfTLSv1_2_client_method()))
end

--- @private
function Context:__gc()
  c.wolfSSL_CTX_free(self.ctx)
end

--- Loads credentials from given path and file.
--- @param file string?
--- @param path string?
--- @return string | nil err
function Context:loadVerifyLocations(file, path)
  local err = c.wolfSSL_CTX_load_verify_locations(self.ctx, file, path)
  if err ~= SSL_SUCCESS then
    return "failed to load certificates"
  end

  return nil
end

-- FIXME: doesn't work. needs a further investigation.
--- Loads CA certs from OS-dependent CA certificate store.
--- @return string | nil
function Context:loadSystemCACerts()
  local err = c.wolfSSL_CTX_load_system_CA_certs(self.ctx)
  if err ~= SSL_SUCCESS then
    return "failed to load system CA certificates"
  end

  return nil
end

--- @class SSL
--- @field public ssl userdata
local SSL = {}
SSL.__index = SSL

--- Creates a new SSL object with `Context`.
--- @return SSL
function Context:newSSL()
  local SSLWrapperType = ffi.typeof "ssl_wrapper_t"
  local mt = ffi.metatype(SSLWrapperType, SSL)

  return mt(c.wolfSSL_new(self.ctx))
end

---@private
function SSL:__gc()
  c.wolfSSL_free(self.ssl)
end

--- Gets the error value from value `err`.
--- @param err integer
--- @return integer
function SSL:getError(err)
  return c.wolfSSL_get_error(self.ssl, err)
end

--- Adds a check for the domain name in the handshake.
--- @param domainName string
--- @return string | nil err
function SSL:checkDomainName(domainName)
  local err = c.wolfSSL_check_domain_name(self.ssl, domainName)
  if err ~= SSL_SUCCESS then
    return "failed to add domain name check"
  end

  return nil
end

--- Sets the file descriptor `fd` for the given SSL object.
--- @param fd integer
--- @return string | nil
function SSL:setFd(fd)
  local err = c.wolfSSL_set_fd(self.ssl, fd)
  if err ~= SSL_SUCCESS then
    return "failed to set file descriptor"
  end

  return nil
end

function SSL:setConnectState()
  c.wolfSSL_set_connect_state(self.ssl)
end

function SSL:setAcceptState()
  c.wolfSSL_set_accept_state(self.ssl)
end

--- comment
--- @param rb BIO
--- @param wb BIO
function SSL:setBIO(rb, wb)
  c.wolfSSL_set_bio(self.ssl, rb, wb)
end

function SSL:doHandshake()
  local err = c.wolfSSL_SSL_do_handshake(self.ssl)
  print(self:getError(err))

  return err
end

function SSL:negotiate()
  local err = c.wolfSSL_negotiate(self.ssl)
  print(self:getError(err))

  return err
end

--- Handles the TLS handshake for the client-side SSL object.
--- @return integer | nil
function SSL:connect()
  local err = c.wolfSSL_connect(self.ssl)
  if err ~= SSL_SUCCESS then
    return self:getError(err)
  end

  return nil
end

--- Accepts the incoming SSL connection.
--- @return integer | nil
function SSL:accept()
  local err = c.wolfSSL_accept()
  if err ~= SSL_SUCCESS then
    return self:getError(err)
  end

  return nil
end

--- Writes given buffer to the SSL object.
--- Buffer can either be string or FFI char data. It works well with LuaJIT string buffers too.
--- @param buffer string | any (cdata)
--- @param len integer
--- @return integer | nil
--- @return integer | nil
function SSL:write(buffer, len)
  len = len or #buffer
  local err = c.wolfSSL_write(self.ssl, buffer, len)
  -- error situation if `err` is equal or smaller than 0
  if err <= 0 then
    return nil, self:getError(err)
  end

  -- success
  return err, nil
end

-- TLSv1.3 only.
-- Only used with clients.
function SSL:writeEarlyData(buffer, len)
  local outSz = ffi.new "int[1]"

  local err = c.wolfSSL_write_early_data(self.ssl, buffer, len, outSz)
  if err ~= SSL_SUCCESS then
    return nil, self:getError(err)
  end

  return outSz[0], nil
end

-- TLSv1.3 only.
-- Only used with servers.
function SSL:readEarlyData(buffer, len)
  local outSz = ffi.new "int[1]"

  local err = c.wolfSSL_read_early_data(self.ssl, buffer, len, outSz)
  if err ~= SSL_SUCCESS then
    return nil, self:getError(err)
  end

  return outSz[0], nil
end

--- Reads from the SSL object.
--- @param len integer
--- @return string | nil
--- @return integer | nil
function SSL:read(len)
  local buffer = ffi.new("char[?]", len)
  local err = c.wolfSSL_read(self.ssl, buffer, len)
  -- success situation
  if err > 0 then
    return ffi.string(buffer, err), nil
  end

  -- failure
  return nil, self:getError(err)
end

--- Reads from the SSL object to the given byte buffer.
--- This can be more performant than `SSL:read` if program reads a lot.
--- @param buffer any (cdata)
--- @param len integer
--- @return integer | nil
--- @return integer | nil
function SSL:readToBuffer(buffer, len)
  -- buffer is supplied by user
  local err = c.wolfSSL_read(self.ssl, buffer, len)
  -- success situation
  if err > 0 then
    return err, nil
  end

  -- failure
  return nil, self:getError(err)
end

-- error codes
local error = {
  WantRead = 2,
  WantWrite = 3,
  WantConnect = 7,
  WantAccept = 8,
  Syscall = 5,
  WantX509Lookup = 83,
  ZeroReturn = 6,
  SSL = 85,

  -- TODO: add more error codes
}

--- @class BIO
--- @field private bio userdata
local BIO = {}
BIO.__index = BIO

--- Creates a new BIO object that has socket BIO method.
--- @return BIO
function BIO.newSocketBIO()
  local BIOWrapperType = ffi.typeof "bio_wrapper_t"
  local mt = ffi.metatype(BIOWrapperType, BIO)

  return mt(c.wolfSSL_BIO_new(c.wolfSSL_BIO_s_socket()))
end

function BIO.newSocket(sfd)
  local BIOWrapperType = ffi.typeof "bio_wrapper_t"
  local mt = ffi.metatype(BIOWrapperType, BIO)

  return mt(c.wolfSSL_BIO_new_socket(sfd, 0))
end

--- Creates a new BIO object that has memory BIO method.
--- @return BIO
function BIO.newMemoryBIO()
  local BIOWrapperType = ffi.typeof "bio_wrapper_t"
  local mt = ffi.metatype(BIOWrapperType, BIO)

  return mt(c.wolfSSL_BIO_new(c.wolfSSL_BIO_s_mem()))
end

--- Creates a new BIO object that has SSL BIO method.
--- @return BIO
function BIO.newSSLBIO()
  local BIOWrapperType = ffi.typeof "bio_wrapper_t"
  local mt = ffi.metatype(BIOWrapperType, BIO)

  return mt(c.wolfSSL_BIO_new(c.wolfSSL_BIO_f_ssl()))
end

--- @private
function BIO:__gc()
  c.wolfSSL_BIO_free(self.bio)
end

function BIO:write(buffer, len)
  len = len or #buffer
  local err = c.wolfSSL_BIO_write(self.bio, buffer, len)

  print(err)
end

function BIO:read(len)
  local buffer = ffi.new("char[?]", len)
  local err = c.wolfSSL_BIO_read(self.bio, buffer, len)

  if err > 0 then
    return ffi.string(buffer, err)
  end
end

return {
  -- universal
  init = init,
  deinit = deinit,
  getErrorString = getErrorString,
  error = error,

  -- WOLFSSL_CTX API
  Context = Context,

  -- WOLFSSL_BIO API
  BIO = BIO,
}
