#include "Oidc.h"
#include "Base64Url.h"

const size_t Oidc::tokenLen = 16;
const size_t Oidc::clientIdLen = 16;
const size_t Oidc::clientSecretLen = 32;
const size_t Oidc::idTokenExpire = 60; // In seconds
const size_t Oidc::accessTokenExpire = 3600;

Oidc::Oidc() {
  auto relyingPartyName = std::getenv("WEBAUTHN_RP_NAME");
  if (relyingPartyName != NULL) {
    this->iss = std::make_shared<std::string>(std::string{"https://"}.append(relyingPartyName));
  } else {
    this->iss = std::make_shared<std::string>("https://localhost");
  }
  std::filesystem::path
      certFolder = "cert",
      pathFileCert = std::filesystem::path(certFolder).append("domain.crt"),
      pathFileKey = std::filesystem::path(certFolder).append("domain.key");
  LOG(INFO) << "Loading X509 certificate and corresponding private key from "
               "the files "
            << pathFileCert << " and " << pathFileKey;

  // If one of the certificate is missing, generate a self signed as backup.
  if (!std::filesystem::exists(pathFileCert) ||
      !std::filesystem::exists(pathFileKey)) {
    LOG_ERROR << "Missing file(s). Make sure that " << pathFileCert << " and "
              << pathFileKey << " are available.";

    // Verify whether the certificate folder exists or not.
    if (!std::filesystem::exists(certFolder) ||
        !std::filesystem::is_directory(certFolder)) {
      LOG_INFO << "Missing the folder " << certFolder;
      LOG_INFO << "Creating the folder " << certFolder;
      std::error_code ec;
      if (!std::filesystem::create_directory(certFolder, ec)) {
        LOG_ERROR << "Couldn't create the folder " << certFolder;
        throw std::runtime_error{ec.message()};
      }
    }

    LOG_INFO << "Generate a self signed certificate.";
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (pkey == NULL) {
      LOG_ERROR << "Couldn't create a new asymmetric key structure";
      throw std::runtime_error{
          "Couldn't create a new asymmetric key structure"};
    }

    X509 *x509 = X509_new();
    if (x509 == NULL) {
      LOG_ERROR << "Couldn't allocate and initialize a new x509 structure";
      EVP_PKEY_free(pkey);
      throw std::runtime_error{ERR_reason_error_string(ERR_get_error())};
    }

    X509_NAME *subName;
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    // 365 days
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    subName = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(subName, "C", MBSTRING_ASC,
                               (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subName, "O", MBSTRING_ASC,
                               (unsigned char *)"identity provider", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subName, "CN", MBSTRING_ASC,
                               (unsigned char *)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, subName);
    X509_sign(x509, pkey, EVP_sha1());

    LOG_INFO << "Store " << pathFileCert;
    FILE *domainKey = fopen(pathFileKey.c_str(), "wb");
    // PEM_write_RSAPrivateKey(domainKey, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_PrivateKey(domainKey, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(domainKey);

    LOG_INFO << "Store " << pathFileKey;
    FILE *domainCert = fopen(pathFileCert.c_str(), "wb");
    PEM_write_X509(domainCert, x509);
    fclose(domainCert);

    /*
    std::vector<unsigned char> bufE(bufSize);
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_RSA_E,
                                         bufE.data(), bufE.size(), &bufSize)) {
      LOG_ERROR << "Couldn't get the octet string of param e of RSA.";
      X509_free(x509);
      EVP_PKEY_free(pkey);
      throw std::runtime_error{
          "Couldn't get the octet string of param e of RSA."};
    }
    LOG_INFO << "Domain parameter e: " << bufE.data();
    */

    X509_free(x509);
    EVP_PKEY_free(pkey);
  }
  /*
    auto fileCert = std::fopen(pathFileCert.c_str(), "r");
    if(!fileCert) {
            LOG_ERROR << "Couldn't open the file " << pathFileCert;
            throw std::runtime_error{std::strerror(errno)};
    }

    auto fileKey = std::fopen(pathFileKey.c_str(), "r");
    if(!fileKey) {
            LOG_ERROR << "Couldn't open the file " << pathFileKey;
            fclose(fileCert);
            throw std::runtime_error{std::strerror(errno)};
    }

    this->x509Cert = std::make_shared<std::string>();
    this->pubkey = std::make_shared<std::string>();

    fclose(fileCert);
    fclose(fileKey);*/

  std::ifstream fileCertFs{pathFileCert}, fileKeyFs{pathFileKey};
  std::ostringstream strCert, strKey;

  LOG(INFO) << "Reading the cert file";
  strCert << fileCertFs.rdbuf();
  LOG(INFO) << "Reading the private key file";
  strKey << fileKeyFs.rdbuf();

  fileCertFs.close();
  fileKeyFs.close();

  this->x509Cert = std::make_shared<std::string>(strCert.str());
  this->privkey = std::make_shared<std::string>(strKey.str());
  this->pubkey = std::make_shared<std::string>(
      jwt::helper::extract_pubkey_from_cert(*this->x509Cert));

  auto bioMemX509 = BIO_new(BIO_s_mem());
  if (bioMemX509 == NULL) {
    LOG_ERROR << "Couldn't create bio in memory.";
    throw std::runtime_error("Couldn't create bio in memory.");
  }

  if (BIO_write(bioMemX509, this->x509Cert->data(), this->x509Cert->size()) <
      1) {
    LOG_ERROR << "Couldn't write the x509 cert into bio.";
    BIO_free(bioMemX509);
    throw std::runtime_error{"Couldn't write the x509 cert into bio."};
  }

  X509 *x509 = NULL;
  PEM_read_bio_X509(bioMemX509, &x509, NULL, NULL);
  if (x509 == NULL) {
    LOG_ERROR << "Couldn't read the x509 cert from bio into x509 object.";
    BIO_free(bioMemX509);
    throw std::runtime_error{
        "Couldn't read the x509 cert from bio into x509 object."};
  }
  BIO_free(bioMemX509);

  auto pkey = X509_get_pubkey(x509);
  if (pkey == NULL) {
    LOG_ERROR << "Couldn't extract the public key from the x509 structure.";
    X509_free(x509);
    throw std::runtime_error{
        "Couldn't extract the public key from the x509 structure."};
  }

  // Encode x509 in DER
  unsigned char *tmpX509DER = NULL;
  auto sizeTmpX509DER = i2d_X509(x509, &tmpX509DER);
  if (sizeTmpX509DER < 0) {
    LOG_ERROR << "Couldn't encode the x509 cert to DER";
    EVP_PKEY_free(pkey);
    X509_free(x509);
    throw std::runtime_error{ERR_reason_error_string(ERR_get_error())};
  }
  this->x509CertDER = std::make_shared<std::string>(
      drogon::utils::base64Encode(tmpX509DER, sizeTmpX509DER));
  LOG_INFO << "x509 in DER with base64: " << *this->x509CertDER;

  // Extract the public key exponent e
  BIGNUM *bnE = NULL;
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bnE) != 1) {
    LOG_ERROR
        << "Couldn't determine the size of the parameter e from the RSA key.";
    X509_free(x509);
    EVP_PKEY_free(pkey);
    throw std::runtime_error{
        "Couldn't determine the size of the parameter e from the RSA key."};
  }

  // Encode the public key exponent e to base64
  std::vector<unsigned char> vecE(BN_num_bytes(bnE));
  BN_bn2bin(bnE, vecE.data());
  BN_free(bnE);
  this->pubKeyE = std::make_shared<std::string>(
      drogon::utils::base64Encode(vecE.data(), vecE.size()));
  LOG_INFO << "Public key exponent e=" << *this->pubKeyE;
  Base64Url::encode(this->pubKeyE);

  // Extract the public key modulo n
  BIGNUM *bnN = NULL;
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bnN) != 1) {
    LOG_ERROR
        << "Couldn't determine the size of the parameter e from the RSA key.";
    X509_free(x509);
    EVP_PKEY_free(pkey);
    throw std::runtime_error{
        "Couldn't determine the size of the parameter e from the RSA key."};
  }

  // Encode the public key modulo n to base64
  std::vector<unsigned char> vecN(BN_num_bytes(bnN));
  BN_bn2bin(bnN, vecN.data());
  BN_free(bnN);
  this->pubKeyN = std::make_shared<std::string>(
      drogon::utils::base64Encode(vecN.data(), vecN.size()));
  LOG_INFO << "Public key modulo n=" << *this->pubKeyN;
  Base64Url::encode(this->pubKeyN);

  /*
  FILE *filePub = fopen("cert/pub.pem", "wb");
  PEM_write_PUBKEY(filePub, pkey);

  BIO *bioMemPubKey = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bioMemPubKey, pkey);
  size_t lenPubKey = BIO_ctrl_pending(bioMemPubKey);
  LOG_INFO << "The public key is " << lenPubKey << " bytes long";

  std::vector<char> vecPubKey(lenPubKey);
  BIO_read(bioMemPubKey, vecPubKey.data(), vecPubKey.size());

  LOG_INFO << "Public key: " << vecPubKey.data();
*/
  X509_free(x509);
  EVP_PKEY_free(pkey);

  // Generate the OpenID Provider Configuration
  if (!this->config) {
    LOG_DEBUG << "Generate OpenID Provider Configuration";
    this->config = std::make_shared<Json::Value>();
    (*this->config)["issuer"] = *this->iss;
  }
}

/**
 * @brief Authorization Endpoint 3.1.2.1
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * An Authentication Request is an OAuth 2.0 Authorization Request that requests
 * that the End-User be authenticated by the Authorization Server. Authorization
 * Servers MUST support the use of the HTTP GET and POST methods defined in RFC
 * 2616 [RFC2616] at the Authorization Endpoint. Clients MAY use the HTTP GET or
 * POST methods to send the Authorization Request to the Authorization Server.
 * If using the HTTP GET method, the request parameters are serialized using URI
 * Query String Serialization, per Section 13.1. If using the HTTP POST method,
 * the request parameters are serialized using Form Serialization, per
 * Section 13.2. OpenID Connect uses the following OAuth 2.0 request parameters
 * with the Authorization Code Flow:
 *
 * @param response_type REQUIRED. OAuth 2.0 Response Type value that determines
 * the authorization processing flow to be used, including what parameters are
 * returned from the endpoints used. When using the Authorization Code Flow,
 * this value is code.
 * @param client_id REQUIRED. OAuth 2.0 Client Identifier valid at the
 * Authorization Server.
 * @param redirect_uri REQUIRED. Redirection URI to which the response will be
 * sent. This URI MUST exactly match one of the Redirection URI values for the
 * Client pre-registered at the OpenID Provider, with the matching performed as
 * described in Section 6.2.1 of [RFC3986] (Simple String Comparison). When
 * using this flow, the Redirection URI SHOULD use the https scheme; however, it
 * MAY use the http scheme, provided that the Client Type is confidential, as
 * defined in Section 2.1 of OAuth 2.0, and provided the OP allows the use of
 * http Redirection URIs in this case. The Redirection URI MAY use an alternate
 * scheme, such as one that is intended to identify a callback into a native
 * application.
 * @param scope  REQUIRED. OpenID Connect requests MUST contain the openid scope
 * value. If the openid scope value is not present, the behavior is entirely
 * unspecified. Other scope values MAY be present. Scope values used that are
 * not understood by an implementation SHOULD be ignored. See Sections 5.4 and
 * 11 for additional scope values defined by this specification.
 * @return drogon::AsyncTask
 */
drogon::AsyncTask Oidc::authorize(
    HttpRequestPtr req, std::function<void(const HttpResponsePtr &)> callback,
    std::string response_type, std::string client_id, std::string redirect_uri,
    std::string scope, std::string state) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " Body: " << req->bodyData()
            << " Method: " << req->getMethodString()
            << " Query: " << req->getQuery();

  try {
    // Check if the user is logged in.
    auto sessionPtr = req->session();
    if (!sessionPtr->find("token")) {
      throw std::invalid_argument{
          "User must be logged in first, in order to authorize a third party"};
    }

    // The scope has to be openid
    LOG_DEBUG << "Verify that the scope openid is set";
    auto regexScope = std::regex{" "};
    bool foundScopeOpenId = false;
    std::sregex_token_iterator regIt{scope.begin(), scope.end(), regexScope,
                                     -1};
    for (auto end = std::sregex_token_iterator{}; regIt != end; regIt++) {
      LOG_DEBUG << "Scope found: " << *regIt;
      if (*regIt == "openid") {
        foundScopeOpenId = true;
        break;
      }
    }
    if (!foundScopeOpenId) {
      LOG_ERROR << "The scope has to contain the string openid.";
      throw std::invalid_argument{
          "The scope has to contain the string openid."};
    }

    // The response_type has to be code. Others aren't supported.
    if (response_type != "code") {
      LOG_ERROR
          << "The response_type has to contain the string code(Other flows "
             "aren't supported).";
      throw std::invalid_argument{"The response_type has to contain the string "
                                  "code(Other flows aren't supported)."};
    }

    // client_id: OAuth 2.0 Client Identifier valid at the Authorization Server.
    if (client_id.empty()) {
      LOG_ERROR << "The client_id must NOT be empty.";
      throw std::invalid_argument{"The client_id must NOT be empty."};
    }

    // redirect_uri
    if (redirect_uri.empty()) {
      LOG_ERROR << "The redirect_uri must NOT be empty.";
      throw std::invalid_argument{"The redirect_uri must NOT be empty."};
    }

    // Check if the client_id is registered
    auto dbClient = app().getDbClient("");
    auto sqlResultClient = co_await dbClient->execSqlCoro(
        "SELECT id,app_name FROM oidc_client as c INNER JOIN oidc_client_uri "
        "as u ON "
        "c.id=u.fk_oidc_client_id WHERE c.client_id=? AND u.uri=?",
        client_id, redirect_uri);

    if (sqlResultClient.size() == 0) {
      LOG_ERROR << "The application with the client_id: " << client_id
                << " and redirect_uri: " << redirect_uri
                << " is not registered";
      throw std::invalid_argument{"The application is not registered"};
    }
    auto clientId = sqlResultClient[0]["id"].as<size_t>();

    // Check if the user already has granted the client access to its oidc
    // scope.
    LOG_DEBUG << "Check if the user already has granted the client access to "
                 "its oidc scope";
    auto credRec = sessionPtr->get<CredentialRecord>("token");
    auto sqlResultResourceOwner = co_await dbClient->execSqlCoro(
        "SELECT id FROM resource_owner WHERE username=?", *credRec.uName);
    if (sqlResultResourceOwner.size() == 0) {
      LOG_ERROR << "Couldn't find the resource_owner with the username "
                << *credRec.uName;
      throw std::invalid_argument{"Couldn't find a user with this username"};
    }
    auto resourceOwnerId = sqlResultResourceOwner[0]["id"].as<size_t>();

    auto sqlResultOidcMapping = co_await dbClient->execSqlCoro(
        "SELECT oidc FROM oidc_scope_mapping WHERE fk_oidc_client_id=? AND "
        "fk_resource_owner_id=?",
        clientId, resourceOwnerId);
    if (sqlResultOidcMapping.size() == 0) {
      LOG_DEBUG << "The client hasn't been granted access yet";
    } else if (sqlResultOidcMapping[0]["oidc"].as<bool>()) {
      LOG_DEBUG << "The client has already been granted access to oidc scope";
      auto responsePtr = co_await Oidc::generateResponseAuhtorizationCode(
          clientId, redirect_uri, resourceOwnerId, state);
      callback(responsePtr);
      co_return;
    }

    // Generate token
    LOG_DEBUG << "Generating token.";
    std::random_device rd;
    std::independent_bits_engine<std::mt19937_64, 8, unsigned int> e1{rd()};
    auto token = std::string();
    std::generate_n(std::back_inserter(token), tokenLen, e1);
    token =
        utils::base64Encode((unsigned char *)token.c_str(), token.size(), true);
    LOG_DEBUG << "token: " << token;

    // Store the authorization request in memory
    Json::Value authRequest;
    authRequest["scope"] = scope;
    authRequest["response_type"] = response_type;
    authRequest["client_id"] = client_id;
    authRequest["redirect_uri"] = redirect_uri;
    if (!state.empty()) {
      LOG_DEBUG << "Found parameter status in query. Binding session id to "
                   "this request";
      authRequest["state"] = state;
      authRequest["session_id"] = req->getSession()->sessionId();
    }

    auto builder = Json::StreamWriterBuilder{};
    builder["indentation"] = "";
    builder["commentStyle"] = "None";
    auto strJsonAuthRequest = Json::writeString(builder, authRequest);

    auto redisClient = app().getRedisClient();
    co_await redisClient->execCommandCoro(
        "set authReq:%s %s EX 600", token.c_str(), strJsonAuthRequest.c_str());

    // Generate authorization view.
    HttpViewData data;
    data.insert("appName", sqlResultClient[0]["app_name"].as<std::string>());
    data.insert("token", token);
    data.insert("data", std::forward_list<std::string>({"openid"}));
    callback(HttpResponse::newHttpViewResponse("Authorize.csp", data));

  } catch (std::invalid_argument &ex) {
    callback(toError(HttpStatusCode::k400BadRequest, ex.what()));
  } catch (...) {
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Unkown server error occured"));
  }
  co_return;
}

drogon::AsyncTask
Oidc::grant(HttpRequestPtr req,
            std::function<void(const HttpResponsePtr &)> callback,
            std::string token) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " Body: " << req->bodyData();

  try {
    // Check if a token is set
    if (token.empty()) {
      LOG_DEBUG << "Missing token";
      throw std::invalid_argument{"Missing token"};
    }

    // Check if the user is logged in.
    LOG_DEBUG << "Check if the user is logged in";
    auto sessionPtr = req->session();
    if (!sessionPtr->find("token")) {
      throw std::invalid_argument{
          "User must be logged in first, in order to authorize a third party"};
    }

    auto credRec = sessionPtr->get<CredentialRecord>("token");

    // Select the token from redis.
    auto redisClient = app().getRedisClient();
    auto redisResult =
        co_await redisClient->execCommandCoro("get authReq:%s", token.c_str());
    if (redisResult.isNil()) {
      LOG_DEBUG << "Couldn't token authReq:" << token << " in Redis";
      throw std::invalid_argument{"Couldn't find the token"};
    }
    auto authRequestStr = redisResult.asString();

    // Deserialize the authReq
    LOG_DEBUG << "Deserialize the authReq from Redis";
    std::shared_ptr<Json::Value> authReq = std::make_shared<Json::Value>();
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

    if (!reader->parse(authRequestStr.c_str(),
                       authRequestStr.c_str() + authRequestStr.length(),
                       &(*authReq), nullptr)) {
      LOG_ERROR << "Couldn't parse the authRequest from Redis";
      throw std::invalid_argument{"Internal server error"};
    }

    std::string state{""};
    if (authReq->isMember("state")) {
      LOG_DEBUG << "Field status were passed during /authorize.\nCheck if the "
                   "sessions match";
      state = (*authReq)["state"].as<std::string>();
      if (!authReq->isMember("session_id")) {
        LOG_ERROR << "Missing session_id. This should never happen";
        throw std::runtime_error{"Internal server error"};
      }
      if ((*authReq)["session_id"].as<std::string>() !=
          sessionPtr->sessionId()) {
        LOG_ERROR << "The session ids dosen't match";
        throw std::invalid_argument{
            "This session isn't allowed to use that token"};
      }
    }
    // Get the resource owners database entry id.
    LOG_DEBUG << "Get the resource owners database entry id";
    auto dbClient = app().getDbClient("");
    auto sqlResultResourceOwner = co_await dbClient->execSqlCoro(
        "SELECT id FROM resource_owner WHERE username=?", *credRec.uName);

    if (sqlResultResourceOwner.size() == 0) {
      LOG_ERROR << "Couldn't find the resource owner with the username: "
                << *credRec.uName << " in the database";
      throw std::invalid_argument{"Couldn't find the user"};
    }
    auto resourceOwnerId = sqlResultResourceOwner[0]["id"].as<size_t>();

    // Get the clients database id.
    LOG_DEBUG << "Get the clients database id";
    auto sqlResultClient = co_await dbClient->execSqlCoro(
        "SELECT id FROM oidc_client WHERE client_id=?",
        (*authReq)["client_id"].as<std::string>());

    if (sqlResultClient.size() == 0) {
      LOG_ERROR << "Couldn't find the client_id";
      throw std::invalid_argument{"Couldn't find the application"};
    }
    auto clientId = sqlResultClient[0]["id"].as<size_t>();

    // Check if the client is already granted some scopes.
    auto sqlResultClientScopeSelect = co_await dbClient->execSqlCoro(
        "SELECT *FROM oidc_scope_mapping WHERE fk_oidc_client_id=? AND "
        "fk_resource_owner_id=?",
        clientId, resourceOwnerId);

    if (sqlResultClientScopeSelect.size() > 0) {
      LOG_ERROR << "The user has already registered the client";
      throw std::invalid_argument{
          "The application is already bound to your account"};
    }

    // Insert the grant into the database.
    LOG_DEBUG << "Insert the grant into the database";
    auto sqlResultClientScope = co_await dbClient->execSqlCoro(
        "INSERT INTO "
        "oidc_scope_mapping(fk_oidc_client_id,fk_resource_owner_id,oidc) "
        "VALUES(?,?,?)",
        clientId, resourceOwnerId, true);

    if (sqlResultClient.affectedRows() == 0) {
      LOG_ERROR << "Couldn't insert the grant permission into the database";
      throw std::runtime_error{"Internal server error"};
    }

    // Generate and store Authorization Code.
    auto redirect_uri = (*authReq)["redirect_uri"].as<std::string>();
    auto responsePtr = co_await Oidc::generateResponseAuhtorizationCode(
        clientId, redirect_uri, resourceOwnerId, state);
    callback(responsePtr);

  } catch (std::invalid_argument &ex) {
    callback(toError(HttpStatusCode::k400BadRequest, ex.what()));
  } catch (const drogon::nosql::RedisException &err) {
    LOG_ERROR << err.what();
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Internal server error occured"));
  } catch (...) {
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Unkown server error occured"));
  }
  co_return;
}
drogon::AsyncTask
Oidc::token(HttpRequestPtr req,
            std::function<void(const HttpResponsePtr &)> callback,
            std::string grant_type, std::string code, std::string redirect_uri,
            std::string client_id, std::string client_secret) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " Body: " << req->bodyData();
  try {
    // Verify the grant_type.
    if (grant_type.compare("authorization_code") != 0) {
      LOG_ERROR << "The grant_type is invalid";
      LOG_DEBUG << "grant_type: " << grant_type;
      throw std::invalid_argument{
          "The grant_type has to be \"authorization_code\""};
    }

    // Verify that code, redirect_uri, client_id and client_secret are set.
    if (code.empty() || redirect_uri.empty() || client_id.empty() ||
        client_secret.empty()) {
      LOG_ERROR << "Following fields has to be set: code, redirect_uri, "
                   "client_id and client_secret";
      throw std::invalid_argument{"Following fields has to be set: code, "
                                  "redirect_uri, client_id and client_secret"};
    }

    // Authenticate the client.
    auto dbClient = app().getDbClient("");
    auto sqlClientResult = co_await dbClient->execSqlCoro(
        "SELECT id,client_secret FROM oidc_client WHERE client_id=?",
        client_id);
    if (sqlClientResult.size() == 0) {
      LOG_ERROR << "Couldn't find the client with client_id " << client_id
                << " in the database";
      throw std::invalid_argument{"Couldn't find a client with that client_id"};
    }

    // Verify the client_secret
    // Hash the client_secret
    LOG_DEBUG << "Hash the client_secret";
    unsigned char client_secret_hash[32] = {0};
    int err = mbedtls_sha256(
        reinterpret_cast<const unsigned char *>(client_secret.c_str()),
        client_secret.size(), client_secret_hash, 0);
    if (err != 0) {
      LOG(ERROR) << "An exception occured during the sha256 calculation of the "
                    "client_secret. Error: "
                 << mbedtls_high_level_strerr(err);
      throw std::runtime_error{"Internal server error"};
    }
    auto client_secret_hash_hex =
        utils::binaryStringToHex(client_secret_hash, 32);
    LOG_DEBUG << "Verify that the client_secret match";
    if (sqlClientResult[0]["client_secret"].as<std::string>().compare(
            client_secret_hash_hex) != 0) {
      LOG_ERROR << "Invalid client_secret";
      throw std::invalid_argument{"Invalid client_secret"};
    }

    // Retrieve data from Redis
    LOG_DEBUG << "Retrieve data from Redis";
    auto redisClient = app().getRedisClient();
    auto redisTransaction = co_await redisClient->newTransactionCoro();
    auto isClientIdValid = co_await redisTransaction->execCommandCoro(
        "SISMEMBER auth_code:%s:client_id %s", code.c_str(), client_id.c_str());
    auto isRedirectUriValid = co_await redisTransaction->execCommandCoro(
        "SISMEMBER auth_code:%s:redirect_uri %s", code.c_str(),
        redirect_uri.c_str());
    co_await redisTransaction->executeCoro();

    // Validate client_id
    LOG_DEBUG << "Verify that the resource owner has granted the authorization "
                 "token for this client_id";
    if (!isClientIdValid) {
      LOG_ERROR << "Redis couldn't find the client_id " << client_id
                << " for the code " << code;
      throw std::invalid_argument{"Invalid authorization code or client_id"};
    }

    // Validate redirect_uri
    // The redirect_uri should be the same as the granted.
    // INFO: A client can own multiple redirect_uris one-to-many cardinality.
    LOG_DEBUG << "Verify that the resource owner has granted the redirect_uri";
    if (!isRedirectUriValid) {
      LOG_ERROR << "Redis couldn't find the redirect_uri " << redirect_uri
                << " for the code " << code;
      throw std::invalid_argument{"Invalid authorization code or redirect_uri"};
    }
    // Retrieve the resource owners database id from redis(Temporary).
    auto redisResultResourceOwnerId = co_await redisClient->execCommandCoro(
        "GET auth_code:%s:resource_owner_id", code.c_str());
    if (redisResultResourceOwnerId.isNil()) {
      LOG_ERROR << "Redis couldn't find the resource owners id ";
      throw std::runtime_error{"Redis couldn't find the resource owners id"};
    }

    // Subject identifier(Resource owners database id).
    auto sub =
        std::make_shared<std::string>(redisResultResourceOwnerId.asString());

    // Retrieve the resource owner last authentication timestamp from Redis.
    LOG_DEBUG << "Retrieve the resource owners last authentication timestamp "
                 "from Redis";
    auto redisResultAuthTime = co_await redisClient->execCommandCoro(
        "GET user:%s:last_login", sub->c_str());
    if (redisResultAuthTime.isNil()) {
      LOG_ERROR << "Redis couldn't find the auth_time of the resource owner";
      throw std::runtime_error{
          "Redis couldn't find the auth_time of the resource owner"};
    }
    auto auth_time = std::make_shared<std::chrono::system_clock::time_point>(
        std::chrono::seconds{
            std::atoll(redisResultAuthTime.asString().c_str())});

    auto aud = std::make_shared<std::string>(client_id);
    auto idToken = IdToken(this->iss, aud, sub, idTokenExpire, auth_time);

    // Create the JWT
    LOG_DEBUG << "Create the JWT";
    auto jwt =
        jwt::create()
            .set_type("JWT")
            .set_payload_claim("iss", jwt::claim{*this->iss})
            .set_payload_claim("aud", jwt::claim{*aud})
            .set_payload_claim("sub", jwt::claim{*sub})
            .set_payload_claim(
                "exp", jwt::claim{std::chrono::system_clock::now() +
                                  std::chrono::seconds{Oidc::idTokenExpire}})
            .sign(jwt::algorithm::rs256{*this->pubkey, *this->privkey});

    // Generate the access token
    auto access_token = utils::getUuid();

    // Create the token response JSON
    Json::Value resJson;
    resJson["access_token"] = access_token;
    resJson["expires_in"] = Oidc::accessTokenExpire;
    resJson["token_type"] = "Bearer";
    resJson["id_token"] = jwt;

    LOG_DEBUG << "ID Token: " << jwt;

    // Store the access_token in Redis
    co_await redisClient->execCommandCoro("SET access_token:%s:user_id %s",
                                          access_token.c_str(), sub->c_str());
    co_await redisClient->execCommandCoro("EXPIRE access_token:%s:user_id %u",
                                          access_token.c_str(),
                                          Oidc::accessTokenExpire);

    LOG_DEBUG << "ResponseJSON: " << resJson.toStyledString();
    auto resPtr = HttpResponse::newHttpJsonResponse(std::move(resJson));
    resPtr->addHeader("Cache-Control", "no-store");
    resPtr->addHeader("Pragma", "no-cache");

    LOG_DEBUG << "Send JSON response";
    callback(resPtr);
  } catch (std::invalid_argument &ex) {
    callback(toError(HttpStatusCode::k400BadRequest, ex.what()));
  } catch (const drogon::nosql::RedisException &err) {
    LOG_ERROR << err.what();
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Internal server error occured"));
  } catch (...) {
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Unkown server error occured"));
  }
  co_return;
}

drogon::AsyncTask
Oidc::keys(HttpRequestPtr req,
           std::function<void(const HttpResponsePtr &)> callback) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();

  Json::Value root, key1;
  Json::Value certs{Json::ValueType::arrayValue},
      keys{Json::ValueType::arrayValue};
  certs.append(*this->x509CertDER);
  key1["alg"] = "RS256";
  key1["kty"] = "RSA";
  key1["use"] = "sig";
  key1["x5c"] = std::move(certs);
  key1["e"] = *this->pubKeyE;
  key1["n"] = *this->pubKeyN;
  keys.append(std::move(key1));
  root["keys"] = std::move(keys);

  callback(HttpResponse::newHttpJsonResponse(std::move(root)));
  co_return;
}
drogon::AsyncTask
Oidc::userinfo(HttpRequestPtr req,
               std::function<void(const HttpResponsePtr &)> callback) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();

  auto authHeader = req->getHeader("Authorization");
  if (!authHeader.starts_with("Bearer ")) {
    LOG_ERROR << "The Authorization header has to start with Bearer ";
    throw std::invalid_argument{"Invalid Authorization header"};
  }

  // Extract the accessToken
  auto accessToken = authHeader.substr(7);
  if (accessToken.empty()) {
    LOG_ERROR << "Missing bearer token";
    throw std::invalid_argument{"Invalid Authorization header"};
  }

  // Retrieve the resource owners id from Redis
  auto redisClient = app().getRedisClient();
  auto redisResultUserId = co_await redisClient->execCommandCoro(
      "GET access_token:%s:user_id", accessToken.c_str());
  if (redisResultUserId.isNil()) {
    LOG_ERROR << "Redis couldn't find the user id for access_token "
              << accessToken;
    throw std::invalid_argument{"Invalid token"};
  }
  auto strResourceOwnerId = redisResultUserId.asString();

  // Get resource owner information from the database
  auto dbClient = app().getDbClient("");
  auto sqlResultResourceOwner = co_await dbClient->execSqlCoro(
      "SELECT id,username FROM webauthn.resource_owner WHERE id=?",
      strResourceOwnerId);
  if (sqlResultResourceOwner.size() == 0) {
    LOG_ERROR << "Couldn't find a resource owner with id "
              << strResourceOwnerId;
    throw std::runtime_error{"Internval server error"};
  }

  LOG_DEBUG << "Generate response";
  Json::Value res;
  res["sub"] = sqlResultResourceOwner[0]["id"].as<std::string>();
  res["username"] = sqlResultResourceOwner[0]["username"].as<std::string>();

  callback(HttpResponse::newHttpJsonResponse(res));
  co_return;
}

drogon::AsyncTask
Oidc::clientRegister(HttpRequestPtr req,
                     std::function<void(const HttpResponsePtr &)> callback,
                     std::string website_uri, std::string app_name,
                     int client_type, std::string callback_uri) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " Body: " << req->bodyData();

  try {
    // Check if the website_uri is empty
    if (website_uri.empty()) {
      LOG_ERROR << "The website_uri must NOT be empty";
      throw std::invalid_argument{"The website url has to be specified"};
    }

    // Check if the app_name is empty
    if (app_name.empty()) {
      LOG_ERROR << "The app_name must NOT be empty";
      throw std::invalid_argument{"The application name has to be specified"};
    }

    // The client_type has to be 0.
    // 0 -> Confidential client
    // 1 -> Public client
    if (!(client_type == 0)) {
      LOG_ERROR << "The client_type must be 0(Confidential)";
      throw std::invalid_argument{"The client_type has to be confidential"};
    }

    // Check if the client is already registered
    LOG_INFO << "Check if a client with this app_name or callback_uri is "
                "already registered";
    auto dbClient = app().getDbClient("");
    auto sqlResultClientCount = co_await dbClient->execSqlCoro(
        "SELECT COUNT(client.id) FROM oidc_client as client JOIN "
        "oidc_client_uri as uri WHERE client.app_name=? OR uri.uri=?",
        app_name, callback_uri);
    if (sqlResultClientCount[0][0].as<size_t>() > 0) {
      LOG_DEBUG << "A client with the app_name " << app_name
                << " or callback_uri " << website_uri
                << " is already registered";
      throw std::invalid_argument{"A client with this application name or "
                                  "callback uri is already registered"};
    }

    // Generate client_id and client_secret
    LOG_INFO << "Generate the client_id and client_secret";
    std::random_device rd;
    std::independent_bits_engine<std::mt19937_64, 8, unsigned int> e1{rd()};
    auto client_secret = std::make_shared<std::string>();
    std::generate_n(std::back_inserter(*client_secret), clientSecretLen, e1);
    *client_secret = utils::base64Encode(
        (unsigned char *)client_secret->c_str(), client_secret->size(), true);
    Base64Url::encode(client_secret);
    auto client_id = utils::getUuid();
    unsigned char client_secret_hash[32] = {0};

    // Hash the client_secret
    LOG_DEBUG << "Hash the client_secret";
    int err = mbedtls_sha256(
        reinterpret_cast<const unsigned char *>(client_secret->c_str()),
        client_secret->size(), client_secret_hash, 0);
    if (err != 0) {
      LOG(ERROR) << "An exception occured during the sha256 calculation of the "
                    "client_secret. Error: "
                 << mbedtls_high_level_strerr(err);
      throw std::runtime_error{"Internal server error"};
    }

    auto client_secret_hash_hex =
        utils::binaryStringToHex(client_secret_hash, 32);

    // Insert client
    LOG_DEBUG << "Insert the new client into the database";
    auto sqlResultInsert = co_await dbClient->execSqlCoro(
        "INSERT INTO "
        "oidc_client(client_type,client_id,client_secret,app_name,website_uri) "
        "VALUES(?,?,?,?,?)",
        client_type, client_id, client_secret_hash_hex, app_name, website_uri);

    if (sqlResultInsert.affectedRows() == 0) {
      LOG_ERROR << "Couldn't insert the new client into the database";
      throw std::runtime_error{"Internal server error"};
    }

    // Insert callback URI
    LOG_DEBUG << "Insert the callback_uri into the database";
    auto sqlResultInsertUri = co_await dbClient->execSqlCoro(
        "INSERT INTO oidc_client_uri(fk_oidc_client_id,uri) VALUES(?,?)",
        sqlResultInsert.insertId(), callback_uri);

    if (sqlResultInsertUri.affectedRows() == 0) {
      LOG_ERROR
          << "Couldn't insert the callback uri of the client with the id: "
          << sqlResultInsert.insertId();
      throw std::runtime_error{"Internal server error"};
    }

    // Generate view with client_id and client_secret
    LOG_DEBUG << "Generate the view";
    HttpViewData data;
    data.insert("app_name", app_name);
    data.insert("client_id", client_id);
    data.insert("client_secret", *client_secret);
    data.insert("callback_uri", callback_uri);
    data.insert("website_uri", website_uri);
    callback(
        HttpResponse::newHttpViewResponse("ClientRegisterFinish.csp", data));

  } catch (std::invalid_argument &ex) {
    callback(toError(HttpStatusCode::k400BadRequest, ex.what()));
  } catch (...) {
    callback(toError(HttpStatusCode::k500InternalServerError,
                     "Unkown server error occured"));
  }
  co_return;
}

auto Oidc::generateResponseAuhtorizationCode(size_t &client_id,
                                             std::string &redirect_uri,
                                             size_t &resource_owner_id,
                                             std::string &state)
    -> Task<HttpResponsePtr> {
  // Generate Authorization Code.
  LOG_DEBUG << "Generate the authorization code";
  auto authorizationCode = utils::getUuid();
  LOG_DEBUG << "Authorization code: " << authorizationCode;

  // Store the Authorization Code in Redis.
  LOG_DEBUG << "Store auth_code, client_id, redirect_uri, resource_owner_id "
               "in Redis";
  auto redisClient = app().getRedisClient();
  auto redisTransaction = co_await redisClient->newTransactionCoro();
  co_await redisTransaction->execCommandCoro(
      "SADD auth_code:%s:client_id %u", authorizationCode.c_str(), client_id);
  co_await redisTransaction->execCommandCoro(
      "SADD auth_code:%s:redirect_uri %s", authorizationCode.c_str(),
      redirect_uri.c_str());
  co_await redisTransaction->execCommandCoro(
      "SET auth_code:%s:resource_owner_id %u", authorizationCode.c_str(),
      resource_owner_id);
  co_await redisTransaction->execCommandCoro(
      "EXPIRE auth_code:%s:client_id 600", authorizationCode.c_str());
  co_await redisTransaction->execCommandCoro(
      "EXPIRE auth_code:%s:redirect_uri 600", authorizationCode.c_str());
  co_await redisTransaction->execCommandCoro(
      "EXPIRE auth_code:%s:resource_owner_id 600", authorizationCode.c_str());
  co_await redisTransaction->executeCoro();

  // Redirect the user to the applications redirection url.
  LOG_DEBUG << "Redirect user to the applications redirection url";
  redirect_uri.append("?code=").append(authorizationCode);
  if (!state.empty()) {
    redirect_uri.append("&state=").append(state);
  }
  auto redirectionResponsePtr =
      HttpResponse::newRedirectionResponse(redirect_uri);
  redirectionResponsePtr->setContentTypeString(
      "application/x-www-form-urlencoded");
  co_return redirectionResponsePtr;
}

drogon::AsyncTask Oidc::openIdConfiguration(
    HttpRequestPtr req, std::function<void(const HttpResponsePtr &)> callback) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();
  callback(HttpResponse::newHttpJsonResponse(*this->config));

  co_return;
}
