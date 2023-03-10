#include "Register.h"
#include "PublicKeyCredentialUserEntity.h"
#include <drogon/HttpResponse.h>
#include <drogon/utils/FunctionTraits.h>

// Standard constructor
Register::Register() {
  auto relyingPartyId = std::getenv("WEBAUTHN_RP_ID");
  auto relyingPartyName = std::getenv("WEBAUTHN_RP_NAME");

  if (relyingPartyId != NULL) {
    auto rpId = std::string{relyingPartyId};
    this->webauthn.setRpId(rpId);
  } else {
    auto rpId = std::string{"localhost"};
    this->webauthn.setRpId(rpId);
  }

  if (relyingPartyName != NULL) {
    auto rpName = std::string{relyingPartyName};
    this->webauthn.setRpName(rpName);
  } else {
    auto rpName = std::string{"localhost"};
    this->webauthn.setRpName(rpName);
  }
}

// Add definition of your processing function here
drogon::AsyncTask
Register::begin(const HttpRequestPtr req,
                std::function<void(const HttpResponsePtr &)> callback,
                std::string name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();
  try {
    // Response pointer
    drogon::HttpResponsePtr resp = nullptr;

    // Check if the username which has to be unique has been provided
    if (name.empty()) {
      LOG_INFO << "The username must NOT be empty";
      callback(toError(drogon::HttpStatusCode::k400BadRequest,
                       "The username is invalid"));
      co_return;
    } else {
      // PublicKeyCredentialCreationOptions as json
      auto jsonPubKeyCredOpt =
          this->webauthn.beginRegistration(name)->getJson();
      auto builder = Json::StreamWriterBuilder{};
      builder["indentation"] = "";
      builder["commentStyle"] = "None";
      auto strJsonResponse = Json::writeString(builder, *jsonPubKeyCredOpt);

      // Store the users registration data
      auto redisClient = app().getRedisClient();

      co_await redisClient->execCommandCoro(
          "set registration:%s %s", name.c_str(), strJsonResponse.c_str());

      LOG_DEBUG << "Response " << strJsonResponse;
      callback(drogon::HttpResponse::newHttpJsonResponse(*jsonPubKeyCredOpt));
    }

  } catch (const std::exception &ex) {
    LOG_ERROR << "An exception occured: " << ex.what();
    callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                     "Internal server error"));
  }
  co_return;
}

drogon::AsyncTask
Register::finish(HttpRequestPtr req,
                 std::function<void(const HttpResponsePtr &)> callback,
                 std::string name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " with body " << req->getBody();
  try {
    if (name.empty()) {
      LOG_INFO << "The username mus NOT be empty";
      callback(toError(drogon::HttpStatusCode::k400BadRequest,
                       "The username is invalid"));
      co_return;
    }
    auto redisClient = app().getRedisClient();
    auto redisRes = co_await redisClient->execCommandCoro("get registration:%s",
                                                          name.c_str());

    if (redisRes.type() == nosql::RedisResultType::kNil) {
      LOG_INFO << "Redis: No entry for the username: " << name << " found";
      callback(
          toError(drogon::HttpStatusCode::k400BadRequest,
                  "Missing redistration data for username " + name +
                      ". /register/begin must have been called berforehand"));
      co_return;
    }
    std::string optionsJson{redisRes.asString()};
    LOG_INFO << "Redis: Found entry: " << optionsJson.c_str();

    LOG_DEBUG << "Deserialize database entry...";
    std::shared_ptr<Json::Value> root = std::make_shared<Json::Value>();
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

    if (!reader->parse(optionsJson.c_str(),
                       optionsJson.c_str() + optionsJson.length(), &(*root),
                       nullptr)) {
      LOG_DEBUG << "Couldn't parse the database entry to JSON";
      callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                       "Internal server error"));
      co_return;
    }

    // std::string body = req->body();
    //  std::shared_ptr<Json::Value> reqJson = std::make_shared<Json::Value>();
    //  Json::CharReaderBuilder reqBuilder;
    //  std::unique_ptr<Json::CharReader> reqReader{reqBuilder.newCharReader()};

    // if (!reader->parse(body.c_str(), body.c_str()+ body.length(),
    // &(*reqJson), nullptr)) {
    //   LOG_DEBUG << "Couldn't parse the request body to JSON";
    //   callback(toError(drogon::HttpStatusCode::k500InternalServerError,
    //                    "Internal server error"));
    //   co_return;
    // }

    std::shared_ptr<PublicKeyCredentialCreationOptions> options =
        PublicKeyCredentialCreationOptions::fromJson(root);
    auto jsonObj = req->jsonObject();
    auto credentialRecord =
        this->webauthn.finishRegistration(options, req->getJsonObject());

    // §7.1.24 Verify that the credentialId is not yet registered for any user.
    // If the credentialId is already known then the Relying Party SHOULD fail
    // this registration ceremony.
    auto dbPtr = app().getDbClient("db");
    auto sqlResultUserCount = co_await dbPtr->execSqlCoro(
        "SELECT COUNT(username) FROM webauthn.credential WHERE username=?",
        name);
    if (sqlResultUserCount[0][0].as<size_t>() > 0) {
      LOG_INFO << "The username " << name << " already exists";
      throw std::invalid_argument{"User already registered"};
    }

    // §7.1.25 If the attestation statement attStmt verified successfully and is
    // found to be trustworthy, then create and store a new credential record in
    // the user account that was denoted in options.user,
    auto publicKeyPtr =
        static_pointer_cast<PublicKeyEC2>(credentialRecord->publicKey);
    auto sqlResultPbKey = co_await dbPtr->execSqlCoro(
        "INSERT INTO webauthn.public_key (kty, alg, crv, x, "
        "y) VALUES(?,?,?,?,?)",
        credentialRecord->publicKey->kty, credentialRecord->publicKey->alg,
        publicKeyPtr->crv, publicKeyPtr->x, publicKeyPtr->y);

    if (sqlResultPbKey.affectedRows() == 0) {
      LOG_ERROR << "Couldn't insert the public key";
      std::runtime_error{"Internal server error"};
    }

    auto sqlResultCredential = co_await dbPtr->execSqlCoro(
        "INSERT INTO webauthn.credential (username, credential_id, "
        "credential_type, credential_signcount, be, bs, fk_public_key) "
        "VALUES(?,?,?,?,?,?,?)",
        name, *credentialRecord->id, credentialRecord->type,
        credentialRecord->signCount, credentialRecord->be, credentialRecord->bs,
        sqlResultPbKey.insertId());

    if (sqlResultPbKey.affectedRows() == 0) {
      LOG_ERROR << "Couldn't insert the user credential";
      std::runtime_error{"Internal server error"};
    }

    callback(drogon::HttpResponse::newHttpResponse());
  } catch (std::invalid_argument &ex) {
    LOG_INFO << "An exception occured: " << ex.what();
    callback(toError(drogon::HttpStatusCode::k400BadRequest, ex.what()));
  } catch (const std::exception &ex) {
    LOG_ERROR << "An exception occured: " << ex.what();
    callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                     "Internal server error"));
  }
  co_return;
}