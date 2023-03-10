#include "Login.h"

// Standard constructor
Login::Login() {}

drogon::AsyncTask
Login::begin(HttpRequestPtr req,
             std::function<void(const HttpResponsePtr &)> callback,
             std::string name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();
  try {

    auto dbPtr = app().getDbClient("");

    // Receive user credentials from database
    LOG_DEBUG << "Searching user credentials for user " << name;
    auto sqlResultUserCredential = co_await dbPtr->execSqlCoro(
        "SELECT username, credential_id, credential_type, "
        "credential_signcount, "
        "be, bs FROM webauthn.credential WHERE username=?",
        name);
    if (sqlResultUserCredential.size() == 0) {
      LOG_INFO << "No credentials found for the username: " << name;
      throw std::invalid_argument{"No credentials found"};
    }
    auto credentialRecordList =
        std::make_shared<std::forward_list<CredentialRecord>>();
    std::transform(
        sqlResultUserCredential.cbegin(), sqlResultUserCredential.cend(),
        std::front_inserter(*credentialRecordList), [](drogon::orm::Row row) {
          auto record = CredentialRecord();
          record.type = static_cast<PublicKeyCredentialType>(
              row["credential_type"].as<int>());
          record.id = std::make_shared<std::string>(
              row["credential_id"].as<std::string>());
          record.signCount = row["credential_signcount"].as<uint32_t>();
          record.be = row["be"].as<bool>();
          record.bs = row["bs"].as<bool>();
          return record;
        });

    LOG_DEBUG << "Found " << sqlResultUserCredential.size()
              << " credentials for the username " << name;

    auto response = this->webauthn->beginLogin(credentialRecordList);

    // PublicKeyCredentialRequestOptions as json
    auto jsonPubKeyCredReqOpt = response->getJson();
    auto builder = Json::StreamWriterBuilder{};
    builder["indentation"] = "";
    builder["commentStyle"] = "None";
    auto strJsonResponse = Json::writeString(builder, *jsonPubKeyCredReqOpt);

    // Cache PublicKeyCredentialRequestOptions
    LOG_DEBUG << "Cache the response";
    auto redisClient = app().getRedisClient();
    co_await redisClient->execCommandCoro("set login:%s %s", name.c_str(),
                                          strJsonResponse.c_str());
    LOG_DEBUG << "Response " << strJsonResponse;
    callback(drogon::HttpResponse::newHttpJsonResponse(*jsonPubKeyCredReqOpt));

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

drogon::AsyncTask
Login::finish(HttpRequestPtr req,
              std::function<void(const HttpResponsePtr &)> callback,
              std::string name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();

  try {
    // Check if a PublicKeyCredentialRequestOptions record is cached
    auto redisClient = app().getRedisClient();
    auto redisRes =
        co_await redisClient->execCommandCoro("get login:%s", name.c_str());

    if (redisRes.type() == nosql::RedisResultType::kNil) {
      LOG_INFO << "Redis: No entry for the username: " << name << " found";
      callback(toError(drogon::HttpStatusCode::k400BadRequest,
                       "Missing login data for username " + name +
                           ". /login/begin must have been called berforehand"));
      co_return;
    }
    std::string redisResJson{redisRes.asString()};
    LOG_DEBUG << "Redis: Found entry: " << redisResJson.c_str();

    LOG_DEBUG << "Deserialize database entry...";
    std::shared_ptr<Json::Value> root = std::make_shared<Json::Value>();
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

    if (!reader->parse(redisResJson.c_str(),
                       redisResJson.c_str() + redisResJson.length(), &(*root),
                       nullptr)) {
      LOG_DEBUG << "Couldn't parse the database entry to JSON";
      callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                       "Internal server error"));
      co_return;
    }

    auto pubKeyCredReqOpt = PublicKeyCredentialRequestOptions::fromJson(root);

    // Pull user credentials from the database
    auto dbPtr = app().getDbClient("");
    auto sqlResultUserCredentialList = co_await dbPtr->execSqlCoro(
        "SELECT c.username, c.credential_id, c.credential_type, "
        "c.credential_signcount, c.be, c.bs, p.kty, p.alg, p.crv, p.x, p.y, "
        "p.n, "
        "p.e FROM credential AS c INNER JOIN public_key AS p ON "
        "c.fk_public_key=p.id WHERE c.username=?",
        name.c_str());
    LOG_DEBUG << "Rows selected: " << sqlResultUserCredentialList.size();

    if (sqlResultUserCredentialList.size() < 1) {
      LOG_INFO << "No database entry found for the user: " << name.c_str();
      callback(
          toError(drogon::HttpStatusCode::k400BadRequest, "User not found"));
      co_return;
    }

    // Extract database entries
    auto credRec = std::make_shared<std::forward_list<CredentialRecord>>();
    for (auto row : sqlResultUserCredentialList) {
      CredentialRecord tmpCred;
      tmpCred.uName = std::make_shared<std::string>(row[0].as<std::string>());
      tmpCred.id = std::make_shared<std::string>(drogon::utils::base64Encode(
          (const unsigned char *)row[1].c_str(), row[1].length(), true));
      Base64Url::encode(tmpCred.id);
      switch (row[2].as<uint32_t>()) {
      case PublicKeyCredentialType::public_key:
        tmpCred.type = PublicKeyCredentialType::public_key;
        break;
      default:
        LOG_ERROR << "The PublicKeyCredentialType entry is invalid.";
        callback(
            toError(drogon::HttpStatusCode::k400BadRequest, "User not found"));
        co_return;
      }
      tmpCred.signCount = row[3].as<uint32_t>();
      tmpCred.be = row[4].as<bool>();
      tmpCred.bs = row[5].as<bool>();

      auto coseKeyType = row[6].as<int>();
      switch (coseKeyType) {
      case COSEKeyType::EC2: {
        LOG_INFO << "Found EC2 public key";
        auto tmpPKey = std::make_shared<PublicKeyEC2>();
        tmpPKey->crv = row[8].as<int>();
        tmpPKey->x = row[9].as<std::vector<char>>();
        tmpPKey->y = row[10].as<std::vector<char>>();
        tmpCred.publicKey = std::move(tmpPKey);
        break;
      }
      case COSEKeyType::RSA: {
        LOG_INFO << "Found RSA public key";
        auto tmpPKey = std::make_shared<PublicKeyRSA>();
        tmpPKey->n = row[11].as<std::vector<char>>();
        tmpPKey->e = row[12].as<std::vector<char>>();
        tmpCred.publicKey = std::move(tmpPKey);
        break;
      }
      default:
        LOG_ERROR << "Found not implemented public key type. COSEKeyType: "
                  << coseKeyType;
        callback(toError(drogon::HttpStatusCode::k400BadRequest,
                         "Found database entry with invalid key type"));
        co_return;
      }
      auto algorithm = row[7].as<int>();
      switch (algorithm) {
      case COSEAlgorithmIdentifier::ES256:
        LOG_INFO << "Using algorithm ES256";
        break;
      case COSEAlgorithmIdentifier::ES384:
        LOG_INFO << "Using algorithm ES384";
        break;
      case COSEAlgorithmIdentifier::ES512:
        LOG_INFO << "Using algorithm ES512";
        break;
      case COSEAlgorithmIdentifier::EDDSA:
        LOG_INFO << "Using algorithm EDDSA";
        break;
      case COSEAlgorithmIdentifier::ED25519:
        LOG_INFO << "Using algorithm ED25519";
        break;
      case COSEAlgorithmIdentifier::P256:
        LOG_INFO << "Using algorithm P256";
        break;
      case COSEAlgorithmIdentifier::P384:
        LOG_INFO << "Using algorithm P384";
        break;
      case COSEAlgorithmIdentifier::P521:
        LOG_INFO << "Using algorithm P521";
        break;
      }
      tmpCred.publicKey->alg = static_cast<COSEAlgorithmIdentifier>(algorithm);
      credRec->emplace_front(std::move(tmpCred));
    }

    auto pKeyCred =
        std::make_shared<PublicKeyCredential<AuthenticatorAssertionResponse>>();
    auto jsonReq = req->getJsonObject();
    pKeyCred->fromJson(jsonReq);

    // Check the request and update the CredentialRecord credRec
    auto credRecIt =
        this->webauthn->finishLogin(pKeyCred, pubKeyCredReqOpt, credRec);

    // Update database
    auto sqlResultCredentialUpdate = co_await dbPtr->execSqlCoro(
        "UPDATE credential SET credential_signcount=?, bs=? WHERE "
        "credential_id=?",
        credRecIt->signCount, credRecIt->bs,
        drogon::utils::base64Decode(*credRecIt->id));
    LOG_DEBUG << "Rows updated: " << sqlResultCredentialUpdate.affectedRows();
    /*if (sqlResultCredentialUpdate.affectedRows() <= 0) {
      LOG_ERROR
          << "Couldn't update the credentials signature count and backup state";
      callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                       "An internal server error occured"));
      co_return;
    }*/
    LOG_INFO << "User " << *credRecIt->uName << " logged in";

    // Set session token
    LOG_INFO << "Set session token";
    auto sessionPtr = req->session();
    if (sessionPtr->find("token")) {
      LOG_DEBUG << "Token already set. Modifying token";
      sessionPtr->modify<CredentialRecord>(
          "token", [credRecIt](CredentialRecord &rec) { rec = *credRecIt; });
    } else {
      sessionPtr->insert("token", *credRecIt);
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
drogon::AsyncTask
Login::status(HttpRequestPtr req,
              std::function<void(const HttpResponsePtr &)> callback) {
  (req->session()->find("token")
       ? callback(drogon::HttpResponse::newHttpResponse())
       : callback(toError(drogon::HttpStatusCode::k401Unauthorized,
                          "You are not logged in")));
  co_return;
}