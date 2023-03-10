#include "Login.h"

// Standard constructor
Login::Login() {
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

    auto response = this->webauthn.beginLogin(credentialRecordList);
    callback(drogon::HttpResponse::newHttpJsonResponse(*response->getJson()));

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
  co_return;
}