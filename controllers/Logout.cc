#include "Logout.h"

// Add definition of your processing function here
Logout::Logout() {
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
Logout::logout(HttpRequestPtr req,
               std::function<void(const HttpResponsePtr &)> callback) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();
  auto session = req->session();
  if (!session->find("token")) {
    LOG_ERROR << "No session found";
    callback(toError(drogon::HttpStatusCode::k400BadRequest,
                     "You have to login before you can logout"));
    co_return;
  }
  LOG_INFO << "Erase session";
  session->erase("token");
  callback(drogon::HttpResponse::newHttpResponse());
}