#include "Register.h"
#include "PublicKeyCredentialUserEntity.h"
#include <drogon/HttpResponse.h>
#include <drogon/utils/FunctionTraits.h>

// Add definition of your processing function here
void Register::begin(const HttpRequestPtr &req,
                     std::function<void(const HttpResponsePtr &)> &&callback,
                     std::string &&name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();

  // Response pointer
  drogon::HttpResponsePtr resp = nullptr;

  // Check if the username which has to be unique has been provided
  if (name.empty()) {
    resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("The username must NOT be empty");
    resp->setStatusCode(HttpStatusCode::k400BadRequest);
  }

  // PublicKeyCredentialCreationOptions as json
  auto pubKeyCredOpt = this->webauthn.beginRegistration(name);
  LOG_DEBUG << "Response " << pubKeyCredOpt->getJson()->toStyledString();

  // Store the users registration data


  callback(drogon::HttpResponse::newHttpJsonResponse(*pubKeyCredOpt->getJson()));
}

void Register::finish(const HttpRequestPtr &req,
                      std::function<void(const HttpResponsePtr &)> &&callback,
                      std::string &&name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " with body " << req->getBody();
}