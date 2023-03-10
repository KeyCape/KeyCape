#include "Register.h"
#include "PublicKeyCredentialUserEntity.h"
#include <drogon/HttpResponse.h>
#include <drogon/utils/FunctionTraits.h>

// Add definition of your processing function here
void Register::begin(const HttpRequestPtr &reg,
                     std::function<void(const HttpResponsePtr &)> &&callback,
                     std::string &&name) {
  drogon::HttpResponsePtr resp = nullptr;
  if (name.empty()) {
    resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("The username must NOT be empty");
    resp->setStatusCode(HttpStatusCode::k400BadRequest);
  }

  auto json = this->webauthn.beginRegistration(name)->getJson();

  callback(drogon::HttpResponse::newHttpJsonResponse(*json));
}