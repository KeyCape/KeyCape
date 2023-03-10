#include "Register.h"
#include <drogon/HttpResponse.h>
#include "PublicKeyCredentialUserEntity.h"

// Add definition of your processing function here
void Register::begin(const HttpRequestPtr &reg,
                     std::function<void(const HttpResponsePtr &)> &&callback,
                     std::string &&name) {
  //auto pkcue = PublicKeyCredentialUserEntity("name", "displayname", "id");

  //auto resp = drogon::HttpResponse::newHttpJsonResponse(*pkcue.getJson());
  callback(drogon::HttpResponse::newHttpResponse());
}