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
    callback(resp);
    return;
  }

  // PublicKeyCredentialCreationOptions as json
  auto jsonPubKeyCredOpt = this->webauthn.beginRegistration(name)->getJson();
  auto jsonResponse = jsonPubKeyCredOpt->toStyledString();
  LOG_DEBUG << "Response " << jsonResponse;

  // Store the users registration data
  auto redisClient = app().getRedisClient();
  redisClient->execCommandAsync(
      [callback, js = *jsonPubKeyCredOpt](const drogon::nosql::RedisResult &r) {
        callback(drogon::HttpResponse::newHttpJsonResponse(js));
      },
      [&callback](const std::exception &ex) {
        LOG_ERROR
            << "Redis client couldn't save the temporary registration data "
            << ex.what();
        auto resPtr = drogon::HttpResponse::newHttpResponse();
        resPtr->setStatusCode(HttpStatusCode::k500InternalServerError);
        resPtr->setBody("Internal database error");
        callback(resPtr);
      },
      "set registration:%s %b", name.c_str(), jsonResponse.c_str(),
      jsonResponse.size());
}

void Register::finish(const HttpRequestPtr &req,
                      std::function<void(const HttpResponsePtr &)> &&callback,
                      std::string &&name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " with body " << req->getBody();
}