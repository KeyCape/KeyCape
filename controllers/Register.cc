#include "Register.h"
#include "PublicKeyCredentialUserEntity.h"
#include <drogon/HttpResponse.h>
#include <drogon/utils/FunctionTraits.h>

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
      resp = drogon::HttpResponse::newHttpResponse();
      resp->setBody("The username must NOT be empty");
      resp->setStatusCode(HttpStatusCode::k400BadRequest);
      callback(resp);
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
    LOG_ERROR << "Redis client couldn't save the temporary registration data: "
              << ex.what();
    auto resPtr = drogon::HttpResponse::newHttpResponse();
    resPtr->setStatusCode(HttpStatusCode::k500InternalServerError);
    resPtr->setBody("Internal database error");
    callback(resPtr);
  }
  co_return;
}

void Register::finish(const HttpRequestPtr &req,
                      std::function<void(const HttpResponsePtr &)> &&callback,
                      std::string &&name) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " with body " << req->getBody();
}