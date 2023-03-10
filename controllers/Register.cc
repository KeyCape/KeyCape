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
      LOG_INFO << "The username mus NOT be empty";
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
    LOG_INFO << "Redis: Found entry: " << redisRes.asString();

  } catch (const std::exception &ex) {
    LOG_ERROR << "An exception occured: " << ex.what();
    callback(toError(drogon::HttpStatusCode::k500InternalServerError,
                     "Internal server error"));
  }
  co_return;
}
