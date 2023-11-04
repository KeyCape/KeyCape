#include "User.h"

drogon::AsyncTask
User::info(HttpRequestPtr req,
           std::function<void(const HttpResponsePtr &)> callback) const {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp();
  try {
    auto dbPtr = app().getDbClient("");

    auto sessionPtr = req->getSession();
    if (!sessionPtr->find("token")) {
        LOG_FATAL << "This error shouldn't have been thrown. It should have been catched by the filter. Error: The session token couldn't be found!";
        throw std::invalid_argument{"You must be logged in to use this functionality"};
    }
    SessionToken sToken = sessionPtr->get<SessionToken>("token");
    auto jsonPtr = sToken.getJson();

    callback(drogon::HttpResponse::newHttpJsonResponse(*jsonPtr));
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