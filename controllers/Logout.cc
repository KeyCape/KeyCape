#include "Logout.h"

// Add definition of your processing function here
Logout::Logout() {}

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