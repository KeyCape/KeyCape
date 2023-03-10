#include "Oidc.h"

/**
 * @brief Authorization Endpoint
 */
drogon::AsyncTask
Oidc::authorize(HttpRequestPtr req,
                std::function<void(const HttpResponsePtr &)> callback,
                std::string &&response_type, std::string &&client_id,
                std::string &&redirect_uri, std::string &&scope) {
  LOG_DEBUG << "Request on " << req->getPath() << " from "
            << req->getPeerAddr().toIp() << " Body: " << req->bodyData()
            << " Method: " << req->getMethodString()
            << " Query: " << req->getQuery();

  try {
    // The scope has to be openid
    if (scope != "openid") {
      LOG_ERROR << "The scope has to contain the string openid.";
      throw std::invalid_argument{
          "The scope has to contain the string openid."};
    }

    // The response_type has to be code. Others aren't supported.
    if (response_type != "code") {
      LOG_ERROR
          << "The response_type has to contain the string code(Other flows "
             "aren't supported).";
      throw std::invalid_argument{"The response_type has to contain the string "
                                  "code(Other flows aren't supported)."};
    }

    // client_id: OAuth 2.0 Client Identifier valid at the Authorization Server.
    if (client_id.empty()) {
      LOG_ERROR << "The client_id must NOT be empty.";
      throw std::invalid_argument{"The client_id must NOT be empty."};
    }

    // redirect_uri
    if (redirect_uri.empty()) {
      LOG_ERROR << "The redirect_uri must NOT be empty.";
      throw std::invalid_argument{"The redirect_uri must NOT be empty."};
    }

  } catch (std::invalid_argument &ex) {
    callback(toError(HttpStatusCode::k400BadRequest, ex.what()));
  }
  co_return;
}
