#pragma once
#include <drogon/HttpController.h>
#include <string>
#include <helper/response.h>

using namespace drogon;

class Oidc : public drogon::HttpController<Oidc> {
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Oidc::authorize,
             "authorize?response_type={1}&client_id={2}&redirect_uri={3}&scope={4}", Get);
  METHOD_LIST_END

  drogon::AsyncTask
  authorize(HttpRequestPtr req,
            std::function<void(const HttpResponsePtr &)> callback,
            std::string &&response_type, std::string &&client_id,
            std::string &&redirect_uri, std::string &&scope);
};
