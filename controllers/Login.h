#pragma once
#include "WebauthnController.h"
#include "helper/response.h"
#include <CredentialRecord.h>
#include <cstdlib>
#include <drogon/HttpController.h>

using namespace drogon;

class Login : public WebauthnController<Login> {
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Login::begin, "/begin/{name}", Get);
  METHOD_ADD(Login::finish, "/finish/{name}", Post);
  METHOD_ADD(Login::status, "/session/status", Post);
  METHOD_LIST_END
  Login();

  drogon::AsyncTask begin(HttpRequestPtr req,
                          std::function<void(const HttpResponsePtr &)> callback,
                          std::string name);
  drogon::AsyncTask
  finish(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback,
         std::string name);

  drogon::AsyncTask
  status(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback);
};
