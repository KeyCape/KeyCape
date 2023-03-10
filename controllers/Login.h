#pragma once
#include <CredentialRecord.h>
#include <cstdlib>
#include <drogon/HttpController.h>
#include <helper/response.h>
#include <webauthn.h>

using namespace drogon;

class Login : public drogon::HttpController<Login> {
private:
  Webauthn<CredentialRecord> webauthn;

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
