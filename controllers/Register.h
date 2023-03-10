#pragma once
#include <helper/response.h>
#include <CredentialRecord.h>
#include <cstdlib>
#include <drogon/HttpController.h>
#include <webauthn.h>

using namespace drogon;

class Register : public drogon::HttpController<Register> {
private:
  Webauthn<CredentialRecord> webauthn;

public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Register::begin, "/begin/{name}", Get);
  METHOD_ADD(Register::finish, "/finish/{name}", Post);
  METHOD_LIST_END
  Register();

  drogon::AsyncTask begin(HttpRequestPtr req,
                          std::function<void(const HttpResponsePtr &)> callback,
                          std::string name);
  drogon::AsyncTask
  finish(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback,
         std::string name);
};
