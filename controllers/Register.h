#pragma once

#include "helper/response.h"
#include <CredentialRecord.h>
#include <drogon/HttpController.h>
#include <webauthn.h>

using namespace drogon;

class Register : public drogon::HttpController<Register> {
private:
  Webauthn<CredentialRecord> webauthn{"localhost", "localhost"};

public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Register::begin, "/begin/{name}", Get);
  METHOD_ADD(Register::finish, "/finish/{name}", Post);
  METHOD_LIST_END

  drogon::AsyncTask begin(HttpRequestPtr req,
                          std::function<void(const HttpResponsePtr &)> callback,
                          std::string name);
  drogon::AsyncTask
  finish(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback,
         std::string name);
};
