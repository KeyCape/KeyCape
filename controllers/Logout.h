#pragma once
#include "helper/response.h"
#include <drogon/HttpController.h>
#include <webauthn.h>

using namespace drogon;

class Logout : public drogon::HttpController<Logout> {
private:
  Webauthn<CredentialRecord> webauthn;

public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Logout::logout, "", Post);
  METHOD_LIST_END
  Logout();

  drogon::AsyncTask
  logout(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback);
};
