#pragma once
#include "WebauthnController.h"
#include "helper/response.h"
#include <drogon/HttpController.h>
#include <webauthn.h>

using namespace drogon;

class Logout : public WebauthnController<Logout> {
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(Logout::logout, "", Post);
  METHOD_LIST_END
  Logout();

  drogon::AsyncTask
  logout(HttpRequestPtr req,
         std::function<void(const HttpResponsePtr &)> callback);
};
