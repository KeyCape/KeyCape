#pragma once

#include <drogon/HttpController.h>
#include <SessionToken.h>
#include "helper/response.h"

using namespace drogon;
/**
 * @brief The User controller class represents the user that is loged in. In order to use this endpoint, the user has to be signed in.
 *
 */
class User : public drogon::HttpController<User>
{
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(User::info, "/info", Get);
  METHOD_LIST_END

  drogon::AsyncTask info(HttpRequestPtr req, std::function<void(const HttpResponsePtr &)> callback) const;
};
