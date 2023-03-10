#include "response.h"

drogon::HttpResponsePtr toError(drogon::HttpStatusCode st, std::string &&msg) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(st);
  response->setBody(msg);
  return response;
}