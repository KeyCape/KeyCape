#pragma once
#include <drogon/HttpController.h>

drogon::HttpResponsePtr toError(drogon::HttpStatusCode st, std::string &&msg); 