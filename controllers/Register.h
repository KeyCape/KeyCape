#pragma once

#include <drogon/HttpController.h>
#include <webauthn.h>

using namespace drogon;

class Register : public drogon::HttpController<Register>
{
  private:
  Webauthn webauthn;
  public:
    METHOD_LIST_BEGIN
    METHOD_ADD(Register::begin, "/begin/{name}", Get);

    // use METHOD_ADD to add your custom processing function here;
    // METHOD_ADD(Register::get, "/{2}/{1}", Get); // path is /Register/{arg2}/{arg1}
    // METHOD_ADD(Register::your_method_name, "/{1}/{2}/list", Get); // path is /Register/{arg1}/{arg2}/list
    // ADD_METHOD_TO(Register::your_method_name, "/absolute/path/{1}/{2}/list", Get); // path is /absolute/path/{arg1}/{arg2}/list

    METHOD_LIST_END
    // your declaration of processing function maybe like this:
    // void get(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, int p1, std::string p2);
    // void your_method_name(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, double p1, int p2) const;

    void begin(const HttpRequestPtr &reg, std::function<void (const HttpResponsePtr &)> &&callback, std::string &&name);
};
