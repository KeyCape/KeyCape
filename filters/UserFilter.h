#pragma once
#include <controllers/helper/response.h>
#include <drogon/drogon.h>

class UserFilter : public drogon::HttpFilter<UserFilter> {
public:
  virtual void doFilter(const drogon::HttpRequestPtr &req,
                        drogon::FilterCallback &&fcb,
                        drogon::FilterChainCallback &&fccb) override;
};
