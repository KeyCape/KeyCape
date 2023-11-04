#include "UserFilter.h"

void UserFilter::doFilter(const drogon::HttpRequestPtr &req,
                          drogon::FilterCallback &&fcb,
                          drogon::FilterChainCallback &&fccb) {
  auto sessionPtr = req->getSession();
  if (!sessionPtr->find("token")) {
    fcb(toError(drogon::HttpStatusCode::k401Unauthorized,
                 "You must be logged in to use this functionality"));
    return;
  }
  fccb();
  return;
}
