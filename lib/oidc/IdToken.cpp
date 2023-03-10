#include "IdToken.h"

IdToken::IdToken(
    std::shared_ptr<std::string> iss, std::shared_ptr<std::string> aud,
    std::shared_ptr<std::string> sub, const size_t expire,
    std::shared_ptr<std::chrono::system_clock::time_point> auth_time)
    : iss{iss}, aud{aud}, sub{sub}, auth_time{auth_time} {
  this->iat = std::make_shared<std::chrono::system_clock::time_point>(
      std::chrono::system_clock::now());
  this->exp = std::make_shared<std::chrono::system_clock::time_point>(
      *iat + std::chrono::seconds{300});
}
std::shared_ptr<Json::Value> IdToken::toJson() {
  auto ret = std::make_shared<Json::Value>();
  (*ret)["iss"] = *this->iss;
  (*ret)["aud"] = *this->aud;
  (*ret)["sub"] = *this->sub;
  (*ret)["auth_time"] = std::chrono::duration_cast<std::chrono::seconds>(
                            this->auth_time->time_since_epoch())
                            .count();
  (*ret)["iat"] = std::chrono::duration_cast<std::chrono::seconds>(
                      this->iat->time_since_epoch())
                      .count();
  (*ret)["exp"] = std::chrono::duration_cast<std::chrono::seconds>(
                      this->exp->time_since_epoch())
                      .count();

  return ret;
}

IdToken::~IdToken() {}