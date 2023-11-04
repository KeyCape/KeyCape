#include "SessionToken.h"

SessionToken::SessionToken(){};
std::unique_ptr<Json::Value> SessionToken::getJson() {
  auto json = std::make_unique<Json::Value>(Json::objectValue);
  (*json)["id"] = (this->resourceOwnerId) ? *this->resourceOwnerId : -1;
  (*json)["name"] = (this->resourceOwnerName) ? *this->resourceOwnerName : "";
  (*json)["tm"] = (this->tm) ? *this->tm : 0;

  return json;
}
SessionToken::~SessionToken(){};