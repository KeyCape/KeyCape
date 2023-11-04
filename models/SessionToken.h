#pragma once
#include <memory>
#include <string>
#include <cstdlib>
#include <IJsonSerialize.h>

class SessionToken : IJsonSerialize {
    public:
    // Database id of the resource owner
    std::shared_ptr<std::size_t> resourceOwnerId;
    std::shared_ptr<std::string> credentialId;
    std::shared_ptr<int64_t> tm;
    std::shared_ptr<std::string> resourceOwnerName;

    SessionToken();
    virtual std::unique_ptr<Json::Value> getJson();
    ~SessionToken();
};