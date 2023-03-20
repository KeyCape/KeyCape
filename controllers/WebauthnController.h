#pragma once
#include <CredentialRecord.h>
#include <drogon/HttpController.h>
#include <webauthn.h>

template <typename T>
class WebauthnController : public drogon::HttpController<T> {
protected:
  std::shared_ptr<Webauthn<CredentialRecord>> webauthn;
  std::shared_ptr<Policy> policy;
  std::shared_ptr<std::string> rpId;
  std::shared_ptr<std::string> rpName;

public:
  WebauthnController();
  ~WebauthnController();
};

template <typename T> WebauthnController<T>::WebauthnController() {
  if (!webauthn) {
    // Set relying party name
    auto relyingPartyName = std::getenv("WEBAUTHN_RP_NAME");
    if (relyingPartyName != NULL) {
      rpName = std::make_shared<std::string>(relyingPartyName);
    } else {
      rpName = std::make_shared<std::string>("localhost");
    }

    // Set relying party id
    auto relyingPartyId = std::getenv("WEBAUTHN_RP_ID");
    if (relyingPartyId != NULL) {
      rpId = std::make_shared<std::string>(relyingPartyId);
    } else {
      rpId = std::make_shared<std::string>("localhost");
    }

    // Set Policy
    policy = std::make_shared<Policy>();
    policy->userVerification = std::make_shared<UserVerificationRequirement>(
        UserVerificationRequirement::preferred);
    policy->attestation = std::make_shared<AttestationConveyancePreference>(
        AttestationConveyancePreference::indirect);
    policy->attStmtFmts = std::make_shared<
        std::forward_list<AttestationStatementFormatIdentifier>>();
    //policy->attStmtFmts->push_front(AttestationStatementFormatIdentifier::fido_u2f);

    // Create instance of webauthn
    webauthn =
        std::make_shared<Webauthn<CredentialRecord>>(rpName, rpId, policy);
  }
}

template <typename T> WebauthnController<T>::~WebauthnController() {}