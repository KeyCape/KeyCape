#include <drogon/drogon.h>
#include <webauthn.h>

int main() {
  auto wa = Webauthn{"Relying Party Name", "Relying Party Id"};
  drogon::app().addListener("0.0.0.0", 80);
  drogon::app().loadConfigFile("../config.json");
  drogon::app().run();
  return 0;
}