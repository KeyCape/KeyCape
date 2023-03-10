#include <drogon/drogon.h>
#include <glog/logging.h>

int main() {
  google::InitGoogleLogging("");
  FLAGS_logtostderr = 1;
  drogon::app().addListener("0.0.0.0", 80);
  drogon::app().loadConfigFile("../config.json");
  drogon::app().run();
  return 0;
}