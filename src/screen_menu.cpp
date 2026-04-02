#include "App.h"
#include "AppConfig.h"

void App::drawMenuScreen() {
  drawBackground();

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  tft.drawString("CYD Authenticator", centerX, 18, 4);
  tft.drawString("Select a mode", centerX, 52, 2);

  drawButton(btnTwoFA);
  drawButton(btnVault);
}
