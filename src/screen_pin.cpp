#include "App.h"
#include "AppConfig.h"

void App::drawPinEntry() {
  if (pinSetupRequired) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextDatum(TC_DATUM);
    tft.drawString("PIN setup required", centerX, 48, 4);
    tft.drawString("Open Serial Monitor", centerX, 94, 2);
    tft.drawString("and enter your 6-digit PIN", centerX, 118, 2);
    tft.drawString("when prompted.", centerX, 142, 2);
    return;
  }

  tft.fillRoundRect(14, 44, screenW - 28, 44, 12, COLOR_PANEL);

  int16_t cellGap = 8;
  int16_t totalGap = cellGap * 5;
  int16_t cellW = ((screenW - 52) - totalGap) / 6;
  int16_t x = 26;
  int16_t y = 54;

  for (uint8_t i = 0; i < 6; i++) {
    uint16_t fill = (i < enteredPinLen) ? COLOR_PRIMARY : COLOR_BG;
    uint16_t text = (i < enteredPinLen) ? COLOR_TEXT_LIGHT : COLOR_TEXT_DARK;

    tft.fillRoundRect(x, y, cellW, 24, 6, fill);
    tft.drawRoundRect(x, y, cellW, 24, 6, COLOR_TEXT_LIGHT);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(text, fill);
    char cellText[2] = {'-', '\0'};
    if (i < enteredPinLen) {
      cellText[0] = enteredPin[i];
    }
    tft.drawString(cellText, x + (cellW / 2), y + 12, 2);

    x += cellW + cellGap;
  }

  tft.fillRect(0, 88, screenW, 10, COLOR_BG);
  tft.setTextDatum(TC_DATUM);
  uint32_t nowUnix = (uint32_t)getUnixTimeSeconds();
  if (isPinDailyCapReached()) {
    tft.setTextColor(TFT_RED, COLOR_BG);
    tft.drawString("Daily attempt cap reached", centerX, 90, 2);
  } else if (pinLockoutUntilUnix > nowUnix) {
    uint32_t secondsLeft = pinLockoutUntilUnix - nowUnix;
    char waitMsg[32];
    snprintf(waitMsg, sizeof(waitMsg), "Try again in %lus", (unsigned long)secondsLeft);
    tft.setTextColor(TFT_RED, COLOR_BG);
    tft.drawString(waitMsg, centerX, 90, 2);
  } else if (pinShowError) {
    tft.setTextColor(TFT_RED, COLOR_BG);
    tft.drawString("Incorrect PIN", centerX, 90, 2);
  } else {
    tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
    tft.drawString("Enter 6-digit PIN", centerX, 90, 2);
  }
}

void App::drawPinScreen() {
  if (pinSetupRequired) {
    drawPinEntry();
    return;
  }

  drawBackground();

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  tft.drawString("CYD Authenticator", centerX, 12, 4);
  tft.drawString("Unlock", centerX, 28, 2);

  drawPinEntry();

  for (uint8_t i = 0; i < 12; i++) {
    drawButton(pinButtons[i]);
  }
}
