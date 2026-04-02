#include "App.h"
#include "AppConfig.h"

void App::drawAccountsScreen() {
  drawBackground();
  drawButton(btnBack);

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  tft.drawString("2FA Accounts", centerX, 14, 4);

  int16_t viewBottom = getAccountsViewportBottom();

  if (accountCount == 0) {
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
    tft.drawString("No accounts yet", centerX, (ACCOUNTS_VIEW_TOP + viewBottom) / 2 - 12, 2);
    tft.drawString("Tap Add Account", centerX, (ACCOUNTS_VIEW_TOP + viewBottom) / 2 + 12, 2);
  }

  for (uint8_t i = 0; i < accountCount; i++) {
    Button row = getAccountButtonAt(i);
    if ((row.y + row.h) < ACCOUNTS_VIEW_TOP || row.y > viewBottom) {
      continue;
    }
    drawButton(row);
  }

  // List scrollbar (always visible when content is scrollable).
  int16_t maxScroll = getAccountsMaxScroll();
  if (maxScroll > 0) {
    int16_t trackX = screenW - 8;
    int16_t trackY = ACCOUNTS_VIEW_TOP;
    int16_t trackH = viewBottom - ACCOUNTS_VIEW_TOP;
    if (trackH > 0) {
      tft.fillRoundRect(trackX, trackY, 4, trackH, 2, COLOR_PANEL);

      int16_t thumbH = (trackH * trackH) / (trackH + maxScroll);
      thumbH = constrain(thumbH, (int16_t)18, trackH);
      int16_t thumbTravel = trackH - thumbH;
      int16_t thumbY = trackY;
      if (thumbTravel > 0) {
        thumbY = trackY + (int16_t)((long)accountsScrollY * thumbTravel / maxScroll);
      }

      tft.fillRoundRect(trackX, thumbY, 4, thumbH, 2, COLOR_PRIMARY);
    }
  }

  drawButton(btnAddAccount);
}
