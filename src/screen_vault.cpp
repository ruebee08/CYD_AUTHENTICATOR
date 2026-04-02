#include "App.h"
#include "AppConfig.h"
#include <cstring>

namespace {

constexpr int16_t VAULT_ROW_HEIGHT = 74;
constexpr int16_t VAULT_ROW_GAP = 10;

}  // namespace

void App::drawVaultRows() {
  int16_t rowX = 14;
  int16_t rowW = screenW - 28;
  int16_t viewBottom = getVaultViewportBottom();

  if (vaultItemCount == 0) {
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
    tft.drawString("No vault items", centerX, centerY - 8, 2);
    tft.drawString("Use Serial: vadd", centerX, centerY + 16, 2);
    return;
  }

  for (uint8_t i = 0; i < vaultItemCount; i++) {
    int16_t rowY = VAULT_VIEW_TOP + (i * (VAULT_ROW_HEIGHT + VAULT_ROW_GAP)) - vaultScrollY;
    if ((rowY + VAULT_ROW_HEIGHT) < VAULT_VIEW_TOP || rowY > viewBottom) {
      continue;
    }

    tft.fillRoundRect(rowX, rowY, rowW, VAULT_ROW_HEIGHT, 12, COLOR_PANEL);
    tft.drawRoundRect(rowX, rowY, rowW, VAULT_ROW_HEIGHT, 12, COLOR_TEXT_LIGHT);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_TEXT_DARK, COLOR_PANEL);
    tft.drawString(vaultItems[i].name, rowX + 10, rowY + 8, 2);

    String shownSecret;
    if (vaultItems[i].revealSecret) {
      shownSecret = String(vaultItems[i].secret);
    } else {
      size_t secretLen = strnlen(vaultItems[i].secret, sizeof(vaultItems[i].secret));
      if (secretLen == 0) {
        shownSecret = "(empty)";
      } else {
        shownSecret.reserve(secretLen);
        for (size_t s = 0; s < secretLen; s++) {
          shownSecret += '*';
        }
      }
    }

    tft.setTextColor(COLOR_TEXT_DARK, COLOR_PANEL);
    tft.drawString(shownSecret, rowX + 10, rowY + 34, 2);

    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(COLOR_SECONDARY, COLOR_PANEL);
    tft.drawString(vaultItems[i].revealSecret ? "Hide" : "Show", rowX + rowW - 10, rowY + 34, 2);
  }

  int16_t maxScroll = getVaultMaxScroll();
  if (maxScroll > 0) {
    int16_t trackX = screenW - 8;
    int16_t trackY = VAULT_VIEW_TOP;
    int16_t trackH = viewBottom - VAULT_VIEW_TOP;
    if (trackH > 0) {
      tft.fillRoundRect(trackX, trackY, 4, trackH, 2, COLOR_PANEL);

      int16_t thumbH = (trackH * trackH) / (trackH + maxScroll);
      thumbH = constrain(thumbH, (int16_t)18, trackH);
      int16_t thumbTravel = trackH - thumbH;
      int16_t thumbY = trackY;
      if (thumbTravel > 0) {
        thumbY = trackY + (int16_t)((long)vaultScrollY * thumbTravel / maxScroll);
      }

      tft.fillRoundRect(trackX, thumbY, 4, thumbH, 2, COLOR_PRIMARY);
    }
  }
}

void App::drawVaultScreen() {
  drawBackground();
  drawButton(btnBack);

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  tft.drawString("Access Vault", centerX, 14, 4);

  drawVaultRows();
}
