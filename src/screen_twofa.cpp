#include "App.h"
#include "AppConfig.h"
#include <cctype>
#include <cstring>
#include <mbedtls/md.h>

namespace {

int8_t base32Value(char ch) {
  char c = (char)toupper((unsigned char)ch);
  if (c >= 'A' && c <= 'Z') {
    return (int8_t)(c - 'A');
  }
  if (c >= '2' && c <= '7') {
    return (int8_t)(26 + (c - '2'));
  }
  return -1;
}

bool decodeBase32(const char* input, uint8_t* out, size_t outMax, size_t& outLen) {
  uint32_t buffer = 0;
  uint8_t bitsLeft = 0;
  outLen = 0;

  for (size_t i = 0; input[i] != '\0'; i++) {
    char ch = input[i];
    if (ch == ' ' || ch == '-' || ch == '=') {
      continue;
    }

    int8_t val = base32Value(ch);
    if (val < 0) {
      return false;
    }

    buffer = (buffer << 5) | (uint32_t)val;
    bitsLeft += 5;

    while (bitsLeft >= 8) {
      bitsLeft -= 8;
      if (outLen >= outMax) {
        return false;
      }
      out[outLen++] = (uint8_t)((buffer >> bitsLeft) & 0xFFu);
    }
  }

  return outLen > 0;
}

}  // namespace

void App::drawRing(float progress) {
  progress = constrain(progress, 0.0f, 1.0f);
  int16_t progressDeg = (int16_t)(progress * 360.0f);

  for (int16_t deg = 0; deg < 360; deg++) {
    float rad = ((float)deg - 90.0f) * DEG_TO_RAD;
    uint16_t color = (deg < progressDeg) ? COLOR_PRIMARY : COLOR_SECONDARY;

    for (int16_t r = ringInnerR; r <= ringOuterR; r++) {
      int16_t px = centerX + (int16_t)(cosf(rad) * r);
      int16_t py = ringCenterY + (int16_t)(sinf(rad) * r);
      tft.drawPixel(px, py, color);
    }
  }
}

void App::drawSecondsLeft(uint8_t secondsLeft) {
  tft.fillRoundRect(centerX - 42, ringCenterY + 26, 84, 24, 8, COLOR_PANEL);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_PANEL);

  char buf[16];
  snprintf(buf, sizeof(buf), "%2us", secondsLeft);
  tft.drawString(buf, centerX, ringCenterY + 38, 4);
}

void App::drawTotpCode(const char* code) {
  tft.fillRoundRect(centerX - 100, ringCenterY - 28, 200, 56, 12, COLOR_PANEL);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_PANEL);
  tft.drawString(code, centerX, ringCenterY - 2, 7);
}

bool App::generateTotpCode(uint8_t accountIndex, uint64_t unixTimeSeconds, char outCode[7]) const {
  if (accountIndex >= accountCount) {
    return false;
  }

  const char* secretBase32 = accounts[accountIndex].secret;
  if (secretBase32[0] == '\0') {
    return false;
  }

  uint8_t key[64];
  size_t keyLen = 0;
  if (!decodeBase32(secretBase32, key, sizeof(key), keyLen)) {
    return false;
  }

  uint64_t counter = unixTimeSeconds / (TOTP_PERIOD_MS / 1000ULL);
  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; i--) {
    counterBytes[i] = (uint8_t)(counter & 0xFFu);
    counter >>= 8;
  }

  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (mdInfo == nullptr) {
    return false;
  }

  uint8_t digest[20];
  int rc = mbedtls_md_hmac(mdInfo, key, keyLen, counterBytes, sizeof(counterBytes), digest);
  if (rc != 0) {
    return false;
  }

  uint8_t offset = digest[19] & 0x0F;
  uint32_t binary = ((uint32_t)(digest[offset] & 0x7F) << 24) |
                    ((uint32_t)digest[offset + 1] << 16) |
                    ((uint32_t)digest[offset + 2] << 8) |
                    (uint32_t)digest[offset + 3];

  uint32_t otp = binary % 1000000u;
  snprintf(outCode, 7, "%06lu", (unsigned long)otp);
  return true;
}

void App::drawTwoFAScreen() {
  drawBackground();
  drawButton(btnBack);

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  tft.drawString("2FA", centerX, 12, 4);

  drawTotpCode(currentTotpCode);

  tft.setTextDatum(TC_DATUM);
  tft.setTextColor(COLOR_TEXT_DARK, COLOR_BG);
  if (accountCount > 0 && selectedAccountIndex < accountCount) {
    tft.drawString(accounts[selectedAccountIndex].name, centerX, screenH - 24, 2);
  } else {
    tft.drawString("No account", centerX, screenH - 24, 2);
  }

  drawRing(0.0f);
  drawSecondsLeft(30);
}

void App::updateTwoFAScreen() {
  uint64_t unixNow = getUnixTimeSeconds();
  uint64_t step = unixNow / (TOTP_PERIOD_MS / 1000ULL);

  if (step != lastTotpStep) {
    char nextCode[7] = "------";
    if (generateTotpCode(selectedAccountIndex, unixNow, nextCode)) {
      strncpy(currentTotpCode, nextCode, sizeof(currentTotpCode) - 1);
      currentTotpCode[sizeof(currentTotpCode) - 1] = '\0';
    } else {
      strncpy(currentTotpCode, "ERR---", sizeof(currentTotpCode) - 1);
      currentTotpCode[sizeof(currentTotpCode) - 1] = '\0';
    }
    drawTotpCode(currentTotpCode);
    lastTotpStep = step;
    Serial.printf("New TOTP code: %s\n", currentTotpCode);
  }

  uint32_t elapsedInSlotMs = (uint32_t)((unixNow % (TOTP_PERIOD_MS / 1000ULL)) * 1000ULL) + (millis() % 1000UL);
  elapsedInSlotMs %= TOTP_PERIOD_MS;

  float progress = (float)elapsedInSlotMs / (float)TOTP_PERIOD_MS;
  uint8_t secondsLeft = (uint8_t)((TOTP_PERIOD_MS - elapsedInSlotMs + 999) / 1000);
  if (secondsLeft > 30) {
    secondsLeft = 30;
  }

  if (fabsf(progress - lastProgress) >= 0.01f) {
    drawRing(progress);
    lastProgress = progress;
  }

  if (secondsLeft != lastSecondsLeft) {
    drawSecondsLeft(secondsLeft);
    setStatusLed(secondsLeft);
    lastSecondsLeft = secondsLeft;
  }
}
