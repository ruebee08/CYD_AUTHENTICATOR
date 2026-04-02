#include "App.h"
#include "AppConfig.h"
#include <Preferences.h>
#include <WiFi.h>
#include <cctype>
#include <cstring>
#include <esp_system.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <time.h>
#include <XPT2046_Bitbang.h>

XPT2046_Bitbang touch(TOUCH_MOSI_PIN, TOUCH_MISO_PIN, TOUCH_SCK_PIN, TOUCH_CS_PIN);

namespace {

Preferences gPrefs;
Preferences gKeyPrefs;
Preferences gPinPrefs;
constexpr const char* STORAGE_NS = "authdata";
constexpr const char* STORAGE_KEY_NS = "authkeys";
constexpr const char* STORAGE_MASTER_KEY_NAME = "mkey";
constexpr const char* STORAGE_ACCOUNT_COUNT_KEY = "count";
constexpr const char* STORAGE_VAULT_COUNT_KEY = "vcount";
constexpr const char* PIN_NS = "authpin";
constexpr const char* PIN_VER_KEY = "v";
constexpr const char* PIN_SALT_KEY = "salt";
constexpr const char* PIN_HASH_KEY = "hash";
constexpr const char* PIN_FAIL_KEY = "fail";
constexpr const char* PIN_LOCK_KEY = "lock";
constexpr const char* PIN_DAILY_FAIL_KEY = "dfail";
constexpr const char* PIN_DAILY_START_KEY = "dstart";
constexpr uint8_t PIN_RECORD_VERSION = 2;
constexpr uint16_t PIN_DAILY_MAX_ATTEMPTS = 20;
constexpr uint32_t PIN_DAILY_WINDOW_SECONDS = 86400;
constexpr size_t STORAGE_MASTER_KEY_SIZE = 32;
constexpr const char* PIN_KEY_LABELS[12] = {
  "1", "2", "3",
  "4", "5", "6",
  "7", "8", "9",
  "CLR", "0", "DEL",
};
constexpr uint32_t PIN_ERROR_FLASH_MS = 1200;
constexpr int16_t VAULT_LIST_TOP = 56;
constexpr int16_t VAULT_ROW_HEIGHT = 74;
constexpr int16_t VAULT_ROW_GAP = 10;
constexpr size_t AES_BLOCK_SIZE_BYTES = 16;
constexpr size_t MAX_SECRET_SIZE = 95;
constexpr size_t MAX_CIPHER_SIZE = 96;
constexpr size_t MAX_ENCRYPTED_BLOB_SIZE = 16 + MAX_CIPHER_SIZE;

bool appendHexByte(String& out, uint8_t value) {
  static const char* kHex = "0123456789ABCDEF";
  out += kHex[(value >> 4) & 0x0F];
  out += kHex[value & 0x0F];
  return true;
}

int8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') {
    return (int8_t)(c - '0');
  }
  char up = (char)toupper((unsigned char)c);
  if (up >= 'A' && up <= 'F') {
    return (int8_t)(10 + (up - 'A'));
  }
  return -1;
}

bool parseHex(const char* hex, uint8_t* out, size_t outMax, size_t& outLen) {
  size_t hexLen = strlen(hex);
  if ((hexLen == 0) || ((hexLen % 2) != 0)) {
    return false;
  }

  outLen = hexLen / 2;
  if (outLen > outMax) {
    return false;
  }

  for (size_t i = 0; i < outLen; i++) {
    int8_t hi = hexNibble(hex[2 * i]);
    int8_t lo = hexNibble(hex[(2 * i) + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }

  return true;
}

String storageNameKey(uint8_t index) {
  return String("n") + String(index);
}

String storageSecretKey(uint8_t index) {
  return String("s") + String(index);
}

String storageVaultNameKey(uint8_t index) {
  return String("vn") + String(index);
}

String storageVaultSecretKey(uint8_t index) {
  return String("vs") + String(index);
}

}  

bool App::loadOrCreateStorageMasterKey() {
  storageMasterKeyReady = false;
  memset(storageMasterKey, 0, sizeof(storageMasterKey));

  if (!gKeyPrefs.begin(STORAGE_KEY_NS, false)) {
    Serial.println("Storage key namespace open failed.");
    return false;
  }

  size_t keyLen = gKeyPrefs.getBytesLength(STORAGE_MASTER_KEY_NAME);
  if (keyLen == STORAGE_MASTER_KEY_SIZE) {
    size_t readLen = gKeyPrefs.getBytes(STORAGE_MASTER_KEY_NAME, storageMasterKey, sizeof(storageMasterKey));
    gKeyPrefs.end();
    if (readLen != STORAGE_MASTER_KEY_SIZE) {
      Serial.println("Stored master key read failed.");
      return false;
    }
    storageMasterKeyReady = true;
    Serial.println("Loaded storage master key from flash.");
    return true;
  }

  for (size_t i = 0; i < sizeof(storageMasterKey); i++) {
    storageMasterKey[i] = (uint8_t)(esp_random() & 0xFFu);
  }

  size_t written = gKeyPrefs.putBytes(STORAGE_MASTER_KEY_NAME, storageMasterKey, sizeof(storageMasterKey));
  gKeyPrefs.end();
  if (written != STORAGE_MASTER_KEY_SIZE) {
    Serial.println("Failed to persist generated storage master key.");
    memset(storageMasterKey, 0, sizeof(storageMasterKey));
    return false;
  }

  storageMasterKeyReady = true;
  Serial.println("Generated and stored new storage master key.");
  return true;
}

bool App::derivePinHash(const char* pin, const uint8_t* salt, uint8_t outHash[32]) const {
  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mdInfo == nullptr) {
    return false;
  }

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  int rc = mbedtls_md_setup(&ctx, mdInfo, 0);
  if (rc == 0) {
    rc = mbedtls_md_starts(&ctx);
  }
  if (rc == 0) {
    rc = mbedtls_md_update(&ctx, salt, 16);
  }
  if (rc == 0) {
    rc = mbedtls_md_update(&ctx, (const unsigned char*)pin, strlen(pin));
  }
  if (rc == 0) {
    rc = mbedtls_md_finish(&ctx, outHash);
  }
  mbedtls_md_free(&ctx);
  return rc == 0;
}

bool App::loadPinAuthConfig() {
  pinAuthConfigured = false;
  pinFailedAttempts = 0;
  pinDailyFailedAttempts = 0;
  pinDailyWindowStartUnix = 0;
  pinLockoutUntilUnix = 0;
  pinLastLockoutSeconds = 0xFFFF;
  memset(pinSalt, 0, sizeof(pinSalt));
  memset(pinHash, 0, sizeof(pinHash));

  if (!gPinPrefs.begin(PIN_NS, true)) {
    Serial.println("PIN namespace open failed.");
    return false;
  }

  uint8_t version = gPinPrefs.getUChar(PIN_VER_KEY, 0);
  if (version != PIN_RECORD_VERSION) {
    gPinPrefs.end();
    pinSetupRequired = true;
    return true;
  }

  size_t saltLen = gPinPrefs.getBytesLength(PIN_SALT_KEY);
  size_t hashLen = gPinPrefs.getBytesLength(PIN_HASH_KEY);
  if (saltLen != sizeof(pinSalt) || hashLen != sizeof(pinHash)) {
    gPinPrefs.end();
    pinSetupRequired = true;
    return true;
  }

  size_t readSalt = gPinPrefs.getBytes(PIN_SALT_KEY, pinSalt, sizeof(pinSalt));
  size_t readHash = gPinPrefs.getBytes(PIN_HASH_KEY, pinHash, sizeof(pinHash));
  pinFailedAttempts = gPinPrefs.getUChar(PIN_FAIL_KEY, 0);
  pinLockoutUntilUnix = gPinPrefs.getUInt(PIN_LOCK_KEY, 0);
  pinDailyFailedAttempts = gPinPrefs.getUShort(PIN_DAILY_FAIL_KEY, 0);
  pinDailyWindowStartUnix = gPinPrefs.getUInt(PIN_DAILY_START_KEY, 0);
  gPinPrefs.end();

  if (readSalt != sizeof(pinSalt) || readHash != sizeof(pinHash)) {
    pinSetupRequired = true;
    return true;
  }

  pinAuthConfigured = true;
  pinSetupRequired = false;
  return true;
}

bool App::savePinAuthConfig() {
  if (!gPinPrefs.begin(PIN_NS, false)) {
    return false;
  }

  bool ok = true;
  if (gPinPrefs.putUChar(PIN_VER_KEY, PIN_RECORD_VERSION) == 0) {
    ok = false;
  }
  if (ok && gPinPrefs.putBytes(PIN_SALT_KEY, pinSalt, sizeof(pinSalt)) != sizeof(pinSalt)) {
    ok = false;
  }
  if (ok && gPinPrefs.putBytes(PIN_HASH_KEY, pinHash, sizeof(pinHash)) != sizeof(pinHash)) {
    ok = false;
  }
  if (ok && gPinPrefs.putUChar(PIN_FAIL_KEY, pinFailedAttempts) == 0) {
    ok = false;
  }
  if (ok && gPinPrefs.putUInt(PIN_LOCK_KEY, pinLockoutUntilUnix) == 0) {
    ok = false;
  }
  if (ok && gPinPrefs.putUShort(PIN_DAILY_FAIL_KEY, pinDailyFailedAttempts) == 0) {
    ok = false;
  }
  if (ok && gPinPrefs.putUInt(PIN_DAILY_START_KEY, pinDailyWindowStartUnix) == 0) {
    ok = false;
  }

  gPinPrefs.end();
  return ok;
}

bool App::savePinFailedAttempts() const {
  if (!gPinPrefs.begin(PIN_NS, false)) {
    return false;
  }
  bool ok = gPinPrefs.putUChar(PIN_FAIL_KEY, pinFailedAttempts) > 0;
  ok = ok && (gPinPrefs.putUInt(PIN_LOCK_KEY, pinLockoutUntilUnix) > 0);
  ok = ok && (gPinPrefs.putUShort(PIN_DAILY_FAIL_KEY, pinDailyFailedAttempts) > 0);
  ok = ok && (gPinPrefs.putUInt(PIN_DAILY_START_KEY, pinDailyWindowStartUnix) > 0);
  gPinPrefs.end();
  return ok;
}

uint32_t App::getPinBackoffSeconds(uint8_t failedAttempts) const {
  if (failedAttempts <= 3) {
    return 0;
  }
  if (failedAttempts == 4) {
    return 15;
  }
  if (failedAttempts == 5) {
    return 30;
  }
  if (failedAttempts == 6) {
    return 60;
  }
  return 300;
}

bool App::isPinDailyCapReached() const {
  uint64_t nowUnix = getUnixTimeSeconds();
  if (pinDailyWindowStartUnix == 0 || nowUnix < pinDailyWindowStartUnix) {
    return false;
  }
  if ((nowUnix - pinDailyWindowStartUnix) >= PIN_DAILY_WINDOW_SECONDS) {
    return false;
  }
  return pinDailyFailedAttempts >= PIN_DAILY_MAX_ATTEMPTS;
}

bool App::isSixDigitPin(const String& value) const {
  if (value.length() != 6) {
    return false;
  }
  for (size_t i = 0; i < 6; i++) {
    char c = value[(int)i];
    if (c < '0' || c > '9') {
      return false;
    }
  }
  return true;
}

int8_t App::hitVaultItemIndex(int16_t x, int16_t y) const {
  if (y < VAULT_VIEW_TOP || y > getVaultViewportBottom()) {
    return -1;
  }

  int16_t rowX = 14;
  int16_t rowW = screenW - 28;

  for (uint8_t i = 0; i < vaultItemCount; i++) {
    int16_t rowY = VAULT_LIST_TOP + (i * (VAULT_ROW_HEIGHT + VAULT_ROW_GAP)) - vaultScrollY;
    if (x >= rowX && x <= (rowX + rowW) && y >= rowY && y <= (rowY + VAULT_ROW_HEIGHT)) {
      return (int8_t)i;
    }
  }

  return -1;
}

void App::beginPinSetupSerialFlow() {
  pinSetupState = PinSetupState::WaitPin;
  pendingPinSetupValue = "";
  Serial.println("PIN setup required (first boot).");
  Serial.println("Enter new 6-digit PIN:");
  Serial.print("> ");
}

void App::handlePinSetupSerialLine(const String& line) {
  String value = line;
  value.trim();

  if (pinSetupState == PinSetupState::WaitPin) {
    if (!isSixDigitPin(value)) {
      Serial.println("PIN must be exactly 6 digits (0-9). Try again:");
      Serial.print("> ");
      return;
    }
    pendingPinSetupValue = value;
    pinSetupState = PinSetupState::WaitConfirm;
    Serial.println("Confirm 6-digit PIN:");
    Serial.print("> ");
    return;
  }

  if (pinSetupState == PinSetupState::WaitConfirm) {
    if (value != pendingPinSetupValue) {
      pendingPinSetupValue = "";
      pinSetupState = PinSetupState::WaitPin;
      Serial.println("PINs do not match. Enter new 6-digit PIN:");
      Serial.print("> ");
      return;
    }

    for (size_t i = 0; i < sizeof(pinSalt); i++) {
      pinSalt[i] = (uint8_t)(esp_random() & 0xFFu);
    }
    pinFailedAttempts = 0;

    if (!derivePinHash(value.c_str(), pinSalt, pinHash)) {
      Serial.println("PIN hash generation failed. Retry:");
      pendingPinSetupValue = "";
      pinSetupState = PinSetupState::WaitPin;
      Serial.print("> ");
      return;
    }

    if (!savePinAuthConfig()) {
      Serial.println("Failed to save PIN config. Retry setup:");
      pendingPinSetupValue = "";
      pinSetupState = PinSetupState::WaitPin;
      Serial.print("> ");
      return;
    }

    memset(pinHash, 0, sizeof(pinHash));
    if (!loadPinAuthConfig()) {
      Serial.println("Failed loading PIN config after save.");
      return;
    }

    pendingPinSetupValue = "";
    pinSetupState = PinSetupState::Idle;
    pinSetupRequired = false;
    pinUnlocked = false;
    enteredPinLen = 0;
    enteredPin[0] = '\0';
    pinShowError = false;
    pinLockoutUntilUnix = 0;
    pinDailyFailedAttempts = 0;
    pinDailyWindowStartUnix = (uint32_t)getUnixTimeSeconds();
    pinLastLockoutSeconds = 0xFFFF;
    Serial.println("PIN setup complete.");
    drawPinScreen();
  }
}

bool App::verifyEnteredPinAgainstStoredHash() {
  if (!pinAuthConfigured) {
    return false;
  }

  uint8_t computed[32] = {0};
  if (!derivePinHash(enteredPin, pinSalt, computed)) {
    return false;
  }

  uint8_t diff = 0;
  for (size_t i = 0; i < sizeof(computed); i++) {
    diff |= (uint8_t)(computed[i] ^ pinHash[i]);
  }
  memset(computed, 0, sizeof(computed));
  return diff == 0;
}

bool App::validateEnteredPin() {
  if (enteredPinLen != 6) {
    return false;
  }
  return verifyEnteredPinAgainstStoredHash();
}

void App::handlePinTap(int16_t x, int16_t y) {
  x = (screenW - 1) - x;

  if (pinSetupRequired) {
    return;
  }

  uint32_t nowUnix = (uint32_t)getUnixTimeSeconds();
  if (pinDailyWindowStartUnix == 0 || nowUnix < pinDailyWindowStartUnix ||
      (nowUnix - pinDailyWindowStartUnix) >= PIN_DAILY_WINDOW_SECONDS) {
    pinDailyWindowStartUnix = nowUnix;
    pinDailyFailedAttempts = 0;
    savePinFailedAttempts();
  }

  if (isPinDailyCapReached()) {
    pinShowError = true;
    pinErrorStartedMs = millis();
    drawPinEntry();
    return;
  }

  if (pinLockoutUntilUnix > nowUnix) {
    return;
  }

  for (uint8_t i = 0; i < 12; i++) {
    if (!hitButton(pinButtons[i], x, y)) {
      continue;
    }

    if (i == 9) {
      enteredPinLen = 0;
      enteredPin[0] = '\0';
      pinShowError = false;
      drawPinEntry();
      return;
    }

    if (i == 11) {
      if (enteredPinLen > 0) {
        enteredPinLen--;
        enteredPin[enteredPinLen] = '\0';
      }
      pinShowError = false;
      drawPinEntry();
      return;
    }

    if (enteredPinLen >= 6) {
      return;
    }

    char digit = PIN_KEY_LABELS[i][0];
    enteredPin[enteredPinLen++] = digit;
    enteredPin[enteredPinLen] = '\0';
    pinShowError = false;
    drawPinEntry();

    if (enteredPinLen == 6) {
      if (validateEnteredPin()) {
        pinFailedAttempts = 0;
        pinLockoutUntilUnix = 0;
        pinLastLockoutSeconds = 0xFFFF;
        savePinFailedAttempts();
        pinUnlocked = true;
        switchScreen(Screen::Menu);
      } else {
        if (pinFailedAttempts < 255) {
          pinFailedAttempts++;
        }

        if (pinDailyFailedAttempts < 65535) {
          pinDailyFailedAttempts++;
        }

        uint32_t lockSeconds = getPinBackoffSeconds(pinFailedAttempts);
        pinLockoutUntilUnix = (lockSeconds > 0) ? (nowUnix + lockSeconds) : 0;
        pinLastLockoutSeconds = 0xFFFF;
        savePinFailedAttempts();

        enteredPinLen = 0;
        enteredPin[0] = '\0';
        pinShowError = true;
        pinErrorStartedMs = millis();
        drawPinEntry();
      }
    }
    return;
  }
}

bool App::syncTimeWithNtp() {
  if (strlen(WIFI_SSID) == 0 || strcmp(WIFI_SSID, "YOUR_WIFI_SSID") == 0) {
    Serial.println("NTP skipped: set WIFI_SSID/WIFI_PASSWORD in AppConfig.h");
    ntpSynced = false;
    lastNtpRetryMs = millis();
    return false;
  }

  WiFi.mode(WIFI_STA);
  uint32_t start = 0;

  if (WiFi.status() != WL_CONNECTED) {
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.printf("Connecting WiFi SSID: %s\n", WIFI_SSID);

    start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < WIFI_CONNECT_TIMEOUT_MS) {
      delay(250);
      Serial.print('.');
    }
    Serial.println();
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi connect failed; using fallback boot time.");
    ntpSynced = false;
    lastNtpRetryMs = millis();
    return false;
  }

  configTime(0, 0, NTP_SERVER_PRIMARY, NTP_SERVER_SECONDARY);
  Serial.printf("Syncing NTP with %s / %s\n", NTP_SERVER_PRIMARY, NTP_SERVER_SECONDARY);

  time_t now = time(nullptr);
  start = millis();
  while (now < 1700000000 && (millis() - start) < NTP_SYNC_TIMEOUT_MS) {
    delay(200);
    now = time(nullptr);
  }

  if (now < 1700000000) {
    Serial.println("NTP sync timeout; using fallback boot time.");
    ntpSynced = false;
    lastNtpRetryMs = millis();
    return false;
  }

  // Sanity check: NTP time must be after March 2025 (1743638400).
  // If it's too old, the NTP server is giving wrong time; reject and retry.
  constexpr time_t MIN_VALID_UNIX = 1743638400;  // 2025-03-01
  if (now < MIN_VALID_UNIX) {
    Serial.printf("NTP time is too old (%llu), server may be incorrect. Retrying...\n", (unsigned long long)now);
    ntpSynced = false;
    lastNtpRetryMs = millis();
    return false;
  }

  ntpSynced = true;
  lastNtpRetryMs = millis();
  Serial.printf("NTP synced. Unix time: %llu\n", (unsigned long long)now);
  return true;
}

void App::printTimeStatus() const {
  uint64_t unixNow = getUnixTimeSeconds();
  Serial.printf("Time source: %s\n", ntpSynced ? "NTP" : "Fallback uptime");
  Serial.printf("Unix now: %llu\n", (unsigned long long)unixNow);
}

void App::begin() {
  Serial.begin(115200);

  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BLUE_LED_PIN, OUTPUT);
  setStatusLed(30);

  pinMode(TFT_BACKLIGHT_PIN, OUTPUT);
  digitalWrite(TFT_BACKLIGHT_PIN, HIGH);

  tft.init();
  tft.setRotation(3);

  touch.begin();

  if (!loadOrCreateStorageMasterKey()) {
    Serial.println("Storage encryption key unavailable; account storage disabled.");
  }

  if (!loadPinAuthConfig()) {
    Serial.println("PIN auth config unavailable.");
    pinSetupRequired = true;
  }

  syncTimeWithNtp();

  loadAccountsFromStorage();
  loadVaultFromStorage();
  updateLayout();
  updateButtons();
  enteredPinLen = 0;
  enteredPin[0] = '\0';
  pinShowError = false;
  lastUserInteractionMs = millis();

  if (pinSetupRequired) {
    beginPinSetupSerialFlow();
  }

  Serial.printf("TFT size: %dx%d\n", screenW, screenH);
  printSerialHelp();
  switchScreen(Screen::Pin);
}

void App::update() {
  if ((millis() - lastNtpRetryMs) >= NTP_RESYNC_INTERVAL_MS) {
    syncTimeWithNtp();
  }

  handleSerial();
  handleTouch();

  if (currentScreen == Screen::TwoFA) {
    updateTwoFAScreen();
  }

  if (pinUnlocked && currentScreen != Screen::Pin &&
      (millis() - lastUserInteractionMs) >= INACTIVITY_LOCK_TIMEOUT_MS) {
    pinUnlocked = false;
    enteredPinLen = 0;
    enteredPin[0] = '\0';
    pinShowError = false;
    switchScreen(Screen::Pin);
  }

  if (currentScreen == Screen::Pin && pinShowError && (millis() - pinErrorStartedMs) >= PIN_ERROR_FLASH_MS) {
    pinShowError = false;
    drawPinEntry();
  }

  if (currentScreen == Screen::Pin && !pinSetupRequired) {
    uint32_t nowUnix = (uint32_t)getUnixTimeSeconds();
    uint16_t remaining = 0;
    if (pinLockoutUntilUnix > nowUnix) {
      remaining = (uint16_t)(pinLockoutUntilUnix - nowUnix);
    }
    if (remaining != pinLastLockoutSeconds) {
      pinLastLockoutSeconds = remaining;
      drawPinEntry();
    }
  }

  delay(20);
}

void App::loadAccountsFromStorage() {
  accountCount = 0;
  selectedAccountIndex = 0;

  for (uint8_t i = 0; i < MAX_ACCOUNTS; i++) {
    accounts[i].name[0] = '\0';
    accounts[i].secret[0] = '\0';
  }

  if (!gPrefs.begin(STORAGE_NS, true)) {
    Serial.println("Storage open failed; starting with empty account list.");
    return;
  }

  uint8_t storedCount = gPrefs.getUChar(STORAGE_ACCOUNT_COUNT_KEY, 0);
  if (storedCount > MAX_ACCOUNTS) {
    storedCount = MAX_ACCOUNTS;
  }

  uint8_t loaded = 0;
  for (uint8_t i = 0; i < storedCount; i++) {
    String name = gPrefs.getString(storageNameKey(i).c_str(), "");
    String encryptedSecret = gPrefs.getString(storageSecretKey(i).c_str(), "");
    name.trim();
    encryptedSecret.trim();
    if (name.length() == 0 || encryptedSecret.length() == 0) {
      continue;
    }

    char decrypted[65] = {0};
    if (!decryptSecretFromStorage(encryptedSecret.c_str(), decrypted, sizeof(decrypted))) {
      Serial.printf("Skipping corrupted account at slot %u\n", i);
      continue;
    }

    strncpy(accounts[loaded].name, name.c_str(), sizeof(accounts[loaded].name) - 1);
    accounts[loaded].name[sizeof(accounts[loaded].name) - 1] = '\0';
    strncpy(accounts[loaded].secret, decrypted, sizeof(accounts[loaded].secret) - 1);
    accounts[loaded].secret[sizeof(accounts[loaded].secret) - 1] = '\0';
    loaded++;
  }

  gPrefs.end();
  accountCount = loaded;
  Serial.printf("Loaded %u account(s) from flash.\n", accountCount);
}

void App::loadVaultFromStorage() {
  vaultItemCount = 0;

  for (uint8_t i = 0; i < MAX_VAULT_ITEMS; i++) {
    vaultItems[i].name[0] = '\0';
    vaultItems[i].secret[0] = '\0';
    vaultItems[i].revealSecret = false;
  }

  if (!gPrefs.begin(STORAGE_NS, true)) {
    Serial.println("Vault storage open failed; starting with empty vault.");
    return;
  }

  uint8_t storedCount = gPrefs.getUChar(STORAGE_VAULT_COUNT_KEY, 0);
  if (storedCount > MAX_VAULT_ITEMS) {
    storedCount = MAX_VAULT_ITEMS;
  }

  uint8_t loaded = 0;
  for (uint8_t i = 0; i < storedCount; i++) {
    String name = gPrefs.getString(storageVaultNameKey(i).c_str(), "");
    String encryptedSecret = gPrefs.getString(storageVaultSecretKey(i).c_str(), "");
    name.trim();
    encryptedSecret.trim();
    if (name.length() == 0 || encryptedSecret.length() == 0) {
      continue;
    }

    char decrypted[96] = {0};
    if (!decryptSecretFromStorage(encryptedSecret.c_str(), decrypted, sizeof(decrypted))) {
      Serial.printf("Skipping corrupted vault item at slot %u\n", i);
      continue;
    }

    strncpy(vaultItems[loaded].name, name.c_str(), sizeof(vaultItems[loaded].name) - 1);
    vaultItems[loaded].name[sizeof(vaultItems[loaded].name) - 1] = '\0';
    strncpy(vaultItems[loaded].secret, decrypted, sizeof(vaultItems[loaded].secret) - 1);
    vaultItems[loaded].secret[sizeof(vaultItems[loaded].secret) - 1] = '\0';
    vaultItems[loaded].revealSecret = false;
    loaded++;
  }

  gPrefs.end();
  vaultItemCount = loaded;
  Serial.printf("Loaded %u vault item(s) from flash.\n", vaultItemCount);
}

bool App::saveAccountsToStorage() const {
  if (!gPrefs.begin(STORAGE_NS, false)) {
    Serial.println("Storage open for write failed.");
    return false;
  }

  bool ok = true;
  uint8_t previousCount = gPrefs.getUChar(STORAGE_ACCOUNT_COUNT_KEY, 0);

  if (gPrefs.putUChar(STORAGE_ACCOUNT_COUNT_KEY, accountCount) == 0) {
    ok = false;
  }

  for (uint8_t i = 0; i < accountCount; i++) {
    String encryptedSecret;
    if (!encryptSecretForStorage(accounts[i].secret, encryptedSecret)) {
      gPrefs.end();
      Serial.printf("Encryption failed for account slot %u\n", i);
      return false;
    }

    if (gPrefs.putString(storageNameKey(i).c_str(), accounts[i].name) == 0) {
      gPrefs.end();
      Serial.printf("Failed writing account name for slot %u\n", i);
      return false;
    }

    if (gPrefs.putString(storageSecretKey(i).c_str(), encryptedSecret) == 0) {
      gPrefs.end();
      Serial.printf("Failed writing encrypted secret for slot %u\n", i);
      return false;
    }
  }

  if (ok) {
    for (uint8_t i = accountCount; i < previousCount; i++) {
      gPrefs.remove(storageNameKey(i).c_str());
      gPrefs.remove(storageSecretKey(i).c_str());
    }
  }

  gPrefs.end();
  if (!ok) {
    Serial.println("Account storage cleanup failed.");
  }
  return ok;
}

bool App::saveVaultToStorage() const {
  if (!gPrefs.begin(STORAGE_NS, false)) {
    Serial.println("Vault storage open for write failed.");
    return false;
  }

  bool ok = true;
  uint8_t previousCount = gPrefs.getUChar(STORAGE_VAULT_COUNT_KEY, 0);

  if (gPrefs.putUChar(STORAGE_VAULT_COUNT_KEY, vaultItemCount) == 0) {
    ok = false;
  }

  for (uint8_t i = 0; i < vaultItemCount; i++) {
    String encryptedSecret;
    if (!encryptSecretForStorage(vaultItems[i].secret, encryptedSecret)) {
      gPrefs.end();
      Serial.printf("Vault encryption failed for slot %u\n", i);
      return false;
    }

    if (gPrefs.putString(storageVaultNameKey(i).c_str(), vaultItems[i].name) == 0) {
      gPrefs.end();
      Serial.printf("Failed writing vault name for slot %u\n", i);
      return false;
    }

    if (gPrefs.putString(storageVaultSecretKey(i).c_str(), encryptedSecret) == 0) {
      gPrefs.end();
      Serial.printf("Failed writing encrypted vault secret for slot %u\n", i);
      return false;
    }
  }

  if (ok) {
    for (uint8_t i = vaultItemCount; i < previousCount; i++) {
      gPrefs.remove(storageVaultNameKey(i).c_str());
      gPrefs.remove(storageVaultSecretKey(i).c_str());
    }
  }

  gPrefs.end();
  if (!ok) {
    Serial.println("Vault storage cleanup failed.");
  }
  return ok;
}

bool App::encryptSecretForStorage(const char* plainSecret, String& outHex) const {
  if (!storageMasterKeyReady) {
    return false;
  }

  size_t plainLen = strnlen(plainSecret, MAX_SECRET_SIZE);
  if (plainLen == 0 || plainLen > MAX_SECRET_SIZE) {
    return false;
  }

  size_t paddedLen = ((plainLen / AES_BLOCK_SIZE_BYTES) + 1) * AES_BLOCK_SIZE_BYTES;
  if (paddedLen > MAX_CIPHER_SIZE) {
    return false;
  }

  uint8_t iv[16];
  for (uint8_t i = 0; i < sizeof(iv); i++) {
    iv[i] = (uint8_t)(esp_random() & 0xFFu);
  }

  uint8_t ivWork[16];
  memcpy(ivWork, iv, sizeof(iv));

  uint8_t cipher[MAX_CIPHER_SIZE];
  memcpy(cipher, plainSecret, plainLen);
  uint8_t padLen = (uint8_t)(paddedLen - plainLen);
  for (size_t i = plainLen; i < paddedLen; i++) {
    cipher[i] = padLen;
  }

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int rc = mbedtls_aes_setkey_enc(&aes, storageMasterKey, 256);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, ivWork, cipher, cipher);
  }
  mbedtls_aes_free(&aes);
  if (rc != 0) {
    return false;
  }

  outHex = "";
  outHex.reserve((16 + paddedLen) * 2);
  for (uint8_t i = 0; i < sizeof(iv); i++) {
    appendHexByte(outHex, iv[i]);
  }
  for (size_t i = 0; i < paddedLen; i++) {
    appendHexByte(outHex, cipher[i]);
  }
  return true;
}

bool App::decryptSecretFromStorage(const char* encryptedHex, char* outSecret, size_t outSecretSize) const {
  if (!storageMasterKeyReady) {
    return false;
  }

  uint8_t blob[MAX_ENCRYPTED_BLOB_SIZE];
  size_t blobLen = 0;
  if (!parseHex(encryptedHex, blob, sizeof(blob), blobLen)) {
    return false;
  }

  if (blobLen <= 16 || ((blobLen - 16) % AES_BLOCK_SIZE_BYTES) != 0) {
    return false;
  }

  uint8_t iv[16];
  memcpy(iv, blob, sizeof(iv));

  size_t cipherLen = blobLen - 16;
  uint8_t plain[MAX_CIPHER_SIZE];
  memcpy(plain, blob + 16, cipherLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int rc = mbedtls_aes_setkey_dec(&aes, storageMasterKey, 256);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipherLen, iv, plain, plain);
  }
  mbedtls_aes_free(&aes);
  if (rc != 0 || cipherLen == 0) {
    return false;
  }

  uint8_t padLen = plain[cipherLen - 1];
  if (padLen == 0 || padLen > AES_BLOCK_SIZE_BYTES || padLen > cipherLen) {
    return false;
  }
  for (size_t i = 0; i < padLen; i++) {
    if (plain[cipherLen - 1 - i] != padLen) {
      return false;
    }
  }

  size_t plainLen = cipherLen - padLen;
  if (plainLen + 1 > outSecretSize || plainLen > MAX_SECRET_SIZE) {
    return false;
  }

  memcpy(outSecret, plain, plainLen);
  outSecret[plainLen] = '\0';
  return true;
}

bool App::isValidBase32Secret(const String& secret) const {
  size_t usefulChars = 0;
  for (size_t i = 0; i < (size_t)secret.length(); i++) {
    char c = secret[(int)i];
    if (c == ' ' || c == '-' || c == '=') {
      continue;
    }

    char up = (char)toupper((unsigned char)c);
    bool isAlpha = (up >= 'A' && up <= 'Z');
    bool isDigit = (up >= '2' && up <= '7');
    if (!isAlpha && !isDigit) {
      return false;
    }
    usefulChars++;
  }

  return usefulChars >= 8 && usefulChars <= MAX_SECRET_SIZE;
}

void App::beginSerialAddAccountFlow() {
  if (serialEnrollState != SerialEnrollState::Idle) {
    Serial.println("Add account flow is already active.");
    if (serialEnrollState == SerialEnrollState::WaitName) {
      Serial.println("Enter account name or type cancel.");
    } else {
      Serial.println("Enter Base32 secret or type cancel.");
    }
    Serial.print("> ");
    return;
  }

  if (accountCount >= MAX_ACCOUNTS) {
    Serial.println("Account list is full. Delete an account first.");
    return;
  }

  serialEnrollState = SerialEnrollState::WaitName;
  pendingAccountName = "";
  Serial.println("Add account flow started.");
  Serial.println("Enter account name and press Enter:");
  Serial.print("> ");
}

void App::beginSerialAddVaultFlow() {
  if (serialEnrollState != SerialEnrollState::Idle) {
    Serial.println("Another serial input flow is already active.");
    Serial.print("> ");
    return;
  }

  if (vaultItemCount >= MAX_VAULT_ITEMS) {
    Serial.println("Vault is full. Delete an item first.");
    return;
  }

  serialEnrollState = SerialEnrollState::WaitVaultName;
  pendingVaultName = "";
  Serial.println("Add vault secret flow started.");
  Serial.println("Enter vault item name and press Enter:");
  Serial.print("> ");
}

void App::beginSerialUpdateVaultFlow(uint8_t index) {
  if (serialEnrollState != SerialEnrollState::Idle) {
    Serial.println("Another serial input flow is already active.");
    Serial.print("> ");
    return;
  }

  if (index >= vaultItemCount) {
    Serial.println("Invalid vault index. Use: vlist");
    return;
  }

  pendingVaultIndex = (int8_t)index;
  pendingVaultName = "";
  serialEnrollState = SerialEnrollState::WaitVaultUpdateName;

  Serial.printf("Update vault item [%u] %s\n", (unsigned int)index, vaultItems[index].name);
  Serial.println("Enter new vault item name, or . to keep current:");
  Serial.print("> ");
}

void App::handleSerial() {
  while (Serial.available() > 0) {
    char ch = (char)Serial.read();
    if (ch == '\r') {
      continue;
    }

    if (ch == '\b' || ch == 127) {
      if (serialLineBuffer.length() > 0) {
        serialLineBuffer.remove(serialLineBuffer.length() - 1);
        Serial.print("\b \b");
      }
      continue;
    }

    if (ch == '\n') {
      Serial.println();
      serialLineBuffer.trim();
      if (serialLineBuffer.length() > 0) {
        handleSerialLine(serialLineBuffer);
      }
      serialLineBuffer = "";
      continue;
    }

    if (ch >= 32 && ch <= 126 && serialLineBuffer.length() < 160) {
      serialLineBuffer += ch;
      bool maskInput = (serialEnrollState == SerialEnrollState::WaitSecret) ||
               (serialEnrollState == SerialEnrollState::WaitVaultSecret) ||
               (serialEnrollState == SerialEnrollState::WaitVaultUpdateSecret) ||
               (pinSetupRequired && pinSetupState != PinSetupState::Idle);
      if (maskInput) {
        Serial.print('*');
      } else {
        Serial.print(ch);
      }
    }
  }
}

void App::handleSerialLine(const String& line) {
  if (pinSetupRequired && pinSetupState != PinSetupState::Idle) {
    handlePinSetupSerialLine(line);
    return;
  }

  String value = line;
  value.trim();

  if (!pinUnlocked) {
    Serial.println("Device locked. Enter PIN on touchscreen.");
    return;
  }

  if (value.equalsIgnoreCase("cancel")) {
    if (serialEnrollState != SerialEnrollState::Idle) {
      serialEnrollState = SerialEnrollState::Idle;
      pendingAccountName = "";
      pendingVaultName = "";
      pendingVaultIndex = -1;
      Serial.println("Active add flow cancelled.");
    } else {
      Serial.println("No active add flow.");
    }
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitName) {
    if (value.length() == 0) {
      Serial.println("Name cannot be empty. Enter account name:");
      return;
    }

    if (value.length() >= (int)sizeof(accounts[0].name)) {
      Serial.printf("Name too long. Max %u chars.\n", (unsigned int)(sizeof(accounts[0].name) - 1));
      Serial.println("Enter account name:");
      return;
    }

    pendingAccountName = value;
    serialEnrollState = SerialEnrollState::WaitSecret;
    Serial.println("Enter Base32 secret and press Enter:");
    Serial.print("> ");
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitSecret) {
    String secret = value;
    secret.trim();
    if (!isValidBase32Secret(secret)) {
      Serial.println("Invalid Base32 secret. Allowed: A-Z, 2-7, spaces, -, =");
      Serial.println("Enter Base32 secret:");
      Serial.print("> ");
      return;
    }

    if (secret.length() >= (int)sizeof(accounts[0].secret)) {
      Serial.printf("Secret too long. Max %u chars.\n", (unsigned int)(sizeof(accounts[0].secret) - 1));
      Serial.println("Enter Base32 secret:");
      Serial.print("> ");
      return;
    }

    uint8_t newIndex = accountCount;
    strncpy(accounts[newIndex].name, pendingAccountName.c_str(), sizeof(accounts[newIndex].name) - 1);
    accounts[newIndex].name[sizeof(accounts[newIndex].name) - 1] = '\0';
    strncpy(accounts[newIndex].secret, secret.c_str(), sizeof(accounts[newIndex].secret) - 1);
    accounts[newIndex].secret[sizeof(accounts[newIndex].secret) - 1] = '\0';
    accountCount++;

    if (!saveAccountsToStorage()) {
      accountCount--;
      accounts[newIndex].name[0] = '\0';
      accounts[newIndex].secret[0] = '\0';
      Serial.println("Failed saving account to flash.");
    } else {
      selectedAccountIndex = newIndex;
      Serial.printf("Account added and stored encrypted: %s\n", accounts[newIndex].name);
      if (currentScreen == Screen::Accounts) {
        drawAccountsScreen();
      }
    }

    pendingAccountName = "";
    serialEnrollState = SerialEnrollState::Idle;
    Serial.println("Type help for commands.");
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitVaultName) {
    if (value.length() == 0) {
      Serial.println("Vault name cannot be empty. Enter vault name:");
      return;
    }

    if (value.length() >= (int)sizeof(vaultItems[0].name)) {
      Serial.printf("Vault name too long. Max %u chars.\n", (unsigned int)(sizeof(vaultItems[0].name) - 1));
      Serial.println("Enter vault name:");
      return;
    }

    pendingVaultName = value;
    serialEnrollState = SerialEnrollState::WaitVaultSecret;
    Serial.println("Enter vault secret and press Enter:");
    Serial.print("> ");
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitVaultSecret) {
    String secret = value;
    secret.trim();
    if (secret.length() == 0) {
      Serial.println("Vault secret cannot be empty. Enter vault secret:");
      Serial.print("> ");
      return;
    }

    if (secret.length() >= (int)sizeof(vaultItems[0].secret)) {
      Serial.printf("Vault secret too long. Max %u chars.\n", (unsigned int)(sizeof(vaultItems[0].secret) - 1));
      Serial.println("Enter vault secret:");
      Serial.print("> ");
      return;
    }

    uint8_t newIndex = vaultItemCount;
    strncpy(vaultItems[newIndex].name, pendingVaultName.c_str(), sizeof(vaultItems[newIndex].name) - 1);
    vaultItems[newIndex].name[sizeof(vaultItems[newIndex].name) - 1] = '\0';
    strncpy(vaultItems[newIndex].secret, secret.c_str(), sizeof(vaultItems[newIndex].secret) - 1);
    vaultItems[newIndex].secret[sizeof(vaultItems[newIndex].secret) - 1] = '\0';
    vaultItems[newIndex].revealSecret = false;
    vaultItemCount++;

    if (!saveVaultToStorage()) {
      vaultItemCount--;
      vaultItems[newIndex].name[0] = '\0';
      vaultItems[newIndex].secret[0] = '\0';
      vaultItems[newIndex].revealSecret = false;
      Serial.println("Failed saving vault item to flash.");
      pendingVaultName = "";
      serialEnrollState = SerialEnrollState::Idle;
      return;
    }

    pendingVaultName = "";
    serialEnrollState = SerialEnrollState::Idle;
    Serial.printf("Vault item added: %s\n", vaultItems[newIndex].name);
    if (currentScreen == Screen::Vault) {
      drawVaultScreen();
    }
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitVaultUpdateName) {
    if (pendingVaultIndex < 0 || pendingVaultIndex >= (int8_t)vaultItemCount) {
      Serial.println("Invalid pending vault update state. Flow cancelled.");
      serialEnrollState = SerialEnrollState::Idle;
      pendingVaultName = "";
      pendingVaultIndex = -1;
      return;
    }

    if (value == ".") {
      pendingVaultName = String(vaultItems[(uint8_t)pendingVaultIndex].name);
    } else {
      if (value.length() == 0) {
        Serial.println("Vault name cannot be empty. Enter name or .:");
        Serial.print("> ");
        return;
      }

      if (value.length() >= (int)sizeof(vaultItems[0].name)) {
        Serial.printf("Vault name too long. Max %u chars.\n", (unsigned int)(sizeof(vaultItems[0].name) - 1));
        Serial.println("Enter name or . to keep current:");
        Serial.print("> ");
        return;
      }

      pendingVaultName = value;
    }

    serialEnrollState = SerialEnrollState::WaitVaultUpdateSecret;
    Serial.println("Enter new vault secret, or . to keep current:");
    Serial.print("> ");
    return;
  }

  if (serialEnrollState == SerialEnrollState::WaitVaultUpdateSecret) {
    if (pendingVaultIndex < 0 || pendingVaultIndex >= (int8_t)vaultItemCount) {
      Serial.println("Invalid pending vault update state. Flow cancelled.");
      serialEnrollState = SerialEnrollState::Idle;
      pendingVaultName = "";
      pendingVaultIndex = -1;
      return;
    }

    String secret = value;
    secret.trim();
    bool keepSecret = (secret == ".");

    if (!keepSecret) {
      if (secret.length() == 0) {
        Serial.println("Vault secret cannot be empty. Enter secret or .:");
        Serial.print("> ");
        return;
      }

      if (secret.length() >= (int)sizeof(vaultItems[0].secret)) {
        Serial.printf("Vault secret too long. Max %u chars.\n", (unsigned int)(sizeof(vaultItems[0].secret) - 1));
        Serial.println("Enter secret or . to keep current:");
        Serial.print("> ");
        return;
      }
    }

    uint8_t idx = (uint8_t)pendingVaultIndex;
    VaultItem oldItem = vaultItems[idx];
    strncpy(vaultItems[idx].name, pendingVaultName.c_str(), sizeof(vaultItems[idx].name) - 1);
    vaultItems[idx].name[sizeof(vaultItems[idx].name) - 1] = '\0';
    if (!keepSecret) {
      strncpy(vaultItems[idx].secret, secret.c_str(), sizeof(vaultItems[idx].secret) - 1);
      vaultItems[idx].secret[sizeof(vaultItems[idx].secret) - 1] = '\0';
    }
    vaultItems[idx].revealSecret = false;

    if (!saveVaultToStorage()) {
      vaultItems[idx] = oldItem;
      Serial.println("Failed persisting vault update.");
      serialEnrollState = SerialEnrollState::Idle;
      pendingVaultName = "";
      pendingVaultIndex = -1;
      return;
    }

    Serial.printf("Vault item updated: [%u] %s\n", (unsigned int)idx, vaultItems[idx].name);

    serialEnrollState = SerialEnrollState::Idle;
    pendingVaultName = "";
    pendingVaultIndex = -1;
    if (currentScreen == Screen::Vault) {
      drawVaultScreen();
    }
    return;
  }

  if (value.equalsIgnoreCase("help")) {
    printSerialHelp();
    return;
  }

  if (value.equalsIgnoreCase("time")) {
    printTimeStatus();
    return;
  }

  if (value.equalsIgnoreCase("ntp")) {
    bool ok = syncTimeWithNtp();
    Serial.println(ok ? "NTP sync successful." : "NTP sync failed.");
    printTimeStatus();
    return;
  }

  if (value.equalsIgnoreCase("add")) {
    beginSerialAddAccountFlow();
    return;
  }

  if (value.equalsIgnoreCase("vadd")) {
    beginSerialAddVaultFlow();
    return;
  }

  if (value.equalsIgnoreCase("vlist")) {
    Serial.printf("Vault items: %u\n", vaultItemCount);
    for (uint8_t i = 0; i < vaultItemCount; i++) {
      Serial.printf("  [%u] %s\n", i, vaultItems[i].name);
    }
    return;
  }

  if (value.startsWith("vupd ")) {
    String idxPart = value.substring(5);
    idxPart.trim();
    int idx = idxPart.toInt();
    if (idx < 0 || idx >= vaultItemCount) {
      Serial.println("Invalid vault index. Use: vlist");
      return;
    }
    beginSerialUpdateVaultFlow((uint8_t)idx);
    return;
  }

  if (value.startsWith("vdel ")) {
    String idxPart = value.substring(5);
    idxPart.trim();
    int idx = idxPart.toInt();
    if (idx < 0 || idx >= vaultItemCount) {
      Serial.println("Invalid vault index. Use: vlist");
      return;
    }

    for (int i = idx; i < (int)vaultItemCount - 1; i++) {
      vaultItems[i] = vaultItems[i + 1];
    }
    vaultItemCount--;
    vaultItems[vaultItemCount].name[0] = '\0';
    vaultItems[vaultItemCount].secret[0] = '\0';
    vaultItems[vaultItemCount].revealSecret = false;

    if (!saveVaultToStorage()) {
      Serial.println("Failed deleting vault item from flash.");
      loadVaultFromStorage();
      if (currentScreen == Screen::Vault) {
        drawVaultScreen();
      }
      return;
    }

    vaultScrollY = constrain(vaultScrollY, 0, getVaultMaxScroll());
    Serial.println("Vault item deleted.");
    if (currentScreen == Screen::Vault) {
      drawVaultScreen();
    }
    return;
  }

  if (value.equalsIgnoreCase("list")) {
    Serial.printf("Accounts: %u\n", accountCount);
    for (uint8_t i = 0; i < accountCount; i++) {
      Serial.printf("  [%u] %s\n", i, accounts[i].name);
    }
    return;
  }

  if (value.startsWith("otp")) {
    int idx = (int)selectedAccountIndex;
    uint64_t unixNow = getUnixTimeSeconds();

    String args = value.substring(3);
    args.trim();
    if (args.length() > 0) {
      int spacePos = args.indexOf(' ');
      if (spacePos < 0) {
        idx = args.toInt();
      } else {
        String idxPart = args.substring(0, spacePos);
        String unixPart = args.substring(spacePos + 1);
        idxPart.trim();
        unixPart.trim();
        idx = idxPart.toInt();
        if (unixPart.length() > 0) {
          unixNow = strtoull(unixPart.c_str(), nullptr, 10);
        }
      }
    }

    if (idx < 0 || idx >= accountCount) {
      Serial.println("Invalid account index. Use: list");
      return;
    }

    char code[7] = "------";
    bool ok = generateTotpCode((uint8_t)idx, unixNow, code);
    uint64_t step = unixNow / (TOTP_PERIOD_MS / 1000ULL);

    Serial.println("OTP debug:");
    Serial.printf("  account: [%d] %s\n", idx, accounts[idx].name);
    Serial.printf("  unix: %llu\n", (unsigned long long)unixNow);
    Serial.printf("  step: %llu\n", (unsigned long long)step);
    Serial.println("  profile: TOTP SHA1 digits=6 period=30");
    Serial.printf("  code: %s\n", ok ? code : "ERR---");
    return;
  }

  if (value.startsWith("del ")) {
    String idxPart = value.substring(4);
    idxPart.trim();
    int idx = idxPart.toInt();
    if (idx < 0 || idx >= accountCount) {
      Serial.println("Invalid index. Use: list");
      return;
    }

    for (int i = idx; i < (int)accountCount - 1; i++) {
      accounts[i] = accounts[i + 1];
    }
    accountCount--;
    accounts[accountCount].name[0] = '\0';
    accounts[accountCount].secret[0] = '\0';

    if (selectedAccountIndex >= accountCount) {
      selectedAccountIndex = (accountCount == 0) ? 0 : (accountCount - 1);
    }

    if (saveAccountsToStorage()) {
      Serial.println("Account deleted and storage updated.");
      if (currentScreen == Screen::Accounts) {
        drawAccountsScreen();
      }
    } else {
      Serial.println("Delete applied in RAM but failed to persist to flash.");
    }
    return;
  }

  Serial.println("Unknown command. Type help");
}

void App::printSerialHelp() const {
  Serial.println("Serial account commands:");
  Serial.println("  add        -> start add-account flow");
  Serial.println("  vadd       -> start add-vault-secret flow");
  Serial.println("  vlist      -> list vault items");
  Serial.println("  vupd <idx> -> update vault item name/secret");
  Serial.println("  vdel <idx> -> delete vault item");
  Serial.println("  cancel     -> cancel active add flow");
  Serial.println("  list       -> list accounts");
  Serial.println("  otp [idx] [unix] -> debug otp for account and optional unix time");
  Serial.println("  del <idx>  -> delete account by index");
  Serial.println("  ntp        -> connect WiFi and sync NTP time");
  Serial.println("  time       -> print current unix time source");
  Serial.println("  help       -> print commands");
  if (!pinUnlocked) {
    Serial.println("Device remains locked until PIN is entered.");
  }
}

void App::updateLayout() {
  screenW = tft.width();
  screenH = tft.height();
  centerX = screenW / 2;
  centerY = screenH / 2;

  int16_t ringBase = min(screenW, screenH);
  // Keep the ring slightly larger and farther from the code area.
  ringOuterR = (ringBase / 2) - 16;
  ringInnerR = ringOuterR - 12;
  ringCenterY = centerY + 10;
}

void App::updateButtons() {
  int16_t pinGridX = 8;
  int16_t pinGridTop = 100;
  int16_t pinGridBottomPad = 8;
  int16_t pinGap = 6;
  int16_t pinGridW = screenW - (pinGridX * 2);
  int16_t pinKeyW = (pinGridW - (2 * pinGap)) / 3;
  int16_t pinGridH = screenH - pinGridTop - pinGridBottomPad;
  int16_t pinKeyH = (pinGridH - (3 * pinGap)) / 4;

  for (uint8_t i = 0; i < 12; i++) {
    int16_t row = i / 3;
    int16_t col = i % 3;
    int16_t keyX = pinGridX + (col * (pinKeyW + pinGap));
    int16_t keyY = pinGridTop + (row * (pinKeyH + pinGap));

    uint16_t keyFill = COLOR_PANEL;
    if (i == 9 || i == 11) {
      keyFill = COLOR_SECONDARY;
    }

    pinButtons[i] = {
      keyX,
      keyY,
      pinKeyW,
      pinKeyH,
      PIN_KEY_LABELS[i],
      keyFill,
      COLOR_TEXT_LIGHT,
    };
  }

  int16_t btnW = screenW - 64;
  int16_t btnH = 52;
  int16_t btnX = (screenW - btnW) / 2;

    btnTwoFA = {
      (int16_t)btnX,
      (int16_t)(centerY - 40),
      (int16_t)btnW,
      (int16_t)btnH,
      "2FA",
      COLOR_PRIMARY,
      COLOR_TEXT_LIGHT,
    };

    btnVault = {
      (int16_t)btnX,
      (int16_t)(centerY + 26),
      (int16_t)btnW,
      (int16_t)btnH,
      "Access Vault",
      COLOR_SECONDARY,
      COLOR_TEXT_LIGHT,
    };

  int16_t listX = 12;
  int16_t listW = screenW - 24;
  int16_t rowH = 42;
  int16_t rowGap = 8;
  int16_t firstRowY = 56;
  for (uint8_t i = 0; i < MAX_ACCOUNTS; i++) {
    accountButtons[i] = {
      listX,
      (int16_t)(firstRowY + (i * (rowH + rowGap))),
      listW,
      rowH,
      accounts[i].name,
      COLOR_PANEL,
      COLOR_TEXT_DARK,
    };
  }

  btnBack = {12, 10, 76, 34, "Back", COLOR_PANEL, COLOR_TEXT_DARK};
  btnAddAccount = {12, (int16_t)(screenH - 44), (int16_t)(screenW - 24), 34, "Add Account", COLOR_PRIMARY, COLOR_TEXT_LIGHT};
}

void App::drawBackground() {
  tft.fillScreen(COLOR_BG);
}

void App::drawButton(const Button& b) {
  tft.fillRoundRect(b.x, b.y, b.w, b.h, 10, b.fill);
  tft.drawRoundRect(b.x, b.y, b.w, b.h, 10, COLOR_TEXT_LIGHT);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(b.text, b.fill);
  tft.drawString(b.label, b.x + (b.w / 2), b.y + (b.h / 2), 4);
}

void App::switchScreen(Screen next) {
  currentScreen = next;

  if (currentScreen == Screen::Pin) {
    drawPinScreen();
    return;
  }

  if (currentScreen == Screen::Menu) {
    drawMenuScreen();
    return;
  }

  if (currentScreen == Screen::Accounts) {
    accountsScrollY = 0;
    accountsDragging = false;
    drawAccountsScreen();
    return;
  }

  if (currentScreen == Screen::TwoFA) {
    slotStartMs = millis();
    lastSecondsLeft = 255;
    lastProgress = -1.0f;
    lastTotpStep = UINT64_MAX;
    strncpy(currentTotpCode, "------", sizeof(currentTotpCode) - 1);
    currentTotpCode[sizeof(currentTotpCode) - 1] = '\0';
    drawTwoFAScreen();
    return;
  }

  if (currentScreen == Screen::Vault) {
    vaultScrollY = 0;
    vaultDragging = false;
    vaultBackPending = false;
    drawVaultScreen();
    return;
  }

  drawVaultScreen();
}

void App::handleTouch() {
  uint16_t tx = 0;
  uint16_t ty = 0;
  bool touched = false;

  TouchPoint p = touch.getTouch();
  if (p.zRaw > 0) {
    uint16_t rawX = (uint16_t)p.x;
    uint16_t rawY = (uint16_t)p.y;

    auto clampMap = [](uint16_t v, int32_t inMin, int32_t inMax, int32_t outMin, int32_t outMax) -> int16_t {
      int32_t mapped = map((int32_t)v, inMin, inMax, outMin, outMax);
      if (mapped < outMin) {
        mapped = outMin;
      }
      if (mapped > outMax) {
        mapped = outMax;
      }
      return (int16_t)mapped;
    };

    // Bitbang driver can return already scaled coordinates (close to screen size).
    bool looksScaled = (rawX <= (uint16_t)(screenW + 20)) && (rawY <= (uint16_t)(screenH + 20));

    int16_t rawXToW = 0;
    int16_t rawYToH = 0;
    int16_t rawXToH = 0;
    int16_t rawYToW = 0;

    if (looksScaled) {
      rawXToW = constrain((int16_t)rawX, 0, screenW - 1);
      rawYToH = constrain((int16_t)rawY, 0, screenH - 1);
      rawXToH = constrain((int16_t)rawX, 0, screenH - 1);
      rawYToW = constrain((int16_t)rawY, 0, screenW - 1);
    } else {
      rawXToW = clampMap(rawX, TOUCH_RAW_X_MIN, TOUCH_RAW_X_MAX, 0, screenW - 1);
      rawYToH = clampMap(rawY, TOUCH_RAW_Y_MIN, TOUCH_RAW_Y_MAX, 0, screenH - 1);
      rawXToH = clampMap(rawX, TOUCH_RAW_X_MIN, TOUCH_RAW_X_MAX, 0, screenH - 1);
      rawYToW = clampMap(rawY, TOUCH_RAW_Y_MIN, TOUCH_RAW_Y_MAX, 0, screenW - 1);
    }

    auto buildPoint = [&](bool swapXY, bool invertX, bool invertY, int16_t& outX, int16_t& outY) {
      int16_t x = swapXY ? rawYToW : rawXToW;
      int16_t y = swapXY ? rawXToH : rawYToH;

      if (invertX) {
        x = (screenW - 1) - x;
      }
      if (invertY) {
        y = (screenH - 1) - y;
      }

      outX = constrain(x, 0, screenW - 1);
      outY = constrain(y, 0, screenH - 1);
    };

    int16_t bestX = 0;
    int16_t bestY = 0;
    bool bestPicked = false;

    // Try configured orientation first.
    buildPoint(TOUCH_SWAP_XY, TOUCH_INVERT_X, TOUCH_INVERT_Y, bestX, bestY);
    bestPicked = true;

    // If config misses active buttons, try fallback combinations.
    if (!hitsCurrentScreenButtons(bestX, bestY)) {
      for (uint8_t m = 0; m < 8; m++) {
        bool swapXY = (m & 0x1) != 0;
        bool invertX = (m & 0x2) != 0;
        bool invertY = (m & 0x4) != 0;

        int16_t cx = 0;
        int16_t cy = 0;
        buildPoint(swapXY, invertX, invertY, cx, cy);

        if (hitsCurrentScreenButtons(cx, cy)) {
          bestX = cx;
          bestY = cy;
          break;
        }
      }
    }

    if (bestPicked) {
      tx = (uint16_t)bestX;
      ty = (uint16_t)bestY;
    }
    touched = true;
  }

  if (touched) {
    lastUserInteractionMs = millis();
    lastTouchX = (int16_t)tx;
    lastTouchY = (int16_t)ty;

    if (currentScreen == Screen::Accounts) {
      if (!touchWasDown) {
        accountsBackPending = false;
        accountsAddPending = hitButton(btnAddAccount, (int16_t)tx, (int16_t)ty);
        accountsDragStartY = (int16_t)ty;
        accountsDragLastY = (int16_t)ty;
        accountsDragging = false;
      } else {
        if (!accountsBackPending && !accountsAddPending) {
          int16_t totalDelta = (int16_t)ty - accountsDragStartY;
          if (abs(totalDelta) >= ACCOUNTS_DRAG_THRESHOLD) {
            accountsDragging = true;
          }

          if (accountsDragging) {
            int16_t deltaY = (int16_t)ty - accountsDragLastY;
            int16_t nextScroll = accountsScrollY - deltaY;
            int16_t maxScroll = getAccountsMaxScroll();
            nextScroll = constrain(nextScroll, 0, maxScroll);
            if (nextScroll != accountsScrollY) {
              accountsScrollY = nextScroll;
              drawAccountsScreen();
            }
          }
        }
        accountsDragLastY = (int16_t)ty;
      }

      touchWasDown = true;
      return;
    }

    if (currentScreen == Screen::Vault) {
      int16_t vaultX = (screenW - 1) - (int16_t)tx;

      if (!touchWasDown) {
        vaultBackPending = hitButton(btnBack, vaultX, (int16_t)ty);
        vaultDragStartY = (int16_t)ty;
        vaultDragLastY = (int16_t)ty;
        vaultDragging = false;
      } else {
        if (!vaultBackPending) {
          int16_t totalDelta = (int16_t)ty - vaultDragStartY;
          if (abs(totalDelta) >= VAULT_DRAG_THRESHOLD) {
            vaultDragging = true;
          }

          if (vaultDragging) {
            int16_t deltaY = (int16_t)ty - vaultDragLastY;
            int16_t nextScroll = vaultScrollY - deltaY;
            int16_t maxScroll = getVaultMaxScroll();
            nextScroll = constrain(nextScroll, 0, maxScroll);
            if (nextScroll != vaultScrollY) {
              vaultScrollY = nextScroll;
              drawVaultScreen();
            }
          }
        }
        vaultDragLastY = (int16_t)ty;
      }

      touchWasDown = true;
      return;
    }

    if (!touchWasDown && (millis() - lastTapMs >= TAP_DEBOUNCE_MS)) {
      handleTap((int16_t)tx, (int16_t)ty);
      lastTapMs = millis();
    }
    touchWasDown = true;
    return;
  }

  if (touchWasDown && currentScreen == Screen::Accounts && (millis() - lastTapMs >= TAP_DEBOUNCE_MS)) {
    if (accountsAddPending) {
      beginSerialAddAccountFlow();
      lastTapMs = millis();
    } else if (!accountsDragging) {
      handleTap(lastTouchX, lastTouchY);
      lastTapMs = millis();
    }
  }

  if (touchWasDown && currentScreen == Screen::Vault && (millis() - lastTapMs >= TAP_DEBOUNCE_MS)) {
    if (!vaultDragging) {
      handleTap(lastTouchX, lastTouchY);
      lastTapMs = millis();
    }
  }

  touchWasDown = false;
  accountsDragging = false;
  accountsBackPending = false;
  accountsAddPending = false;
  vaultDragging = false;
  vaultBackPending = false;
}

void App::handleTap(int16_t x, int16_t y) {
  if (currentScreen == Screen::Pin) {
    handlePinTap(x, y);
    return;
  }

  if (currentScreen == Screen::Menu) {
    if (hitButton(btnTwoFA, x, y)) {
      Serial.println("Menu: Accounts");
      switchScreen(Screen::Accounts);
      return;
    }

    if (hitButton(btnVault, x, y)) {
      if (isPinDailyCapReached()) {
        Serial.println("Vault blocked: PIN lock threshold reached.");
        return;
      }
      Serial.println("Menu: Access Vault");
      switchScreen(Screen::Vault);
      return;
    }

    return;
  }

  if (currentScreen == Screen::Accounts) {
    int16_t accountsX = (screenW - 1) - x;
    if (hitButton(btnBack, accountsX, y)) {
      Serial.println("Back to menu");
      switchScreen(Screen::Menu);
      return;
    }

    if (hitButton(btnAddAccount, x, y)) {
      beginSerialAddAccountFlow();
      return;
    }

    for (uint8_t i = 0; i < accountCount; i++) {
      Button row = getAccountButtonAt(i);
      if (hitButton(row, x, y)) {
        selectedAccountIndex = i;
        Serial.printf("Account selected: %s\n", accounts[i].name);
        switchScreen(Screen::TwoFA);
        return;
      }
    }

    return;
  }

  if (currentScreen == Screen::TwoFA) {
    int16_t twoFaX = (screenW - 1) - x;
    if (hitButton(btnBack, twoFaX, y)) {
      Serial.println("Back to accounts");
      switchScreen(Screen::Accounts);
      return;
    }
  }

  if (currentScreen == Screen::Vault) {
    int16_t vaultX = (screenW - 1) - x;

    if (hitButton(btnBack, vaultX, y)) {
      Serial.println("Back to menu");
      switchScreen(Screen::Menu);
      return;
    }

    int8_t index = hitVaultItemIndex(vaultX, y);
    if (index >= 0) {
      vaultItems[(uint8_t)index].revealSecret = !vaultItems[(uint8_t)index].revealSecret;
      drawVaultScreen();
      return;
    }
  }

  if (hitButton(btnBack, x, y)) {
    Serial.println("Back to menu");
    switchScreen(Screen::Menu);
  }
}

bool App::hitsCurrentScreenButtons(int16_t x, int16_t y) const {
  if (currentScreen == Screen::Pin) {
    for (uint8_t i = 0; i < 12; i++) {
      if (hitButton(pinButtons[i], x, y)) {
        return true;
      }
    }
    return false;
  }

  if (currentScreen == Screen::Menu) {
    return hitButton(btnTwoFA, x, y) || hitButton(btnVault, x, y);
  }

  if (currentScreen == Screen::Accounts) {
    int16_t accountsX = (screenW - 1) - x;
    if (hitButton(btnBack, accountsX, y)) {
      return true;
    }

    if (hitButton(btnAddAccount, x, y)) {
      return true;
    }

    for (uint8_t i = 0; i < accountCount; i++) {
      if (hitButton(getAccountButtonAt(i), x, y)) {
        return true;
      }
    }
  }

  if (currentScreen == Screen::TwoFA) {
    int16_t twoFaX = (screenW - 1) - x;
    if (hitButton(btnBack, twoFaX, y)) {
      return true;
    }
  }

  if (currentScreen == Screen::Vault) {
    int16_t vaultX = (screenW - 1) - x;
    if (vaultX >= 8 && vaultX <= (screenW - 8) && y >= VAULT_VIEW_TOP && y <= getVaultViewportBottom()) {
      return true;
    }
    if (hitButton(btnBack, vaultX, y)) {
      return true;
    }
    return hitVaultItemIndex(vaultX, y) >= 0;
  }

  return hitButton(btnBack, x, y);
}

bool App::hitButton(const Button& b, int16_t x, int16_t y) const {
  return (x >= b.x && x <= (b.x + b.w) && y >= b.y && y <= (b.y + b.h));
}

int16_t App::getAccountsMaxScroll() const {
  if (accountCount == 0) {
    return 0;
  }

  int16_t viewportBottom = getAccountsViewportBottom();
  int16_t contentBottom = accountButtons[accountCount - 1].y + accountButtons[accountCount - 1].h;
  int16_t maxScroll = contentBottom - viewportBottom;
  if (maxScroll < 0) {
    maxScroll = 0;
  }
  return maxScroll;
}

int16_t App::getAccountsViewportBottom() const {
  return screenH - ACCOUNTS_VIEW_BOTTOM_PAD;
}

int16_t App::getVaultViewportBottom() const {
  return screenH - VAULT_VIEW_BOTTOM_PAD;
}

int16_t App::getVaultMaxScroll() const {
  if (vaultItemCount == 0) {
    return 0;
  }

  int16_t contentBottom = VAULT_LIST_TOP + (vaultItemCount * (VAULT_ROW_HEIGHT + VAULT_ROW_GAP)) - VAULT_ROW_GAP;
  int16_t maxScroll = contentBottom - getVaultViewportBottom();
  if (maxScroll < 0) {
    maxScroll = 0;
  }
  return maxScroll;
}

App::Button App::getAccountButtonAt(uint8_t index) const {
  Button b = accountButtons[index];
  b.y = b.y - accountsScrollY;
  return b;
}

uint64_t App::getUnixTimeSeconds() const {
  auto applyOffset = [](uint64_t base) -> uint64_t {
    int64_t adjusted = (int64_t)base + (int64_t)TOTP_TIME_OFFSET_SECONDS;
    if (adjusted < 0) {
      adjusted = 0;
    }
    return (uint64_t)adjusted;
  };

  time_t now = time(nullptr);
  if (now >= 1700000000) {
    return applyOffset((uint64_t)now);
  }
  return applyOffset(millis() / 1000ULL);
}

void App::setStatusLed(uint8_t secondsLeft) {
  if (secondsLeft <= 5) {
    digitalWrite(RED_LED_PIN, HIGH);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(BLUE_LED_PIN, LOW);
  } else if (secondsLeft <= 10) {
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(BLUE_LED_PIN, HIGH);
  } else {
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(BLUE_LED_PIN, LOW);
  }
}
