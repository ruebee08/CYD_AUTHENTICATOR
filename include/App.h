#pragma once

#include <Arduino.h>
#include <TFT_eSPI.h>

class App {
 public:
  void begin();
  void update();

 private:
  enum class Screen {
    Pin,
    Menu,
    Accounts,
    TwoFA,
    Vault,
  };

  struct Button {
    int16_t x;
    int16_t y;
    int16_t w;
    int16_t h;
    const char* label;
    uint16_t fill;
    uint16_t text;
  };

  struct Account {
    char name[24];
    char secret[65];
  };

  struct VaultItem {
    char name[28];
    char secret[96];
    bool revealSecret;
  };

  // Hardware / UI
  TFT_eSPI tft;
  int16_t screenW = 240;
  int16_t screenH = 320;
  int16_t centerX = 120;
  int16_t centerY = 160;
  int16_t ringOuterR = 80;
  int16_t ringInnerR = 64;
  int16_t ringCenterY = 170;

  // Navigation + touch
  Screen currentScreen = Screen::Pin;
  bool touchWasDown = false;
  uint32_t lastTapMs = 0;

  // TOTP visual state
  uint32_t slotStartMs = 0;
  uint8_t lastSecondsLeft = 255;
  float lastProgress = -1.0f;
  uint64_t lastTotpStep = UINT64_MAX;
  char currentTotpCode[7] = "------";

  // Buttons
  Button pinButtons[12]{};
  Button btnTwoFA{};
  Button btnVault{};
  Button btnBack{};
  Button btnAddAccount{};

  char enteredPin[7]{};
  uint8_t enteredPinLen = 0;
  bool pinUnlocked = false;
  bool pinShowError = false;
  uint32_t pinErrorStartedMs = 0;
  bool pinSetupRequired = false;
  uint8_t pinFailedAttempts = 0;
  uint16_t pinDailyFailedAttempts = 0;
  uint32_t pinDailyWindowStartUnix = 0;
  uint32_t pinLockoutUntilUnix = 0;
  uint16_t pinLastLockoutSeconds = 0xFFFF;
  uint8_t pinSalt[16]{};
  uint8_t pinHash[32]{};
  bool pinAuthConfigured = false;

  static constexpr uint32_t INACTIVITY_LOCK_TIMEOUT_MS = 120000;
  uint32_t lastUserInteractionMs = 0;

  static constexpr uint8_t MAX_ACCOUNTS = 16;
  Account accounts[MAX_ACCOUNTS]{};
  Button accountButtons[MAX_ACCOUNTS]{};
  uint8_t accountCount = 0;
  uint8_t selectedAccountIndex = 0;

  static constexpr uint8_t MAX_VAULT_ITEMS = 8;
  VaultItem vaultItems[MAX_VAULT_ITEMS]{};
  uint8_t vaultItemCount = 0;

  int16_t accountsScrollY = 0;
  int16_t accountsDragStartY = 0;
  int16_t accountsDragLastY = 0;
  int16_t vaultScrollY = 0;
  int16_t vaultDragStartY = 0;
  int16_t vaultDragLastY = 0;
  int16_t lastTouchX = 0;
  int16_t lastTouchY = 0;
  bool accountsDragging = false;
  bool vaultDragging = false;
  bool accountsBackPending = false;
  bool accountsAddPending = false;
  bool vaultBackPending = false;
  bool ntpSynced = false;
  bool storageMasterKeyReady = false;
  uint32_t lastNtpRetryMs = 0;
  String serialLineBuffer;
  String pendingAccountName;
  String pendingVaultName;
  int8_t pendingVaultIndex = -1;
  uint8_t storageMasterKey[32]{};

  enum class SerialEnrollState : uint8_t {
    Idle,
    WaitName,
    WaitSecret,
    WaitVaultName,
    WaitVaultSecret,
    WaitVaultUpdateName,
    WaitVaultUpdateSecret,
  };
  SerialEnrollState serialEnrollState = SerialEnrollState::Idle;

  enum class PinSetupState : uint8_t {
    Idle,
    WaitPin,
    WaitConfirm,
  };
  PinSetupState pinSetupState = PinSetupState::Idle;
  String pendingPinSetupValue;

  static constexpr int16_t ACCOUNTS_VIEW_TOP = 56;
  static constexpr int16_t ACCOUNTS_VIEW_BOTTOM_PAD = 58;
  static constexpr int16_t ACCOUNTS_DRAG_THRESHOLD = 8;
  static constexpr int16_t VAULT_VIEW_TOP = 56;
  static constexpr int16_t VAULT_VIEW_BOTTOM_PAD = 12;
  static constexpr int16_t VAULT_DRAG_THRESHOLD = 8;

  // Internal helpers
  void loadAccountsFromStorage();
  void loadVaultFromStorage();
  bool loadOrCreateStorageMasterKey();
  bool saveAccountsToStorage() const;
  bool saveVaultToStorage() const;
  bool encryptSecretForStorage(const char* plainSecret, String& outHex) const;
  bool decryptSecretFromStorage(const char* encryptedHex, char* outSecret, size_t outSecretSize) const;
  bool isValidBase32Secret(const String& secret) const;
  void beginSerialAddAccountFlow();
  void beginSerialAddVaultFlow();
  void beginSerialUpdateVaultFlow(uint8_t index);
  bool syncTimeWithNtp();
  void printTimeStatus() const;
  void handleSerial();
  void handleSerialLine(const String& line);
  void printSerialHelp() const;
  void updateLayout();
  void updateButtons();

  void drawBackground();
  void drawButton(const Button& b);

  void drawMenuScreen();
  void drawAccountsScreen();
  void drawTwoFAScreen();
  void drawVaultScreen();
  void drawVaultRows();
  int8_t hitVaultItemIndex(int16_t x, int16_t y) const;
  void drawPinScreen();
  void drawPinEntry();
  void handlePinTap(int16_t x, int16_t y);
  bool validateEnteredPin();
  bool isSixDigitPin(const String& value) const;
  void beginPinSetupSerialFlow();
  void handlePinSetupSerialLine(const String& line);
  bool loadPinAuthConfig();
  bool savePinAuthConfig();
  bool derivePinHash(const char* pin, const uint8_t* salt, uint8_t outHash[32]) const;
  bool verifyEnteredPinAgainstStoredHash();
  bool savePinFailedAttempts() const;
  uint32_t getPinBackoffSeconds(uint8_t failedAttempts) const;
  bool isPinDailyCapReached() const;

  void drawRing(float progress);
  void drawTotpCode(const char* code);
  void drawSecondsLeft(uint8_t secondsLeft);

  void updateTwoFAScreen();
  uint64_t getUnixTimeSeconds() const;
  bool generateTotpCode(uint8_t accountIndex, uint64_t unixTimeSeconds, char outCode[7]) const;

  void switchScreen(Screen next);
  void handleTouch();
  void handleTap(int16_t x, int16_t y);
  bool hitsCurrentScreenButtons(int16_t x, int16_t y) const;
  int16_t getAccountsViewportBottom() const;
  int16_t getAccountsMaxScroll() const;
  int16_t getVaultViewportBottom() const;
  int16_t getVaultMaxScroll() const;
  Button getAccountButtonAt(uint8_t index) const;
  bool hitButton(const Button& b, int16_t x, int16_t y) const;

  void setStatusLed(uint8_t secondsLeft);
};
