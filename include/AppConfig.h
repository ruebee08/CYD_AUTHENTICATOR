#pragma once

#include <Arduino.h>
#include <TFT_eSPI.h>

constexpr uint8_t RED_LED_PIN = 4;
constexpr uint8_t GREEN_LED_PIN = 16;
constexpr uint8_t BLUE_LED_PIN = 17;
constexpr uint8_t TFT_BACKLIGHT_PIN = 21;
constexpr uint8_t TOUCH_CS_PIN = 33;
constexpr int8_t TOUCH_IRQ_PIN = 36;
constexpr uint8_t TOUCH_MOSI_PIN = 32;
constexpr uint8_t TOUCH_MISO_PIN = 39;
constexpr uint8_t TOUCH_SCK_PIN = 25;

constexpr uint32_t TOTP_PERIOD_MS = 30000;
constexpr uint32_t TAP_DEBOUNCE_MS = 140;

// Wi-Fi + NTP settings used for accurate TOTP time.
// Fill SSID/PASSWORD with your network values.
constexpr const char* WIFI_SSID = "Galaxy A03s215a";
constexpr const char* WIFI_PASSWORD = "googoodol";
constexpr const char* NTP_SERVER_PRIMARY = "time.google.com";
constexpr const char* NTP_SERVER_SECONDARY = "time.cloudflare.com";
constexpr uint32_t WIFI_CONNECT_TIMEOUT_MS = 15000;
constexpr uint32_t NTP_SYNC_TIMEOUT_MS = 10000;
constexpr uint32_t NTP_RESYNC_INTERVAL_MS = 60000;  // 60 seconds (aggressive resync for accurate TOTP)

// Manual correction if your measured device epoch differs from trusted epoch.

constexpr int32_t TOTP_TIME_OFFSET_SECONDS = -74;

// XPT2046 raw touch calibration / orientation mapping.
// Tune these values if taps are offset on your panel.
constexpr uint16_t TOUCH_RAW_X_MIN = 200;
constexpr uint16_t TOUCH_RAW_X_MAX = 3900;
constexpr uint16_t TOUCH_RAW_Y_MIN = 200;
constexpr uint16_t TOUCH_RAW_Y_MAX = 3900;
constexpr bool TOUCH_SWAP_XY = false;
constexpr bool TOUCH_INVERT_X = false;
constexpr bool TOUCH_INVERT_Y = true;

constexpr uint16_t COLOR_BG = 0xFDB9;             // Light pink
constexpr uint16_t COLOR_PANEL = 0xB0F6;          // Soft pink-purple
constexpr uint16_t COLOR_PRIMARY = 0xD174;        // Rose
constexpr uint16_t COLOR_SECONDARY = 0x32BF;      // Blue
constexpr uint16_t COLOR_TEXT_DARK = 0x18C3;      // Dark text
constexpr uint16_t COLOR_TEXT_LIGHT = TFT_WHITE;
