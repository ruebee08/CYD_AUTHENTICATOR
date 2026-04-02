# CYD Authenticator

CYD Authenticator is an ESP32-based authenticator and secret vault UI built for a 240x320 touchscreen device. It provides TOTP account management, a PIN lock screen, and an encrypted vault for storing secrets in flash.
## Demo

https://github.com/user-attachments/assets/5cb7061f-26e5-4bed-af7c-6cdc561d7bb5
## Features

- PIN lock screen with stored PIN verification
- First boot PIN setup prompt before normal use
- TOTP account list and code display
- Encrypted storage for account secrets and vault secrets
- Vault screen with show/hide secret controls
- Serial-driven workflows for adding, updating, and deleting vault items
- Inactivity auto-lock for the device
- Touch UI tuned for the CYD-style ESP32 touchscreen layout

## Hardware / Target

This project is configured for:

- `esp32dev`
- ESP32 + 240x320 ST7789 display
- XPT2046 touch controller
- PlatformIO Arduino framework

## Requirements

- Visual Studio Code
- PlatformIO extension
- ESP32 device connected over USB

## Build and Upload

From the project root:

```bash
pio run
pio run -t upload
```

To open the serial monitor:

```bash
pio device monitor
```

## Serial Commands

On first boot, the CYD will prompt you to create and confirm a PIN on the touchscreen before normal use.

After the PIN is set, unlock the device first if it is PIN-protected, then use the serial monitor for vault and account management.

### Vault

- `vadd` - add a new vault item
- `vlist` - list vault items
- `vupd <idx>` - update a vault item by index
- `vdel <idx>` - delete a vault item by index
- `cancel` - cancel the current add/update flow

### Accounts

- `add` - start the add-account flow
- `list` - list accounts
- `otp [idx] [unix]` - debug TOTP output for an account
- `del <idx>` - delete an account by index

### Utility

- `help` - print the available commands
- `time` - print current Unix time source
- `ntp` - sync time with NTP
- You can check whether your TOTP codes are synced with this website: https://totp.danhersam.com

## Encryption

The app does not keep a hardcoded secret key in the source code. Instead, it generates a persistent storage master key on first boot and saves it in flash so the device can read its own encrypted data after reboot.

Account secrets and vault secrets are encrypted before being written to flash, and decrypted only after loading them back into memory. The PIN itself is stored separately as a salted hash, not as plain text.

To make brute-force attacks harder, the PIN flow uses retry limits with increasing lockout delays and a daily failure cap.

## Project Structure

- `src/app.cpp` - main application logic
- `src/screen_pin.cpp` - PIN screen UI
- `src/screen_menu.cpp` - main menu UI
- `src/screen_accounts.cpp` - accounts list UI
- `src/screen_twofa.cpp` - TOTP screen UI
- `src/screen_vault.cpp` - vault UI
- `include/App.h` - application class and shared state
- `include/AppConfig.h` - device and app configuration

## Notes

- Vault secrets are stored encrypted in flash.
- Serial vault management is the supported path for adding, updating, and deleting secrets.
- The touchscreen vault screen is for viewing and toggling secrets.
