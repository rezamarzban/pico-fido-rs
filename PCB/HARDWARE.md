# Hardware: pico-fido-rs carrier board

Open hardware design (KiCad 8) for the device this firmware runs on: a Raspberry Pi Pico (RP2040,
USB device) with an ATECC608A secure element and an optional SSD1306 OLED.

Files in this directory:

| File | Content |
|---|---|
| `pico-fido-rs-board.kicad_pro` | KiCad project |
| `pico-fido-rs-board.kicad_sch` | schematic |
| `pico-fido-rs-board.kicad_pcb` | board layout, 2 layers, 35.5 x 74 mm |
| `board-preview.png` | board preview |

License: GPL-3.0, same as the firmware (see [LICENSE](../LICENSE)).
The firmware compatibility report does not establish fabrication or electrical validation of this board.

## Connections (as used by the firmware)

| Signal | Pico pin | Goes to |
|---|---|---|
| I2C1 SDA (`src/se/i2c.rs`) | GP14 (pin 19) | ATECC608A pin 5, 4.7 k pull-up R1 |
| I2C1 SCL | GP15 (pin 20) | ATECC608A pin 6, 4.7 k pull-up R2 |
| I2C0 SDA (`src/oled.rs`) | GP16 (pin 21) | J2 pin 4 (OLED SDA) |
| I2C0 SCL | GP17 (pin 22) | J2 pin 3 (OLED SCL) |
| 3V3 | 3V3(OUT) (pin 36) | ATECC608A pin 8, pull-ups, C1, J2 pin 2 |
| GND | all GND pins | ATECC608A pin 4, C1, J2 pin 1 |

The ATECC608A is at I2C address 0x60, the OLED at 0x3C. The OLED I2C lines have no external pull-ups
(modules usually have their own; the firmware also enables the RP2040 internal ones).

## Bill of materials

| Ref | Part | Footprint |
|---|---|---|
| J1 | Raspberry Pi Pico (2x20 pin headers or castellated) | 2x20, 2.54 mm, 17.78 mm row spacing |
| U1 | ATECC608A-SSHDA (SOIC-8) | `Package_SO:SOIC-8_3.9x4.9mm_P1.27mm` |
| R1, R2 | 4.7 k, 0805 | `Resistor_SMD:R_0805_2012Metric` |
| C1 | 100 nF, 0805 | `Capacitor_SMD:C_0805_2012Metric` |
| J2 | 1x4 pin header, 2.54 mm (GND, VCC, SCL, SDA) | `PinHeader_1x04_P2.54mm_Vertical` |

## Notes

* The GND pour on the bottom layer is not filled in the file: open the board in KiCad and press `B`
  (Edit, Fill All Zones) before running DRC or exporting Gerbers.
* The schematic uses net labels for `+3V3` and `GND`: place `PWR_FLAG` symbols on both nets before running ERC.
* Order of the J2 pins matches the common SSD1306 module (GND, VCC, SCL, SDA); check your module.
