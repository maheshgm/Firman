## FirmAn : Firmware Analyser for FlashFuzz

### Dependencies
 * Install ```binbloom``` from the submodule for identifying the base adress of the firmware
 * 
### Setup
``` sh
virtualenv my_venv
. my_venv/bin/activate.fish
pipx install poetry
```

### Installation
``` sh
git clone git@github.com:maheshgm/Firman.git
cd Firman
git submodule update --init --recursive
make
```

### Usage
``` sh
firman ~/Firman/firmwares/Console/Console.bin
```