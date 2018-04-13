# Veil

![Veil Logo](https://www.veil-framework.com/wp-content/uploads/2013/12/cropped-Veil-Symbol2.png "Veil Logo")

Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.

Veil is current under support by @ChrisTruncer

- - -

## Software Requirements:

The following OSs are officially supported:

- Debian 8+
- Kali Linux Rolling 2018.1+

The following OSs are likely able to run Veil:

- Arch Linux
- BlackArch Linux
- Deepin 15+
- Elementary
- Fedora 22+
- Linux Mint
- Parrot Security
- Ubuntu 15.10+

## Setup

### Kali's Quick Install

```bash
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

### Git's Quick Install

**NOTE**:
- Installation must be done with superuser privileges. If you are not using the root account (as default with Kali Linux), prepend commands with `sudo` or change to the root user before beginning.
- Your package manager may be different to `apt`.

```bash
sudo apt-get -y install git
git clone https://github.com/Veil-Framework/Veil.git
cd Veil/
bash config/setup.sh --force --silent
```

### ./config/setup.sh // Setup Files

This file is responsible for installing all the dependences of Veil. This includes all the WINE environment, for the Windows side of things. It will install all the necessary Linux packages and GoLang, as well as Python, Ruby and AutoIT for Windows. In addition, it will also run `./config/update-config.py` for your environment.

It includes two optional flags, `--force` and `--silent`:
```bash
--force ~ If something goes wrong, this will overwrite detecting any previous installs. Useful when there is a setup package update.
--silent ~ This will perform an unattended installation of everything, as it will automate all the steps, so there is no interaction for the user.
```

This can be ran either by doing: `./Veil.py --setup` OR `./config/setup.sh --force`.

### ./config/update-config.py // Regenerating Configuration file

This will generate the output file for `/etc/veil/settings.py`. Most of the time it will not need to be rebuilt but in some cases you might be prompted to do so (such as a major Veil update).

It is important that you are in the `./config/` directory before executing `update-config.py`. If you are not, `/etc/veil/settings.py` will be incorrect and when you launch Veil you will see the following:

```bash
    Main Menu

            0 payloads loaded
```

Don't panic. Run either: `./Veil.py --config` OR `cd ./config/; ./update-config.py`.

### Py2Exe

**NOTE**: Using **Py2Exe** is recommended over PyInstaller _(as it has a lower detection rate)_.

MANUALLY Install on a Windows Computer (as this isn't done by Veil's setup):

- [Python 3.3](https://www.python.org/downloads/release/python-335/)
- [Py2Exe](https://pypi.python.org/pypi/py2exe/)
- [PyCrypto](http://www.voidspace.org.uk/python/modules.shtml#pycrypto)
- [PyWin32](https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/)

- - -

## Licensing

This project is licensed under the GNU General Public License v3 license.
