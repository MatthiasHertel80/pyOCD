


Risks:

- libusb system binaries need to be included. Best practice?

USB Backend Support:
pyocd/probe/pydapaccess/interface/pyusb_backend.py
Used in PyUSB class as the backend for:
CMSIS-DAPv1 on Linux
CMSIS-DAPv2 on all OSes
STLink on all OSes

pyocd/probe/stlink/usb.py
STLink Support:
Used in STLinkUSBInterface for low-level USB communication with STLink devices


Improve:

- Remove included svd files (code changes?)



