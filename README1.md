# Modified Python API for Bluefruit LE Sniffer 

This repository contains the Python API for Adafruit's Bluefruit LE Sniffer, and our easy to use API wrapper, in 
addition it contains the capability to store and create BLE device data to be sent to a cloud database.

It has been tested on the following platforms using Python 2.7:

## Related Links

Bluefruit LE Sniffer product page: https://www.adafruit.com/product/2269
Bluefruit LE Sniffer Learning Guide: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/introduction

## Using sniffer.py

To use sniffer.py, simply specify the serial port where the sniffer can be found (ex. `COM14` on Windows, `/dev/tty.usbmodem1412311` on OS X, `/dev/ttyACM0` or Linux, etc.):

```
python sniffer.py /dev/tty.usbmodem1412311
```

**Note:** You will need to run python with `sudo` on Linux to allow the log file to be created, so `sudo python sniffer.py /dev/ttyACM0`, etc..

This will create a new log file and start scanning for BLE devices, which should result in the following menu:

```
$ python sniffer.py /dev/tty.usbmodem1412311
Logging data to logs/capture.pcap
Connecting to sniffer on /dev/tty.usbmodem1412311
Scanning for BLE devices (5s) ...
Found 2 BLE devices:

  [1] "" (14:99:E2:05:29:CF, RSSI = -85)
  [2] "" (E7:0C:E1:BE:87:66, RSSI = -49)

Select a device to sniff, or '0' to scan again
> 
```

Simply select the device you wish to sniff, and it will start logging traffic from the specified device.

A file containing the basic information of each device(name, address, packet information, time stamp,
pairability, etc.) is created after each scan is completed.

Restarting the sniffer will reset the timestamps and it will treat each device as an unknown device.

Type **CTRL+C** to stop sniffing and quit the application, closing the libpcap log file.



## Requirements

This Python script was written and tested on **Python 2.7.6**, and will require that both Python 2.7 and **pySerial** are installed on your system.
