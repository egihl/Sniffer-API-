import os
import sys
import time
import argparse
import json

from SnifferAPI import Logger
from SnifferAPI import Sniffer
from SnifferAPI.Devices import Device
from SnifferAPI.Devices import DeviceList

# the main modifications to Adafriut Industries Sniffer API code 
# (the addition of the cloud data recording) is located here

mySniffer = None
"""@type: SnifferAPI.Sniffer.Sniffer"""


def setup(serport, delay=6):
    """
    Tries to connect to and initialize the sniffer using the specific serial port
    @param serport: The name of the serial port to connect to ("COM14", "/dev/tty.usbmodem1412311", etc.)
    @type serport: str
    @param delay: Time to wait for the UART connection to be established (in seconds)
    @param delay: int
    """
    global mySniffer

    # Initialize the device on the specified serial port
    print "Connecting to sniffer on " + serport
    mySniffer = Sniffer.Sniffer(serport)
    # Start the sniffer
    mySniffer.start()
    # Wait a bit for the connection to initialise
    time.sleep(delay)


def scanForDevices(scantime=5):
    """
    @param scantime: The time (in seconds) to scan for BLE devices in range
    @type scantime: float
    @return: A DeviceList of any devices found during the scanning process
    @rtype: DeviceList
    """
    if args.verbose:
        print "Starting BLE device scan ({0} seconds)".format(str(scantime))

    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()
    return devs


def dumpPackets():
    """Dumps incoming packets to the display"""
    # Get (pop) unprocessed BLE packets.
    packets = mySniffer.getPackets()
    # Display the packets on the screen in verbose mode
    if args.verbose:
        for packet in packets:
            if packet.blePacket is not None:
                # Display the raw BLE packet payload
                # Note: 'BlePacket' is nested inside the higher level 'Packet' wrapper class
		print packet.blePacket.payload
            else:
                print packet
    else:
        print '.' * len(packets)

def sendtoCloud(devlist):
	count = 0
	if len(devlist):
		for d in devlist.asList():
			"""@type : Device"""
			count += 1
			# creates a formatted temp file as if they were json objects
			# writes file name and device list number
			if str(d.name) == "":
				fid.write("{\"deviceName\": \"N/A\",\n")
				fid.write("\"deviceNumber\": {0},\n".format(count))
			else:
				fid.write('{\"deviceNumber\": ' + str(count) +',\n')
				fid.write('\"deviceName\": \"'+str(d.name)+'\",\n')
			# writes address
			fid.write("\"address\": \"{0}:{1}:{2}:{3}:{4}:{5}\",\n".format("%02X" % d.address[0],
																	"%02X" % d.address[1],
																	"%02X" % d.address[2],
																	"%02X" % d.address[3],
																	"%02X" % d.address[4],
																	"%02X" % d.address[5]))
			# writes packet content and id information														
			packets = mySniffer.getPackets()
			# check for similar advertising packets
			previous_packets = []
			n = 0
			packet_check = True
			pariable = False 
			fid.write("\"packet\":{\n")
			for packet in packets:
				if packet.blePacket is not None:
					# eliminates redundant packets 
					for n in previous_packets:
						if packet.blePacket.payload != previous_packets(n): 
							packet_check = True
							# adds unique packet to list of advertising packets
							previous_packets.append(packet.blePacket.payload)
							# can be fickle when testing for long periods of time
						else:
							packet_check = False
						previous_packets.append(packet.blePacket.payload)
					if packet_check:
						packet_length = packet.payloadLength
						if packet.id is not None:
							packet_id = str(packet.id)
							if packet_id == '0':
								packet_id = 'REQ_FOLLOW'
								pariable = True #packet type determines if pariable
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '1':
								packet_id = 'EVENT_FOLLOW'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '5':
								packet_id = 'EVENT_CONNECT'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '6':
								packet_id = 'EVENT_PACKET'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '7':
								packet_id = 'REQ_SCAN_CONT'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '9':
								packet_id = 'EVENT_DISCONNECT'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == 'C':
								packet_id = 'SET_TEMP_KEY'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == 'D':
								packet_id = 'PING_REQ'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == 'E':
								packet_id = 'PING_RESP'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							elif packet_id == '17':
								packet_id = 'SET_ADV_CHANNEL_RES'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
							else:
								packet_id = 'UNKNOWN'
								fid.write('    \"type\": \"' + packet_id + '\",\n')
						else:
							fid.write("    \"type\": \"N/A\",\n")
						if packet_length is not None:
							content = str(packet.blePacket.payload)
							content = ":".join(c.encode('hex') for c in content)
							fid.write('    \"payloadLength\": ' + str(packet_length) + ',\n')
							fid.write('    \"content\": \"' + content +'\",\n')
						else:
							fid.write("    \"payloadLength\": 0,\n")
							fid.write("    \"content\": \"{0}\",\n").format(str(packet))
				#else:
					#fid.write('    \"content\": \"' + str(packet)+ '\",\n')	
			fid.write("    },\n")
			
			# for first time device detection
			if d.discovered:
				fid.write("\"discovered\": False,\n")
				d.discovered = False
			else:
				fid.write("\"discovered\": True,\n") 
			# writes local time stamp
			local_time = time.localtime()
			time_stamp = time.strftime("%m/%d/%Y %H:%M:%S",local_time)
			fid.write('\"timestamp\": \"' + time_stamp + '\",\n')
			
			# for detection of pariable devices
			if pariable:
				fid.write('\"pairable\": \"True\"}\n')
			else:
				fid.write('\"pairable\": \"False\"}\n\n')
			# End of temp file creation
	
		
def selectDevice(devlist):
    """
    Attempts to select a specific Device from the supplied DeviceList
    @param devlist: The full DeviceList that will be used to select a target Device from
    @type devlist: DeviceList
    @return: A Device object if a selection was made, otherwise None
    @rtype: Device
    """
    count = 0

    if len(devlist):
        print "Found {0} BLE devices:\n".format(str(len(devlist)))
        # Display a list of devices, sorting them by index number
        for d in devlist.asList():
			"""@type : Device"""
			count += 1
			print "  [{0}] {1} ({2}:{3}:{4}:{5}:{6}:{7}, RSSI = {8})".format(count, d.name,
																				"%02X" % d.address[0],
																				"%02X" % d.address[1],
																				"%02X" % d.address[2],
																				"%02X" % d.address[3],
																				"%02X" % d.address[4],
																				"%02X" % d.address[5],
																				d.RSSI)
        try:
            i = int(raw_input("\nSelect a device to sniff, or '0' to scan again\n> "))
        except:
            return None

        # Select a device or scan again, depending on the input
        if (i > 0) and (i <= count):
            # Select the indicated device
            return devlist.find(i - 1)
        else:
            # This will start a new scan	
			return None
			
if __name__ == '__main__':
    """Main program execution point"""

    # Instantiate the command line argument parser
    argparser = argparse.ArgumentParser(description="Interacts with the Bluefruit LE Friend Sniffer firmware")

    # Add the individual arguments
    # Mandatory arguments:
    argparser.add_argument("serialport",
                           help="serial port location ('COM14', '/dev/tty.usbserial-DN009WNO', etc.)")

    # Optional arguments:
    argparser.add_argument("-v", "--verbose",
                           dest="verbose",
                           action="store_true",
                           default=False,
                           help="verbose mode (all serial traffic is displayed)")

    # Parser the arguments passed in from the command-line
    args = argparser.parse_args()

    # Display the libpcap logfile location
    print "Logging data to " + os.path.join(Logger.logFilePath, "capture.pcap")

    # Try to open the serial port
    try:
        setup(args.serialport)
    except OSError:
        # pySerial returns an OSError if an invalid port is supplied
        print "Unable to open serial port '" + args.serialport + "'"
        sys.exit(-1)

    # Optionally display some information about the sniffer
    if args.verbose:
        print "Sniffer Firmware Version: " + str(mySniffer.swversion)

    # Scan for devices in range until the user makes a selection
    try:
		# Creates cloud packet file
		fid = open('cloud_data.txt','w+')
		d = None
		"""@type: Device"""
		while d is None:
			print "Scanning for BLE devices (5s) ..."
			devlist = scanForDevices()
			# creates file to send to cloud
			sendtoCloud(devlist)
			if len(devlist):
				# Select a device
				d = selectDevice(devlist)
		
        # Start sniffing the selected device
		print "Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
																					"%02X" % d.address[1],
																					"%02X" % d.address[2],
																					"%02X" % d.address[3],
																					"%02X" % d.address[4],
																					"%02X" % d.address[5])
		
		# Prints list of devices & timestamp to cloud file
		fid.write("Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
																					"%02X" % d.address[1],
																					"%02X" % d.address[2],
																					"%02X" % d.address[3],
																					"%02X" % d.address[4],
																					"%02X" % d.address[5]))
		local_time = time.localtime()
		time_stamp = time.strftime(" %m/%d/%Y %H:%M:%S",local_time)
		fid.write(time_stamp )
		
		# code to send data to cloud database (to be added)
		
		# Make sure we actually followed the selected device (i.e. it's still available, etc.)
		if d is not None:
			mySniffer.follow(d)
		else:
			print "ERROR: Could not find the selected device"
		
        # Dump packets
		while True:
			dumpPackets()
			time.sleep(1)
		
		# Close gracefully
		mySniffer.doExit()
		fid.close()
		sys.exit()
		
    except KeyboardInterrupt:
    # Close gracefully on CTRL+C
		mySniffer.doExit()
		fid.close()
		sys.exit(-1)	
