package btmgmt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"time"
)


// https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/mgmt-api.txt

type BTManagementSession struct {
	sockFd int
	sockAddr *unix.SockaddrHCI
	controllerIndex uint16
}

// Create raw HCI bluetooth management socket
/**
The Bluetooth management sockets can be created by setting the hci_channel
member of struct sockaddr_hci to HCI_CHANNEL_CONTROL (3) when creating a
raw HCI socket. In C the needed code would look something like the following:

int mgmt_create(void)
{
	struct sockaddr_hci addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                                                BTPROTO_HCI);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	return fd;
}
 */



func CreateSession() (*BTManagementSession, error) {
	// PF_BLUETOOTH = AF_BLUETOOTH
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK, unix.BTPROTO_HCI)
	if err != nil {
		return nil, fmt.Errorf("could not create btmgmt socket: %s", err)
	}

	log.Printf("btmgmt sock fd: %d\n", fd)

	const HCI_DEV_NONE = 0xFFFF

	addr := unix.SockaddrHCI{
		Dev:     HCI_DEV_NONE,
		Channel: unix.HCI_CHANNEL_CONTROL,
	}

	err = unix.Bind(fd, &addr)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("could not bind to btmgmt socket: %s", err)
	}

	return &BTManagementSession{
		sockFd: fd,
		controllerIndex: NON_CONTROLLER,
		sockAddr: &addr,
	}, nil
}

func (session *BTManagementSession) SetController(index uint16) {
	session.controllerIndex = index
}

func (session *BTManagementSession) Close() error {
	return unix.Close(session.sockFd)
}


const NON_CONTROLLER = 0xFFFF

const (
	CMD_READ_CONTROLLER_INDEX_LIST = 0x0003
	CMD_PAIR = 0x0019
	CMD_READ_LOCAL_OOB_DATA = 0x0020
	CMD_READ_LOCAL_OOB_DATA_EXTENDED = 0x003B
	CMD_ADD_REMOTE_OOB_DATA = 0x0021
	CMD_SET_SC = 0x002D
)

func (session *BTManagementSession) GetControllerIndices() ([]uint16, error) {
	var controllers []uint16

	data, err := session.execBlocking(CMD_READ_CONTROLLER_INDEX_LIST, NON_CONTROLLER, nil)
	if err != nil {
		return nil, err
	}

	if len(data) > 2 {
		log.Println("Controller list: ")

		numControllers := binary.LittleEndian.Uint16(data[0:])
		log.Printf("Num controllers: %d\n", numControllers)

		for i := uint16(0); i < numControllers; i++ {
			off := 2 + 2 * i
			log.Printf("Controller %d index: %d", i, binary.LittleEndian.Uint16(data[off:]))
			controllers = append(controllers, binary.LittleEndian.Uint16(data[off:]))
		}
	}

	return controllers, nil
}

/**
Result contents depend on the current controller settings

	Command Code:		0x0020
	Controller Index:	<controller id>
	Command Parameters:
	Return Parameters:	Hash_192 (16 Octets)
				Randomizer_192 (16 Octets)
				Hash_256 (16 Octets, Optional)
				Randomizer_256 (16 Octets, Optional)

	This command is used to read the local Out of Band data.

	This command can only be used when the controller is powered.

	If Secure Connections support is enabled, then this command
	will return P-192 versions of hash and randomizer as well as
	P-256 versions of both.

	Values returned by this command become invalid when the controller
	is powered down. After each power-cycle it is required to call
	this command again to get updated values.

	This command generates a Command Complete event on success or
	a Command Status event on failure.

	Possible errors:	Not Supported
						Busy
						Invalid Parameters
						Not Powered
						Invalid Index
 */
func (session *BTManagementSession) ReadLocalOOBData() (
	h192 [16]byte, r192 [16]byte,
	h256 [16]byte, r256 [16]byte,
	err error) {

	data, err := session.execBlocking(CMD_READ_LOCAL_OOB_DATA,  session.controllerIndex, nil)
	if err != nil {
		return
	}

	copy(h192[:], data[0:16])
	copy(r192[:], data[16:32])
	copy(h256[:], data[32:48])
	copy(r256[:], data[48:64])

	return
}

func (session *BTManagementSession) ReadLocalOOBDataExtended() (
	h192 [16]byte, r192 [16]byte,
	h256 [16]byte, r256 [16]byte,
	err error) {

	parameters := []byte{ LE_PUBLIC }

	_, err = session.execBlocking(CMD_READ_LOCAL_OOB_DATA_EXTENDED,  session.controllerIndex, parameters)
	if err != nil {
		return
	}

	/*copy(h192[:], data[0:16])
	copy(r192[:], data[16:32])
	copy(h256[:], data[32:48])
	copy(r256[:], data[48:64])*/

	return
}

/**
	Command Code:		0x0021
	Controller Index:	<controller id>
	Command Parameters:	Address (6 Octets)
				Address_Type (1 Octet)
				Hash_192 (16 Octets)
				Randomizer_192 (16 Octets)
				Hash_256 (16 Octets, Optional)
				Randomizer_256 (16 Octets, Optional)
	Return Parameters:	Address (6 Octets)
				Address_Type (1 Octet)

	This command is used to provide Out of Band data for a remote
	device.

	Possible values for the Address_Type parameter:
		0	BR/EDR
		1	LE Public
		2	LE Random

	Provided Out Of Band data is persistent over power down/up toggles.

	This command also accept optional P-256 versions of hash and
	randomizer. If they are not provided, then they are set to
	zero value.

	The P-256 versions of both can also be provided when the
	support for Secure Connections is not enabled. However in
	that case they will never be used.

	To only provide the P-256 versions of hash and randomizer,
	it is valid to leave both P-192 fields as zero values. If
	Secure Connections is disabled, then of course this is the
	same as not providing any data at all.

	When providing data for remote LE devices, then the Hash_192 and
	and Randomizer_192 fields are not used and shell be set to zero.

	The Hash_256 and Randomizer_256 fields can be used for LE secure
	connections Out Of Band data. If only LE secure connections data
	is provided the Hash_P192 and Randomizer_P192 fields can be set
	to zero. Currently there is no support for providing the Security
	Manager TK Value for LE legacy pairing.

	If Secure Connections Only mode has been enabled, then providing
	Hash_P192 and Randomizer_P192 is not allowed. They are required
	to be set to zero values.

	This command can be used when the controller is not powered and
	all settings will be programmed once powered.

	This command generates a Command Complete event on success
	or failure.

	Possible errors:	Failed
						Invalid Parameters
						Not Powered
						Invalid Index
 */

const (
	BR_EDR = 0
	LE_PUBLIC = 1
	LE_RANDOM = 2
)

const (
	DisplayOnly = 0
	DisplayYesNo = 1
	KeyboardOnly = 2
	NoInputNoOutput = 3
	KeyboardDisplay = 4
)

/**
Pair Device Command
===================

	Command Code:		0x0019
	Controller Index:	<controller id>
	Command Parameters:	Address (6 Octets)
				Address_Type (1 Octet)
				IO_Capability (1 Octet)
	Return Parameters:	Address (6 Octets)
				Address_Type (1 Octet)

	This command is used to trigger pairing with a remote device.
	The IO_Capability command parameter is used to temporarily (for
	this pairing event only) override the global IO Capability (set
	using the Set IO Capability command).

	Possible values for the Address_Type parameter:
		0	BR/EDR
		1	LE Public
		2	LE Random

	Possible values for the IO_Capability parameter:
		0	DisplayOnly
		1	DisplayYesNo
		2	KeyboardOnly
		3	NoInputNoOutput
		4	KeyboardDisplay

	Passing a value 4 (KeyboardDisplay) will cause the kernel to
	convert it to 1 (DisplayYesNo) in the case of a BR/EDR
	connection (as KeyboardDisplay is specific to SMP).

	The Address and Address_Type of the return parameters will
	return the identity address if known. In case of resolvable
	random address given as command parameters and the remote
	provides an identity resolving key, the return parameters
	will provide the resolved address.

	To allow tracking of which resolvable random address changed
	into which identity address, the New Identity Resolving Key
	event will be sent before receiving Command Complete event
	for this command.

	This command can only be used when the controller is powered.

	This command generates a Command Complete event on success
	or failure.

	Reject status is used when requested transport is not enabled.

	Not Supported status is used if controller is not capable with
	requested transport.

	Possible errors:	Rejected
				Not Supported
				Connect Failed
				Busy
				Invalid Parameters
				Not Powered
				Invalid Index
				Already Paired
 */
func (session *BTManagementSession) Pair(address string, addressType byte, ioCap byte) error {
	mac, err := net.ParseMAC(address)
	if err != nil {
		return fmt.Errorf("invalid address: %s", address)
	}

	parameters := make([]byte, 8)
	copy(parameters, mac[:6])
	parameters[6] = addressType
	parameters[7] = ioCap

	resp, err := session.execBlocking(CMD_PAIR,  session.controllerIndex, parameters)
	if err != nil {
		return err
	}
	log.Infof("Pairing response: %s", hex.EncodeToString(resp))
	return nil
}

func (session *BTManagementSession) AddRemoteOOBData(address string, addressType byte, h192 []byte,  r192 []byte,
	h256 []byte, r256 []byte) error {

	mac, err := net.ParseMAC(address)
	if err != nil {
		return fmt.Errorf("invalid address: %s", address)
	}

	parameters := make([]byte, 6 + 1 + 16 * 4)
	copy(parameters, mac[:6])
	parameters[6] = addressType

	copy(parameters[7 + 16 * 0:7 + 16 * 1], h192)
	copy(parameters[7 + 16 * 1:7 + 16 * 2], r192)
	copy(parameters[7 + 16 * 2:7 + 16 * 3], h256)
	copy(parameters[7 + 16 * 3:7 + 16 * 4], r256)

	_, err = session.execBlocking(CMD_ADD_REMOTE_OOB_DATA,  session.controllerIndex, parameters)
	if err != nil {
		return err
	}
	return nil
}

const (
	SC_OFF = 0
	SC_ON = 1
	SC_ONLY = 2
)

func (session *BTManagementSession) SetSecureConnections(value byte) error {
	_, err := session.execBlocking(CMD_SET_SC,  session.controllerIndex, []byte{ value })
	if err != nil {
		return err
	}
	return nil
}

func ParseSettings(settingsBytes []byte) string {
	settings := binary.LittleEndian.Uint32(settingsBytes)

	const (
		BIT_POWERED = 0
		BIT_CONNECTABLE = 1
		BIT_FAST_CONNECTABLE = 2
		BIT_DISCOVERABLE = 3
		BIT_BONDABLE = 4
		BIT_LINK_LEVEL_SECURITY = 5
		BIT_SECURE_SIMPLE_PAIRING = 6
		BIT_BREDR = 7
		BIT_HIGH_SPEED = 8
		BIT_LE = 9
		BIT_ADVERTISING = 10
		BIT_SECURE_CONNECTIONS = 11
		BIT_DEBUG_KEYS = 12
		BIT_PRIVACY = 13
		BIT_CONTROLLER_CONFIGURATION = 14
		BIT_STATIC_ADDRESS = 15
		BIT_PHY_CONFIGURATION = 16
		BIT_WIDEBAND_SPEECH = 17
	)

	mapBitToName := map[int]string{
		BIT_POWERED: "Powered",
		BIT_CONNECTABLE: "Connectable",
		BIT_FAST_CONNECTABLE: "Fast Connectable",
		BIT_DISCOVERABLE: "Discoverable",
		BIT_BONDABLE: "Bondable",
		BIT_LINK_LEVEL_SECURITY: "LinkSec",
		BIT_SECURE_SIMPLE_PAIRING: "SSP",
		BIT_BREDR: "BREDR",
		BIT_HIGH_SPEED: "High Speed",
		BIT_LE: "LE",
		BIT_ADVERTISING: "Advertising",
		BIT_SECURE_CONNECTIONS: "Secure Connections",
		BIT_DEBUG_KEYS: "Debug keys",
		BIT_PRIVACY: "Privacy",
		BIT_CONTROLLER_CONFIGURATION: "controller config",
		BIT_STATIC_ADDRESS: "Static Address",
		BIT_PHY_CONFIGURATION: "PHY Config",
		BIT_WIDEBAND_SPEECH: "Wideband Speech",
	}


	var flagStrs []string
	for bitIndex := 0; bitIndex < 18; bitIndex++ {
		cFlag := ((settings >> bitIndex) & 1) == 1
		if cFlag {
			flagStrs = append(flagStrs, mapBitToName[bitIndex])
		}
	}
	return strings.Join(flagStrs, ",")
}

/**
Packet Structures
=================

	Commands:

	0    4    8   12   16   22   24   28   31   35   39   43   47
	+-------------------+-------------------+-------------------+
	|  Command Code     |  Controller Index |  Parameter Length |
	+-------------------+-------------------+-------------------+
	|                                                           |

	Events:

	0    4    8   12   16   22   24   28   31   35   39   43   47
	+-------------------+-------------------+-------------------+
	|  Event Code       |  Controller Index |  Parameter Length |
	+-------------------+-------------------+-------------------+
	|                                                           |

All fields are in little-endian byte order (least significant byte first).
*/

const (
	EVENT_COMPLETE = 0x0001
	EVENT_NEW_SETTINGS = 0x0006
)

/**
Todo: implement robust comm with queue, events (current implementation should be good enough for poc)
 */
func (session *BTManagementSession) execBlocking(command uint16, controllerIndex uint16, parameters []byte) ([]byte,  error) {
	// Command Code = 16 bits -> uint16
	// Controller Index = 16 bits -> uint16
	// Parameter Length = 16 bits -> uint16

	var packetHeader = make([]byte, 6)
	binary.LittleEndian.PutUint16(packetHeader[0:], command)
	binary.LittleEndian.PutUint16(packetHeader[2:], controllerIndex)
	binary.LittleEndian.PutUint16(packetHeader[4:], uint16(len(parameters)))

	log.Printf("Command packet header: %s\n", hex.EncodeToString(packetHeader))

	packet := append(packetHeader, parameters ...)

	n, err := unix.Write(session.sockFd,  packet)
	if err != nil {
		return nil, err
	}
	log.Printf("Wrote %d bytes to the mgmt socket\n", n)
	if n != len(packet) {
		return nil, fmt.Errorf("Could not write all bytes to the mgmt socket\n. Wrote %d bytes", n)
	}

	var response = make([]byte, 100)
	readLen := 0

	const HEADER_LEN = 8 // Minimum response length

	// Todo: maybe implement timeout
	for readLen < HEADER_LEN {
		time.Sleep(10 * time.Millisecond)
		currReadLen, err := unix.Read(session.sockFd, response[readLen:])
		if err != nil {
			// E.g., resource temporary unavailable
			time.Sleep(100 * time.Millisecond)
			continue
		}

		log.Printf("Received %d bytes: %s\n", currReadLen,
			hex.EncodeToString(response[readLen:readLen + currReadLen]))
		readLen += currReadLen
	}

	if readLen >= HEADER_LEN {
		eventCode := binary.LittleEndian.Uint16(response[0:])
		resControllerIndex := binary.LittleEndian.Uint16(response[2:]) // controllerIndex
		_ = binary.LittleEndian.Uint16(response[4:]) // parameterLen

		if resControllerIndex != controllerIndex {
			log.Warnf("Unexpected controller index: %d\n", resControllerIndex)
		}

		// Todo: continue processing packets until event complete with the current cmd code
		switch eventCode {
		case EVENT_COMPLETE:
			log.Println("Command completed")

			eventCmdCode := binary.LittleEndian.Uint16(response[6:])
			commandResult := response[8] // 0 == SUCCESS

			log.Printf("Result: %d\n", commandResult)

			if eventCmdCode != command {
				log.Warnf("Unexpected event command code: %d\n", eventCmdCode)
			}

			cmdResult := response[9:readLen]
			log.Printf("Command result: %s\n", hex.EncodeToString(cmdResult))

			if eventCmdCode == command {
				return cmdResult, nil
			}
		case EVENT_NEW_SETTINGS:
			newSettings := response[6:6+4]
			log.Infof("NEW SETTINGS: %s (%s)", ParseSettings(newSettings), hex.EncodeToString(newSettings))
		default:
			log.Warnf("Unknown btmgmt event code: %d", eventCode)
		}
	}
	return nil, nil
}

func ReadLocalOOBData(controllerIndex uint16) (h192 [16]byte, r192 [16]byte, h256 [16]byte, r256 [16]byte, err error) {
	var ses *BTManagementSession
	ses, err = CreateSession()
	if err != nil {
		return
	}
	defer ses.Close()

	ses.SetController(controllerIndex)

	h192, r192, h256, r256, err = ses.ReadLocalOOBData()
	return
}

/**
Does not report errors currently, use btmon to see what is going on
 */
func AddRemoteOOBData(controllerIndex uint16,
	address string, addressType byte, h192 []byte,  r192 []byte,
	h256 []byte, r256 []byte) (err error) {

	var ses *BTManagementSession
	ses, err = CreateSession()
	if err != nil {
		return
	}
	defer ses.Close()

	ses.SetController(controllerIndex)

	ses.AddRemoteOOBData(address, addressType, h192, r192, h256, r256)
	return
}