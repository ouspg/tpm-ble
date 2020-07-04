package btmgmt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
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
	CMD_READ_LOCAL_OOB_DATA = 0x0020
	CMD_ADD_REMOTE_OOB_DATA = 0x0021
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

func (session *BTManagementSession) AddRemoteOOBData(address []byte, addressType byte, h192 []byte,  r192 []byte,
	h256 []byte, r256 []byte) {

	parameters := make([]byte, 6 + 1 + 16 * 4)
	copy(parameters, address[:6])
	parameters[7] = addressType

	copy(parameters[8 + 16 * 0:8 + 16 * 1], h192)
	copy(parameters[8 + 16 * 1:8 + 16 * 2], r192)
	copy(parameters[8 + 16 * 2:8 + 16 * 3], h256)
	copy(parameters[8 + 16 * 3:8 + 16 * 4], r256)

	data, err := session.execBlocking(CMD_READ_LOCAL_OOB_DATA,  session.controllerIndex, parameters)
	if err != nil {
		return
	}
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

	n, err := unix.Write(session.sockFd, append(packetHeader, parameters ...))
	if err != nil {
		return nil, err
	}
	log.Printf("Wrote %d bytes to the mgmt socket\n", n)

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
		eventCmdCode := binary.LittleEndian.Uint16(response[6:]) // parameterLen

		if resControllerIndex != controllerIndex {
			log.Printf("Unexpected controller index: %d\n", resControllerIndex)
		}

		if eventCode == 0x0001 {
			log.Println("Command completed")
			commandResult := response[5] // 0 == SUCCESS
			log.Printf("Result: %d\n", commandResult)
		}

		eventData := response[9:readLen]
		log.Printf("Event data: %s\n", hex.EncodeToString(eventData))


		if eventCmdCode != command {
			log.Printf("Unexpected event command code: %d\n", eventCmdCode)
		}

		if eventCmdCode == command {
			return eventData, nil
		}
	}
	return nil, nil
}