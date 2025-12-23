package kcp

type MsgType uint8
type TLVKey uint8
type KcpFlag uint8

const (
	// Magic header
	MagicHi = 0x4b43
	MagicLo = 0x5044

	// Valid types
	// Error
	MsgInvalid MsgType = 0

	// Lifecycle (Reserved 0 : 10)
	KcpHello   MsgType = 1
	KcpWelcome MsgType = 2
	KcpPing    MsgType = 3
	KcpPong    MsgType = 4

	// Request and responses (Reserved 10 : 20)
	KcpCommand MsgType = 11
	KcpOutput  MsgType = 12
	KcpError   MsgType = 13 // This is for execution errors based on commands

	// TLV Headers
	DiffieHelmanKey TLVKey = 0
	Command TLVKey = 1
	ClientData TLVKey = 2
	NewProxy TLVKey = 3
	
)

type KCPHeader struct {
	MagicBytes    uint16
	Version       uint8
	HeaderLength  uint8
	TransactionID uint32
	ClientID      uint32
	MessageType   uint8
	Flags         uint8
	Reserved      uint8
	BodyLength    uint8  // Length in 32 bit words
	AuthKey       uint64 // GUID
}

type TLV struct {
	Tag    MsgType
	Length uint16
	Value  []byte
}

// Private function for bit shifting to move flags around
func uint8BitMask(Index int) uint8 {
	return uint8(1) << uint8(Index) // Some guy on stack overflow explained this poorly.
}

// Load flags from an array of strings
func LoadFlags(Flags []string) KcpFlag {
	var Flag uint8
	for _, FlagString := range Flags {
		switch FlagString {
		case "NEW": // 10000000
			Flag |= uint8BitMask(7)
		case "ECR": // 01000000
			Flag |= uint8BitMask(6)
		case "TRC": // 00100000
			Flag |= uint8BitMask(5)
		case "STL": // 00010000
			Flag |= uint8BitMask(4)
		case "RTY": // 00001000
			Flag |= uint8BitMask(3)
		case "RCH": // 00000100
			Flag |= uint8BitMask(2)
		case "AUT": // 00000010
			Flag |= uint8BitMask(1)
		case "ARQ": // 00000001
			Flag |= uint8BitMask(0)
		}
	}
	return KcpFlag(Flag)
}
