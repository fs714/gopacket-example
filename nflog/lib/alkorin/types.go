package alkorin

import (
	"syscall"
)

type nlmsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type nlmsgerr struct {
	Error  int32    /* Negative errno or 0 for acknowledgements */
	Header nlmsghdr /* Message header that caused the error */
}

type nfgenmsg struct {
	Family  uint8
	Version uint8
	ResId   uint16 // BigEndian
}

type nfattr struct {
	Len  uint16
	Type uint16
}

type nfulnl_msg_config_cmd struct {
	Command uint8
}

type nfulnl_msg_config_mode struct {
	CopyRange uint32 // BigEndian
	CopyMode  uint8
	_pad      uint8
}

type nfConfigCmd struct {
	Header  nlmsghdr
	Message nfgenmsg
	Attr    nfattr
	Cmd     nfulnl_msg_config_cmd
}

type nfConfigMode struct {
	Header  nlmsghdr
	Message nfgenmsg
	Attr    nfattr
	Mode    nfulnl_msg_config_mode
}

type nflogHeader struct {
	Family  uint8
	Version uint8
	ResId   uint16 // BigEndian
}

type nflogTlv struct {
	Len  uint16
	Type uint16
}

type HwAddr struct {
	Len  uint16
	Pad  uint16
	Addr [8]uint8
}

func newNFConfigCmd(cmd uint8, family uint8, resId uint16) nfConfigCmd {
	return nfConfigCmd{
		Header: nlmsghdr{
			Len:   25,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
			Seq:   0,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  family,
			Version: NFNETLINK_V0,
			ResId:   htons(resId),
		},
		Attr: nfattr{
			Len:  5,
			Type: NFULA_CFG_CMD,
		},
		Cmd: nfulnl_msg_config_cmd{
			Command: cmd,
		},
	}
}

func newNFConfigMode(resId uint16, copyLen uint16) nfConfigMode {
	return nfConfigMode{
		Header: nlmsghdr{
			Len:   30,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
			Seq:   0,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  syscall.AF_UNSPEC,
			Version: NFNETLINK_V0,
			ResId:   htons(resId),
		},
		Attr: nfattr{
			Len:  10,
			Type: NFULA_CFG_MODE,
		},
		Mode: nfulnl_msg_config_mode{
			CopyMode:  NFULNL_COPY_PACKET,
			CopyRange: htonl(uint32(copyLen)),
		},
	}
}

type Msg struct {
	Group        uint16
	Family       uint8
	Prefix       string
	Mark         *uint32
	UID          *uint32
	GID          *uint32
	InDev        *uint32
	OutDev       *uint32
	HwAddr       *HwAddr
	MacLayerType *uint16
	MacLayer     []byte
	Payload      []byte
	Sec          *int64
	Usec         *int64
}
