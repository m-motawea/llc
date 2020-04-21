package llc

import (
	"encoding/binary"
	"errors"
)

type LSAP uint8
type Control []byte

const (
	// Min Length 3 bytes
	LLCMinLength int = 3
	// LSAP for SSAP & DSAP
	LSAPNull                       LSAP = 0x00
	LSAPIndividualLLCSublayerMgt   LSAP = 0x02
	LSAPSNAPathControl             LSAP = 0x04
	LSAPDoDIP                      LSAP = 0x06
	LSAPProWayLAN                  LSAP = 0x0E
	LSAPTexasInstruments           LSAP = 0x18
	LSAPBridgeSpanningTreeProtocol LSAP = 0x42
	LSAPEIARS511                   LSAP = 0x4E
	LSAPISIIP                      LSAP = 0x5E
	LSAPISO8208                    LSAP = 0x7E
	LSAPXNS                        LSAP = 0x80
	LSAPBACnetEthernet             LSAP = 0x82
	LSAPNestar                     LSAP = 0x86
	LSAPProWayLANIEC955            LSAP = 0x8E
	LSAPARPNET                     LSAP = 0x98
	LSAPRDE                        LSAP = 0xA6
	LSAPSNAPExtension              LSAP = 0xAA
	LSAPBanyanVines                LSAP = 0xBC
	LSAPNovellNetWare              LSAP = 0xE0
	LSAPIBMNetBIOS                 LSAP = 0xF0
	LSAPIBMLANManagement           LSAP = 0xF4
	LSAPIBMRemoteProgramLoad       LSAP = 0xF8
	LSAPUngermannBass              LSAP = 0xFA
	LSAPOSIProtocols               LSAP = 0xFE

	// Group DSDAP
	DSAPGroupLLCSublayerMgt LSAP = 0x03
	DSAPSNAPathControl      LSAP = 0x05
	DSAPIBMLANManagement    LSAP = 0xF5
	DSAPGlobal              LSAP = 0xFF //Broadcast
)

type LLCPDU struct {
	DSAP    LSAP
	SSAP    LSAP
	Control Control
	Packet  []byte
}

func (l *LLCPDU) length() int {
	pl := len(l.Packet)
	cl := len(l.Control)
	// 1 byte DSAP
	// 1 byte SSAP
	// 1 <= n <= 2 Control
	// N payload
	return 1 + 1 + cl + pl
}

func (l *LLCPDU) read(b []byte) (int, error) {
	temp := uint16(l.SSAP) | uint16(l.DSAP)<<8
	binary.BigEndian.PutUint16(b[:2], temp)
	n := len(l.Control)
	copy(b[2:2+n], l.Control)
	copy(b[2+n:], l.Packet)
	return len(b), nil
}

func (l *LLCPDU) MarshalBinary() ([]byte, error) {
	b := make([]byte, l.length())
	_, err := l.read(b)
	return b, err
}

func (l *LLCPDU) UnmarshalBinary(b []byte, ctrlLen int) error {
	if len(b) < LLCMinLength {
		return errors.New("invalid header length")
	}
	if ctrlLen > 2 || ctrlLen < 1 {
		return errors.New("invalid control length")
	}

	tempLSAPs := binary.BigEndian.Uint16(b[0:2])
	l.DSAP = LSAP((tempLSAPs & 0xFF00) >> 8)
	l.SSAP = LSAP(tempLSAPs & 0x00FF)
	l.Control = b[2 : 2+ctrlLen]
	l.Packet = b[2+ctrlLen:]
	return nil
}
