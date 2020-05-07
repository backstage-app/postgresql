package postgresql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type oid uint32
type format uint16

const (
	oidInt8   oid = 20
	oidFloat8 oid = 701
	oidJsonb  oid = 3802

	fieldSeverity1 = 0x53 //S
	fieldSeverity2 = 0x56 //V
	fieldCode      = 0x34 //C
	fieldMessage   = 0x4d //M

	formatText   format = 0x00
	formatBinary format = 0x01

	bindMessageType            = 0x42
	parseMessageType           = 0x50
	errorMessageType           = 0x45
	commandCompleteMessageType = 0x43
)

// CommandComplete (B)
// See https://www.postgresql.org/docs/8.2/protocol-message-formats.html
type commandCompleteMessage struct {
	// The command tag. This is usually a single word that identifies which SQL command was completed.
	tag string
}

// isCommandCompleteMessage returns true if data is CommandComplete message.
func isCommandCompleteMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != commandCompleteMessageType {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

func decodeCommandCompleteMessage(data []byte) (*commandCompleteMessage, error) {
	c := &commandCompleteMessage{}

	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return nil, fmt.Errorf("decodeParseMessage: %w", err)
	}

	c.tag = readNullTerminatedString(r)

	return c, nil
}

// Parse (F)
// See https://www.postgresql.org/docs/current/protocol-message-formats.html
type parseMessage struct {
	// The query string to be parsed.
	query string
	// The number of parameter data types specified (can be zero).
	// Note that this is not an indication of the number of parameters that might appear
	// in the query string, only the number that the frontend wants to prespecify types for.
	paramsNum uint16
	// Specifies the object ID of the parameters data type.
	// Placing a zero here is equivalent to leaving the type unspecified.
	oids []oid
}

// isParseMessage returns true if data is Parse message.
func isParseMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != parseMessageType {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

func decodeParseMessage(data []byte) (*parseMessage, error) {
	p := &parseMessage{}

	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return nil, fmt.Errorf("decodeParseMessage: %w", err)
	}

	// Skip name of the destination prepared statement
	skipNullTerminatedString(r)

	// Parsing query string
	p.query = readNullTerminatedString(r)

	// Parsing number of parameters
	paramsBuf := make([]byte, 2)
	n, err := r.Read(paramsBuf)
	if n < len(paramsBuf) {
		return nil, errors.New("decodeParseMessage: read to paramsBuf failed")
	}
	if err != nil {
		return nil, fmt.Errorf("decodeParseMessage: %w", err)
	}
	p.paramsNum = binary.BigEndian.Uint16(paramsBuf)

	// Parsing parameters OIDs
	oidBuf := make([]byte, 4)
	for i := uint16(1); i <= p.paramsNum; i++ {
		n, err = r.Read(oidBuf)
		if n < len(oidBuf) {
			return nil, errors.New("decodeParseMessage: read to oidBuf failed")
		}
		if err != nil {
			return nil, fmt.Errorf("decodeParseMessage: %w", err)
		}
		p.oids = append(p.oids, oid(binary.BigEndian.Uint32(oidBuf)))
	}

	return p, nil
}

// Bind (F)
// See https://www.postgresql.org/docs/current/protocol-message-formats.html
type bindMessage struct {
	statement  string
	formatsNum uint16
	valuesNum  uint16
	formats    []format
	values     [][]byte
}

func isBindMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != bindMessageType {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

func decodeBindMessage(data []byte) (*bindMessage, error) {
	b := &bindMessage{}

	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return nil, fmt.Errorf("decodeBindMessage: %w", err)
	}

	// Skip name of the destination portal
	skipNullTerminatedString(r)

	// Parse statement string
	b.statement = readNullTerminatedString(r)

	twoBytesBuf := make([]byte, 2)
	fourBytesBuf := make([]byte, 4)

	// Parsing number of parameters formats
	n, err := r.Read(twoBytesBuf)
	if n < len(twoBytesBuf) {
		return nil, errors.New("decodeBindMessage: read to formatsNumBuf failed")
	}
	if err != nil {
		return nil, fmt.Errorf("decodeBindMessage: %w", err)
	}

	b.formatsNum = binary.BigEndian.Uint16(twoBytesBuf)
	b.formats = make([]format, b.formatsNum)

	// Parsing each parameter format
	for i := uint16(0); i < b.formatsNum; i++ {
		n, err = r.Read(twoBytesBuf)
		if n < len(twoBytesBuf) {
			return nil, errors.New("decodeBindMessage: read to formatsBuf failed")
		}
		if err != nil {
			return nil, fmt.Errorf("decodeBindMessage: %w", err)
		}
		b.formats[i] = format(binary.BigEndian.Uint16(twoBytesBuf))
	}

	// Parsing number of parameters values
	n, err = r.Read(twoBytesBuf)
	if n < len(twoBytesBuf) {
		return nil, errors.New("decodeBindMessage: read to twoBytesBuf failed")
	}
	if err != nil {
		return nil, fmt.Errorf("decodeBindMessage: %w", err)
	}

	b.valuesNum = binary.BigEndian.Uint16(twoBytesBuf)
	b.values = make([][]byte, b.valuesNum)

	// Parsing parameters values
	for i := uint16(0); i < b.valuesNum; i++ {
		n, err = r.Read(fourBytesBuf)
		if n < len(fourBytesBuf) {
			return nil, errors.New("decodeBindMessage: read to fourBytesBuf failed")
		}
		if err != nil {
			return nil, fmt.Errorf("decodeBindMessage: %w", err)
		}

		valueBuf := make([]byte, binary.BigEndian.Uint32(fourBytesBuf))
		n, err = r.Read(valueBuf)
		if n < len(valueBuf) {
			return nil, errors.New("decodeBindMessage: read to formatsBuf failed")
		}
		if err != nil {
			return nil, fmt.Errorf("decodeBindMessage: %w", err)
		}

		b.values[i] = valueBuf
	}

	return b, nil
}

// ErrorResponse (B)
// See https://www.postgresql.org/docs/current/protocol-message-formats.html
type errorMessage struct {
	message string
}

func decodeErrorMessage(data []byte) *errorMessage {
	e := &errorMessage{}

	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return nil
	}

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			println(err)
		}
		switch b {
		case fieldMessage:
			e.message = readNullTerminatedString(r)
		default:
			skipNullTerminatedString(r)
		}
	}

	return e
}

func isErrorMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != errorMessageType {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

// isCancelRequest возвращает true если пакет является CancelRequest.
// CancelRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 16.
// Вторые 4 байта содержат код пакета, который всегда равен 80877102.
// Остальные 8 байт не представляют интереса для валидации пакета.
// Источник сообщения - клиент.
func isCancelRequestMessage(data []byte) bool {
	if len(data) != 16 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != 16 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(data[4:8])
	return requestCode == 80877102
}

// isSSLRequest возвращает true если пакет является SSLRequest.
// SSLRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 8.
// Вторые 4 байта содержат код пакета, который всегда равен 80877103.
// Источник сообщения - клиент.
func isSSLRequestMessage(data []byte) bool {
	if len(data) != 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != 8 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(data[4:8])
	return requestCode == 80877103
}

// isStartupMessage возвращает true если пакет является StartupMessage.
// StartupMessage не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета.
// Вторые 4 байта содержат версию протокола, которая всегда равна 196608.
// Источник сообщения - клиент.
func isStartupMessage(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != uint32(len(data)) {
		return false
	}
	protoVer := binary.BigEndian.Uint32(data[4:8])
	return protoVer == 196608 //v3.0
}

func isNoOpMessage(data []byte) bool {
	return len(data) == 1
}
