package postgresql

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	fieldSeverity1 = 0x53 //S
	fieldSeverity2 = 0x56 //V
	fieldCode      = 0x34 //C
	fieldMessage   = 0x4d //M

	parseMessageType = 0x50
	errorMessageType = 0x45
)

// Parse (F) at https://www.postgresql.org/docs/current/protocol-message-formats.html
type parseMessage struct {
	query string
}

func decodeParseMessage(data []byte) *parseMessage {
	p := &parseMessage{}

	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return nil
	}

	skipNullTerminatedString(r)
	p.query = readNullTerminatedString(r)

	return p
}

// ErrorResponse (B) at https://www.postgresql.org/docs/current/protocol-message-formats.html
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

// isParseMessage возвращает true если пакет является Parse.
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
