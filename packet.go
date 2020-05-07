package postgresql

import (
	"encoding/binary"
)

const (
	minPacketLen   = 5
	originBackend  = 0x01
	originFrontend = 0x02
)

type packet struct {
	Payload []byte
	Origin  byte
}

func (p *packet) messages() []interface{} {
	if isStartupMessage(p.Payload) || isSSLRequestMessage(p.Payload) || isCancelRequestMessage(p.Payload) {
		return nil
	}

	var offset uint32
	var messages []interface{}
	for {
		if len(p.Payload[offset:]) < minPacketLen {
			break
		}

		pktLen := binary.BigEndian.Uint32(p.Payload[offset+1:offset+minPacketLen]) + 1
		packet := p.Payload[offset : offset+pktLen]
		offset = offset + pktLen

		if p.Origin == originFrontend && isParseMessage(packet) {
			msg, _ := decodeParseMessage(packet)
			messages = append(messages, msg)
			continue
		}
		if p.Origin == originFrontend && isBindMessage(packet) {
			msg, _ := decodeBindMessage(packet)
			messages = append(messages, msg)
			continue
		}
		if p.Origin == originBackend && isErrorMessage(packet) {
			messages = append(messages, decodeErrorMessage(packet))
			continue
		}
		if p.Origin == originBackend && isCommandCompleteMessage(packet) {
			msg, _ := decodeCommandCompleteMessage(packet)
			messages = append(messages, msg)
			continue
		}
	}

	return messages
}

// isValidPacket возвращает true если data это валидный пакет.
// Учитывается, что data может состоять как из одного пакета, так и из множества пакетов.
// В последнем случае data валиден если каждый пакет из data валиден.
func isValidPacket(data []byte) bool {
	if isNoOpMessage(data) {
		return true
	}

	if len(data) < minPacketLen {
		return false
	}

	// Эти типы сообщений в заголовке не содержат байт типа пакета, поэтому их нужно обработать сразу
	if isStartupMessage(data) || isSSLRequestMessage(data) || isCancelRequestMessage(data) {
		return true
	}

	var offset uint32
	for {
		// Если длина остатка пакета меньше пяти, то это однозначно неверный пакет.
		// Минимальный пакет состоит из типа пакета(1 байт) и длины пакета(4 байта).
		if len(data[offset:]) < minPacketLen {
			break
		}
		pktLen := binary.BigEndian.Uint32(data[offset+1:offset+minPacketLen]) + 1
		// Если ожидаемая длина остатка пакета совпадает с фактической длиной остатка пакета,
		// то либо Payload это всего один пакет и он валидный, либо цикл дошел уже до последнего пакета в Payload и
		// это автоматически значит, что все пакеты в Payload так же валидны.
		if pktLen == uint32(len(data[offset:])) {
			return true
		}
		// Ожидаемая длина пакета не может быть больше фактической длины пакета.
		if pktLen > uint32(len(data[offset:])) {
			break
		}
		offset = offset + pktLen
	}
	return false
}
