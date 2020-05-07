package postgresql

import "bytes"

type packetBuilder struct {
	buf bytes.Buffer
}

// append ...
func (p *packetBuilder) append(b []byte, origin byte) (*packet, error) {
	if _, err := p.buf.Write(b); err != nil {
		return nil, err
	}
	if isValidPacket(p.buf.Bytes()) {
		packet := &packet{p.buf.Bytes(), origin}
		p.buf.Reset()
		return packet, nil
	}

	return nil, nil
}
