package postgresql

import (
	"encoding/hex"
	"testing"
)

func decodeHexStream(t *testing.T, stream string) []byte {
	decoded, err := hex.DecodeString(stream)
	if err != nil {
		t.Fatalf("Failed to decode stream in %s", err)
	}
	return decoded
}

func Test_IsCancelRequest_Valid_Packet(t *testing.T) {

}

func Test_IsCancelRequest_InValid_Packet(t *testing.T) {

}

func Test_isSSLRequest_With_ValidPacket_Returns_True(t *testing.T) {
	if !isSSLRequestMessage(decodeHexStream(t, "0000000804d2162f")) {
		t.Error("isSSLRequest expected to return 'true', but 'false' returned")
	}
}

func Test_isSSLRequest_With_InvalidPacket_Returns_False(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(код пакета)
		"000000080fd2162f",
	}
	for _, invalidPacket := range invalidPackets {
		if isSSLRequestMessage(decodeHexStream(t, invalidPacket)) {
			t.Error("isSSLRequestMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_isStartupMessage_With_ValidPacket_Returns_True(t *testing.T) {
	data := decodeHexStream(t, "0000007000030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000")
	if !isStartupMessage(data) {
		t.Error("isStartupMessage expected to return 'true', but 'false' returned")
	}
}

func Test_isStartupMessage_With_InvalidPacket_Returns_False(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(версия протокола)
		"0000007001030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000",
	}
	for _, invalidPacket := range invalidPackets {
		if isStartupMessage(decodeHexStream(t, invalidPacket)) {
			t.Error("isStartupMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_isValidPacket_With_ValidPacket_Return_True(t *testing.T) {
	data := decodeHexStream(t, "52000000080000000053000000166170706c69636174696f6e5f6e616d6500005300000019636c69656e745f656e636f64696e670055544638005300000017446174655374796c650049534f2c204d4459005300000019696e74656765725f6461746574696d6573006f6e00530000001b496e74657276616c5374796c6500706f73746772657300530000001569735f737570657275736572006f66660053000000197365727665725f656e636f64696e67005554463800530000001a7365727665725f76657273696f6e00392e362e313000530000002573657373696f6e5f617574686f72697a6174696f6e0079615f74657374696e670053000000237374616e646172645f636f6e666f726d696e675f737472696e6773006f6e00530000001154696d655a6f6e6500555443004b0000000c00000bbe3d082f545a0000000549")
	if !isValidPacket(data) {
		t.Error("isValidPacket expected to return 'true', but 'false' returned")
	}
}

func Test_Build_With_ValidPacketChunks_Returns_Nil(t *testing.T) {
	chunks := []string{"52000000080000000053000000166170", "706c69636174696f6e5f6e616d6500005300000019636c69656e745f656e636f64696e670055544638005300000017446174655374796c650049534f2c204d4459005300000019696e74656765725f6461746574696d6573006f6e00530000001b496e74657276616c5374796c6500706f73746772657300530000001569735f737570657275736572006f66660053000000197365727665725f656e636f64696e67005554463800530000001a7365727665725f76657273696f6e00392e362e313000530000002573657373696f6e5f617574686f72697a6174696f6e0079615f74657374696e670053000000237374616e646172645f636f6e666f726d696e675f737472696e6773006f6e00530000001154696d655a6f6e6500555443004b0000000c00000bbe3d082f", "545a0000000549"}
	builder := packetBuilder{}

	var packet *packet
	for _, chunk := range chunks {
		packet, _ = builder.append(decodeHexStream(t, chunk), originFrontend)
	}
	if packet == nil {
		t.Error("append expected to return 'true', but 'false' returned")
	}
}

func Test_Messages_Returns_Correct_Number_Of_Messages(t *testing.T) {
	data := decodeHexStream(t, "500000000d00424547494e000000420000000c000000000000000045000000090000000000500000004b00555044415445207075626c69632e6576656e74666c6f775f6e6f6465732053455420706172616d73203d202431205748455245206964203d20243200000200000eda00000014420000002500000002000000010002000000055b2278225d000000080000000000000005000044000000065000450000000900000000015300000004")
	if !isValidPacket(data) {
		t.Error("isValidPacket expected to return 'true', but 'false' returned")
	}

	packet := packet{data, originFrontend}

	messages := packet.messages()
	if len(messages) != 2 {
		t.Errorf("Expected 2 queries in packet, but got %d", len(messages))
	}
}
