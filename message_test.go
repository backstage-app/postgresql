package postgresql

import (
	"encoding/hex"
	"reflect"
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
	if len(messages) != 4 {
		t.Errorf("Expected 2 queries in packet, but got %d", len(messages))
	}
}

func Test_decodeParseMessage(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *parseMessage
		wantErr bool
	}{
		{
			"Sets_Correct_Parameters_Count_And_Oids",
			decodeHexStream(t, "500000005500555044415445207075626c69632e6576656e74666c6f775f6e6f64657320534554206c6174203d2024312c207a7a203d202432205748455245206964203d20243300000300000014000002bd00000014"),
			&parseMessage{"UPDATE public.eventflow_nodes SET lat = $1, zz = $2 WHERE id = $3", 3, []oid{oidInt8, oidFloat8, oidInt8}},
			false,
		},
		{
			"Sets_Correct_Parameters_Count_And_Oids",
			decodeHexStream(t, "50000000b40073656c656374204c2e7472616e73616374696f6e69643a3a766172636861723a3a626967696e74206173207472616e73616374696f6e5f69640a66726f6d2070675f636174616c6f672e70675f6c6f636b73204c0a7768657265204c2e7472616e73616374696f6e6964206973206e6f74206e756c6c0a6f726465722062792070675f636174616c6f672e616765284c2e7472616e73616374696f6e69642920646573630a6c696d69742031000000"),
			&parseMessage{"select L.transactionid::varchar::bigint as transaction_id\nfrom pg_catalog.pg_locks L\nwhere L.transactionid is not null\norder by pg_catalog.age(L.transactionid) desc\nlimit 1", 0, nil},
			false,
		},
		{
			"Sets_Correct_Parameters_Count_And_Oids",
			decodeHexStream(t, "50000000950073656c65637420636173650a20207768656e2070675f636174616c6f672e70675f69735f696e5f7265636f7665727928290a202020207468656e2024310a2020656c73650a2020202070675f636174616c6f672e747869645f63757272656e7428293a3a766172636861723a3a626967696e740a2020656e642061732063757272656e745f7478696400000100000014"),
			&parseMessage{"select case\n  when pg_catalog.pg_is_in_recovery()\n    then $1\n  else\n    pg_catalog.txid_current()::varchar::bigint\n  end as current_txid", 1, []oid{oidInt8}},
			false,
		},
		{
			"Sets_Correct_Parameters_Count_And_Oids",
			decodeHexStream(t, "500000007400555044415445207075626c69632e6576656e74666c6f775f6e6f6465732053455420706172616d73203d2024312c206c6174203d2024322c206c6e67203d2024332c207a7a203d202434205748455245206964203d20243500000500000eda0000001400000014000002bd00000014"),
			&parseMessage{"UPDATE public.eventflow_nodes SET params = $1, lat = $2, lng = $3, zz = $4 WHERE id = $5", 5, []oid{oidJsonb, oidInt8, oidInt8, oidFloat8, oidInt8}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeParseMessage(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeParseMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeParseMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeBindMessage(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *bindMessage
		wantErr bool
	}{
		{
			"x",
			decodeHexStream(t, "4200000016000000010001000100000004000003eb0000"),
			&bindMessage{"", 1, 1, []format{formatBinary}, [][]byte{{00, 00, 0x03, 0xeb}}},
			false,
		},
		{
			"x",
			decodeHexStream(t, "420000000c0000000000000000"),
			&bindMessage{"", 0, 0, []format{}, [][]byte{}},
			false,
		},
		{
			"x",
			decodeHexStream(t, "420000004c00000005000000010001000100010005000000027b7d00000008000000000000007b000000080000000000000159000000084074dc51eb851eb80000000800000000000000050000"),
			&bindMessage{"", 5, 5, []format{formatText, formatBinary, formatBinary, formatBinary, formatBinary}, [][]byte{{0x7b, 0x7d}, {00, 00, 00, 00, 00, 00, 00, 0x7b}, {00, 00, 00, 00, 00, 00, 0x01, 0x59}, {0x40, 0x74, 0xdc, 0x51, 0xeb, 0x85, 0x1e, 0xb8}, {00, 00, 00, 00, 00, 00, 00, 0x05}}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeBindMessage(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeBindMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeBindMessage() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isCommandCompleteMessage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"", decodeHexStream(t, "430000000d555044415445203100"), true},
		{"", decodeHexStream(t, "430000000b434f4d4d495400"), true},
		{"", decodeHexStream(t, "430000000953484f5700"), true},
		{"", decodeHexStream(t, "3100000004"), false},
		{"", decodeHexStream(t, "440000001800010000000e7265616420636f6d6d6974746564"), false},
		{"", decodeHexStream(t, "5a0000000549"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCommandCompleteMessage(tt.data); got != tt.want {
				t.Errorf("isCommandCompleteMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeCommandCompleteMessage(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *commandCompleteMessage
		wantErr bool
	}{
		{"", decodeHexStream(t, "430000000953484f5700"), &commandCompleteMessage{"SHOW"}, false},
		{"", decodeHexStream(t, "430000000b434f4d4d495400"), &commandCompleteMessage{"COMMIT"}, false},
		{"", decodeHexStream(t, "430000000a424547494e00"), &commandCompleteMessage{"BEGIN"}, false},
		{"", decodeHexStream(t, "430000000d53454c454354203500"), &commandCompleteMessage{"SELECT 5"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeCommandCompleteMessage(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeCommandCompleteMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeCommandCompleteMessage() got = %v, want %v", got, tt.want)
			}
		})
	}
}