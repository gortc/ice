package sdp

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/gortc/ice/candidate"
	"github.com/gortc/sdp"
)

func TestAttributes_Value(t *testing.T) {
	a := Attributes{
		{Key: []byte("key"), Value: []byte("value")},
	}
	t.Run("Get key", func(t *testing.T) {
		v := a.Value([]byte("key"))
		if !bytes.Equal(v, []byte("value")) {
			t.Error("attr[key] not equal to value")
		}
	})
	t.Run("Nil", func(t *testing.T) {
		v := a.Value([]byte("1"))
		if v != nil {
			t.Error("attr[1] should be nil")
		}
	})
}

func TestAttribute_String(t *testing.T) {
	for _, tt := range []struct {
		in  Attribute
		out string
	}{
		{Attribute{}, "<nil>:<nil>"},
		{Attribute{Key: []byte("k")}, "k:<nil>"},
		{Attribute{Value: []byte("v")}, "<nil>:v"},
		{Attribute{Key: []byte("k"), Value: []byte("v")}, "k:v"},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.out != tt.in.String() {
				t.Errorf("%q", tt.in.String())
			}
		})
	}
}

func TestAttributes_Equal(t *testing.T) {
	for _, tt := range []struct {
		name  string
		a, b  Attributes
		equal bool
	}{
		{
			name:  "Blank",
			equal: true,
		},
		{
			name: "Equal",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
			},
			b: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
			},
			equal: true,
		},
		{
			name: "Length",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
			},
			equal: false,
		},
		{
			name: "Value",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
			},
			b: Attributes{
				{Key: []byte{1}, Value: []byte{3}},
			},
			equal: false,
		},
		{
			name: "Key",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{3}},
			},
			b: Attributes{
				{Key: []byte{2}, Value: []byte{3}},
			},
			equal: false,
		},
		{
			name: "Values",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
				{Key: []byte{2}, Value: []byte{5}},
			},
			b: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
			},
			equal: false,
		},
		{
			name: "ValuesB",
			a: Attributes{
				{Key: []byte{2}, Value: []byte{1}},
			},
			b: Attributes{
				{Key: []byte{1}, Value: []byte{2}},
				{Key: []byte{2}, Value: []byte{1}},
			},
			equal: false,
		},
		{
			name: "ValuesDuplicate",
			a: Attributes{
				{Key: []byte{1}, Value: []byte{1}},
				{Key: []byte{1}, Value: []byte{1}},
			},
			b: Attributes{
				{Key: []byte{2}, Value: []byte{1}},
				{Key: []byte{1}, Value: []byte{1}},
			},
			equal: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a.Equal(tt.b) != tt.equal {
				t.Error("check failed")
			}
		})
	}
}

func TestCandidate_Reset(t *testing.T) {
	b := Candidate{
		Foundation:  3862931549,
		ComponentID: 1,
		Priority:    2113937151,
		ConnectionAddress: Address{
			IP: net.ParseIP("192.168.220.128"),
		},
		Port:        56032,
		Type:        candidate.Host,
		NetworkCost: 50,
		Attributes: Attributes{
			Attribute{
				Key:   []byte("alpha"),
				Value: []byte("beta"),
			},
		},
	}
	c := Candidate{
		Foundation:  3862931549,
		ComponentID: 1,
		Priority:    2113937151,
		ConnectionAddress: Address{
			IP: net.ParseIP("192.168.220.128"),
		},
		Port:        56032,
		Type:        candidate.Host,
		NetworkCost: 50,
		Attributes: Attributes{
			Attribute{
				Key:   []byte("alpha"),
				Value: []byte("beta"),
			},
		},
	}
	c.Reset()
	if c.Equal(&b) {
		t.Fatal("should not equal")
	}
}

func TestCandidate_Equal(t *testing.T) {
	for _, tt := range []struct {
		name  string
		a, b  Candidate
		equal bool
	}{
		{
			name:  "Blank",
			a:     Candidate{},
			b:     Candidate{},
			equal: true,
		},
		{
			name:  "Attributes",
			a:     Candidate{},
			b:     Candidate{Attributes: Attributes{{}}},
			equal: false,
		},
		{
			name:  "Port",
			a:     Candidate{},
			b:     Candidate{Port: 10},
			equal: false,
		},
		{
			name:  "Priority",
			a:     Candidate{},
			b:     Candidate{Priority: 10},
			equal: false,
		},
		{
			name:  "Transport",
			a:     Candidate{Transport: candidate.TransportUDP},
			b:     Candidate{Transport: candidate.TransportUnknown},
			equal: false,
		},
		{
			name:  "TransportValue",
			a:     Candidate{},
			b:     Candidate{TransportValue: []byte("v")},
			equal: false,
		},
		{
			name:  "Foundation",
			a:     Candidate{},
			b:     Candidate{Foundation: 1},
			equal: false,
		},
		{
			name:  "ComponentID",
			a:     Candidate{},
			b:     Candidate{ComponentID: 1},
			equal: false,
		},
		{
			name:  "NetworkCost",
			a:     Candidate{},
			b:     Candidate{NetworkCost: 1},
			equal: false,
		},
		{
			name:  "Generation",
			a:     Candidate{},
			b:     Candidate{Generation: 1},
			equal: false,
		},
		{
			name:  "Type",
			a:     Candidate{},
			b:     Candidate{Type: 1},
			equal: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a.Equal(&tt.b) != tt.equal {
				t.Error("equality test failed")
			}
		})

	}
}

func loadData(tb testing.TB, name string) []byte {
	name = filepath.Join("testdata", name)
	f, err := os.Open(name)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			tb.Fatal(errClose)
		}
	}()
	v, err := ioutil.ReadAll(f)
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func TestConnectionAddress(t *testing.T) {
	data := loadData(t, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s {
		p := candidateParser{
			c:   new(Candidate),
			buf: c.Value,
		}
		if err = p.parse(); err != nil {
			t.Fatal(err)
		}
	}

	// a=candidate:3862931549 1 udp 2113937151 192.168.220.128 56032
	//     foundation ---┘    |  |      |            |          |
	//   component id --------┘  |      |            |          |
	//      transport -----------┘      |            |          |
	//       priority ------------------┘            |          |
	//  conn. address -------------------------------┘          |
	//           port ------------------------------------------┘
}

func TestParse(t *testing.T) {
	data := loadData(t, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []Candidate{
		{
			Foundation:  3862931549,
			ComponentID: 1,
			Priority:    2113937151,
			ConnectionAddress: Address{
				IP: net.ParseIP("192.168.220.128"),
			},
			Port:        56032,
			Type:        candidate.Host,
			NetworkCost: 50,
			Attributes: Attributes{
				Attribute{
					Key:   []byte("alpha"),
					Value: []byte("beta"),
				},
			},
		},
	}
	tCases := []struct {
		input    []byte
		expected Candidate
	}{
		{s[0].Value, expected[0]}, // 0
	}

	for i, c := range tCases {
		parser := candidateParser{
			buf: c.input,
			c:   new(Candidate),
		}
		if err := parser.parse(); err != nil {
			t.Errorf("[%d]: unexpected error %s",
				i, err,
			)
		}
		if !c.expected.Equal(parser.c) {
			t.Errorf("[%d]: %v != %v (exp)",
				i, parser.c, c.expected,
			)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	data := loadData(b, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	value := s[0].Value
	p := candidateParser{
		c: new(Candidate),
	}
	for i := 0; i < b.N; i++ {
		p.buf = value
		if err = p.parse(); err != nil {
			b.Fatal(err)
		}
		p.c.Reset()
	}
}

func BenchmarkParseIP(b *testing.B) {
	v := []byte("127.0.0.2")
	var (
		result = make([]byte, net.IPv4len)
	)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result = parseIP(result, v)
		result = result[:net.IPv4len]
	}
}

func TestParseAttribute(t *testing.T) {
	data := loadData(t, "candidates_ex1.sdp")
	s, err := sdp.DecodeSession(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []Candidate{
		{
			Foundation:  3862931549,
			ComponentID: 1,
			Priority:    2113937151,
			ConnectionAddress: Address{
				IP: net.ParseIP("192.168.220.128"),
			},
			Port:        56032,
			Type:        candidate.Host,
			NetworkCost: 50,
			Attributes: Attributes{
				Attribute{
					Key:   []byte("alpha"),
					Value: []byte("beta"),
				},
			},
		},
	}
	tCases := []struct {
		input    []byte
		expected Candidate
	}{
		{s[0].Value, expected[0]}, // 0
	}

	for i, tc := range tCases {
		c := new(Candidate)
		if err := ParseAttribute(tc.input, c); err != nil {
			t.Errorf("[%d]: unexpected error %s",
				i, err,
			)
		}
		if !tc.expected.Equal(c) {
			t.Errorf("[%d]: %v != %v (exp)",
				i, c, tc.expected,
			)
		}
	}

}

func TestAddressType_String(t *testing.T) {
	for _, tt := range []struct {
		in  AddressType
		out string
	}{
		{in: AddressIPv4, out: "IPv4"},
		{in: AddressIPv6, out: "IPv6"},
		{in: AddressFQDN, out: "FQDN"},
		{in: AddressFQDN + 10, out: "unknown"},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Errorf("%q", tt.in.String())
			}
		})
	}
}

func TestConnectionAddress_Equal(t *testing.T) {
	for _, tt := range []struct {
		name  string
		a, b  Address
		equal bool
	}{
		{
			name:  "Blank",
			equal: true,
		},
		{
			name: "HostNonFQDN",
			b: Address{
				Host: []byte{1},
			},
			equal: true,
		},
		{
			name: "HostFQDN",
			a: Address{
				Type: AddressFQDN,
			},
			b: Address{
				Type: AddressFQDN,
				Host: []byte{1},
			},
			equal: false,
		},
		{
			name: "IP",
			b: Address{
				IP: net.IPv4(1, 0, 0, 1),
			},
			equal: false,
		},
		{
			name: "Type",
			b: Address{
				Type: AddressIPv6,
			},
			equal: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a.Equal(tt.b) != tt.equal {
				t.Error("equality test failed")
			}
		})

	}
}

func TestConnectionAddress_String(t *testing.T) {
	for _, tt := range []struct {
		in  Address
		out string
	}{
		{
			in:  Address{},
			out: "<nil>",
		},
		{
			in: Address{
				Type: AddressFQDN,
				Host: []byte("gortc.io"),
			},
			out: "gortc.io",
		},
		{
			in: Address{
				IP: net.IPv4(127, 0, 0, 1),
			},
			out: "127.0.0.1",
		},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Errorf("%q", tt.in)
			}
		})
	}
}

func TestCandidateType_String(t *testing.T) {
	for _, tt := range []struct {
		in  candidate.Type
		out string
	}{
		{in: candidate.PeerReflexive, out: "peer-reflexive"},
		{in: candidate.Relayed + 10, out: "unknown"},
	} {
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Errorf("%q", tt.in.String())
			}
		})
	}
}
