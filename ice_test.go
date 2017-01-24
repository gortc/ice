package ice

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/ernado/sdp"
)

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
		fmt.Println(c)
		p := candidateParser{
			buf: c.Value,
		}
		if err = p.parse(); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%+v\n", p.c)
	}

	// a=candidate:3862931549 1 udp 2113937151 192.168.220.128 56032
	//     foundation ---┘    |  |      |            |          |
	//   component id --------┘  |      |            |          |
	//      transport -----------┘      |            |          |
	//       priority ------------------┘            |          |
	//  conn. address -------------------------------┘          |
	//           port ------------------------------------------┘
}
