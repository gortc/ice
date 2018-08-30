package ice

import (
	"testing"
)

func TestHostCandidateGatherer_Candidates(t *testing.T) {
	g := NewHostCandidateGatherer(false)
	candidates, err := g.Candidates()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range candidates {
		c.Addr.Port = 34521 + i
		c.Base.Port = 34521 + i
		c.Foundation = Foundation(&c, Addr{})
		t.Logf("%s: 0x%x", c.Addr, c.Foundation)
		t.Logf(" IsLinkLocalMulticast: %v", c.Addr.IP.IsLinkLocalMulticast())
		t.Logf(" IsLinkLocalUnicast: %v", c.Addr.IP.IsLinkLocalUnicast())
		t.Logf(" IsInterfaceLocalMulticast: %v", c.Addr.IP.IsInterfaceLocalMulticast())
		if !c.Addr.Equal(c.Base) {
			t.Error("base not equal")
		}
	}
}
