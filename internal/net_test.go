package internal

import "testing"

func TestMustParseNet(t *testing.T) {
	t.Run("Negative", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("should panic")
			}
		}()
		MustParseNet("___")
	})
	t.Run("Positive", func(t *testing.T) {
		net := MustParseNet("0.0.0.0/0")
		if net.String() != "0.0.0.0/0" {
			t.Errorf("bad net %s", net)
		}
	})
}
