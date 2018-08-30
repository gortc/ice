package internal

import "testing"

func TestMustParseNet(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("should panic")
		}
	}()
	MustParseNet("___")
}
