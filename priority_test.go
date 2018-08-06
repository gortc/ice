package ice

import (
	"testing"

	"github.com/gortc/stun"
)

func TestPriority_GetFrom(t *testing.T) {
	m := new(stun.Message)
	var p Priority
	if err := p.GetFrom(m); err != stun.ErrAttributeNotFound {
		t.Error("unexpected error")
	}
	if err := m.Build(stun.BindingRequest, &p); err != nil {
		t.Error(err)
	}
	m1 := new(stun.Message)
	if _, err := m1.Write(m.Raw); err != nil {
		t.Error(err)
	}
	var p1 Priority
	if err := p1.GetFrom(m1); err != nil {
		t.Error(err)
	}
	if p1 != p {
		t.Error("not equal")
	}
	t.Run("IncorrectSize", func(t *testing.T) {
		m3 := new(stun.Message)
		m3.Add(stun.AttrPriority, make([]byte, 100))
		var p2 Priority
		if err := p2.GetFrom(m3); !stun.IsAttrSizeInvalid(err) {
			t.Error("should error")
		}
	})
}