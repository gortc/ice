package ice

import (
	"testing"

	"github.com/gortc/stun"
)

func TestControlled_GetFrom(t *testing.T) {
	m := new(stun.Message)
	var c Controlled
	if err := c.GetFrom(m); err != stun.ErrAttributeNotFound {
		t.Error("unexpected error")
	}
	if err := m.Build(stun.BindingRequest, &c); err != nil {
		t.Error(err)
	}
	m1 := new(stun.Message)
	if _, err := m1.Write(m.Raw); err != nil {
		t.Error(err)
	}
	var c1 Controlled
	if err := c1.GetFrom(m1); err != nil {
		t.Error(err)
	}
	if c1 != c {
		t.Error("not equal")
	}
	t.Run("IncorrectSize", func(t *testing.T) {
		m3 := new(stun.Message)
		m3.Add(stun.AttrICEControlled, make([]byte, 100))
		var c2 Controlled
		if err := c2.GetFrom(m3); err == nil {
			t.Error("should error")
		}
	})
}

func TestControlling_GetFrom(t *testing.T) {
	m := new(stun.Message)
	var c Controlling
	if err := c.GetFrom(m); err != stun.ErrAttributeNotFound {
		t.Error("unexpected error")
	}
	if err := m.Build(stun.BindingRequest, &c); err != nil {
		t.Error(err)
	}
	m1 := new(stun.Message)
	if _, err := m1.Write(m.Raw); err != nil {
		t.Error(err)
	}
	var c1 Controlling
	if err := c1.GetFrom(m1); err != nil {
		t.Error(err)
	}
	if c1 != c {
		t.Error("not equal")
	}
	t.Run("IncorrectSize", func(t *testing.T) {
		m3 := new(stun.Message)
		m3.Add(stun.AttrICEControlling, make([]byte, 100))
		var c2 Controlling
		if err := c2.GetFrom(m3); err == nil {
			t.Error("should error")
		}
	})
}