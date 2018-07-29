package ice

import "github.com/gortc/stun"

// iceControlAttribute is common helper for ICE-{CONTROLLED,CONTROLLING}
// attributes.
type iceControlAttribute uint64

const iceControlSize = 8 // 64 bit

// AddToAs adds iceControlAttribute value to m as t attribute.
func (a iceControlAttribute) AddToAs(m *stun.Message, t stun.AttrType) error {
	v := make([]byte, iceControlSize)
	bin.PutUint64(v, uint64(a))
	m.Add(t, v)
	return nil
}

// GetFromAs decodes iceControlAttribute attribute value in message
// getting it as for t type.
func (a *iceControlAttribute) GetFromAs(m *stun.Message, t stun.AttrType) error {
	v, err := m.Get(t)
	if err != nil {
		return err
	}
	if len(v) != iceControlSize {
		return &stun.AttrLengthErr{
			Attr:     t,
			Expected: iceControlSize,
			Got:      len(v),
		}
	}
	*a = iceControlAttribute(bin.Uint64(v))
	return nil
}

// Controlled represents ICE-CONTROLLED attribute.
type Controlled uint64

// AddTo adds ICE-CONTROLLED to message.
func (c Controlled) AddTo(m *stun.Message) error {
	return iceControlAttribute(c).AddToAs(m, stun.AttrICEControlled)
}

// GetFrom decodes ICE-CONTROLLED from message.
func (c *Controlled) GetFrom(m *stun.Message) error {
	return (*iceControlAttribute)(c).GetFromAs(m, stun.AttrICEControlled)
}

// Controlling represents ICE-CONTROLLING attribute.
type Controlling uint64

// AddTo adds ICE-CONTROLLING to message.
func (c Controlling) AddTo(m *stun.Message) error {
	return iceControlAttribute(c).AddToAs(m, stun.AttrICEControlling)
}

// GetFrom decodes ICE-CONTROLLING from message.
func (c *Controlling) GetFrom(m *stun.Message) error {
	return (*iceControlAttribute)(c).GetFromAs(m, stun.AttrICEControlling)
}
