package ice

import "testing"

func TestChecklist_Order(t *testing.T) {
	c := Checklist{
		Pairs: Pairs{
			{Priority: 1},
			{Priority: 10},
		},
	}
	c.Order()
	if c.Pairs[0].Priority == 1 {
		t.Error("pair with 1 priority should be second")
	}
}

func TestChecklist_ComputePriorities(t *testing.T) {
	c := Checklist{
		Pairs: Pairs{
			{
				Local:  Candidate{Priority: 102},
				Remote: Candidate{Priority: 91},
			},
			{
				Local:  Candidate{Priority: 100},
				Remote: Candidate{Priority: 50},
			},
			{
				Local:  Candidate{Priority: 103},
				Remote: Candidate{Priority: 93},
			},
			{
				Local:  Candidate{Priority: 104},
				Remote: Candidate{Priority: 94},
			},
			{
				Local:  Candidate{Priority: 101},
				Remote: Candidate{Priority: 90},
			},
		},
	}
	expectedControlled := []int64{
		390842024140, 214748365000, 399431958734, 403726926032, 386547056842,
	}
	expectedControlling := []int64{
		390842024141, 214748365001, 399431958735, 403726926033, 386547056843,
	}
	c.ComputePriorities(Controlled)
	for i, p := range c.Pairs {
		e := expectedControlled[i]
		if e != p.Priority {
			t.Errorf("controlled: [%d] %d (got) != %d (expected)",
				i, p.Priority, e,
			)
		}
	}
	c.ComputePriorities(Controlling)
	for i, p := range c.Pairs {
		e := expectedControlling[i]
		if e != p.Priority {
			t.Errorf("controlling: [%d] %d (got) != %d (expected)",
				i, p.Priority, e,
			)
		}
	}
}

func TestChecklist_Prune(t *testing.T) {
	c := Checklist{
		Pairs: Pairs{
			// TODO: Improve this
			{
				Local:  Candidate{},
				Remote: Candidate{},
			},
			{
				Local:  Candidate{},
				Remote: Candidate{},
			},
			{
				Local:  Candidate{},
				Remote: Candidate{},
			},
			{
				Local:  Candidate{},
				Remote: Candidate{},
			},
			{
				Local:  Candidate{},
				Remote: Candidate{},
			},
		},
	}
	c.Prune()
	if len(c.Pairs) != 1 {
		t.Error("unexpected result length")
	}
}
