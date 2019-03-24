package ice

import (
	"testing"
	"time"

	"github.com/gortc/stun"
)

func TestAgent_Timeout(t *testing.T) {
	t.Run("NoRetry", func(t *testing.T) {
		a, err := NewAgent()
		if err != nil {
			t.Fatal(err)
		}
		a.checklist = 0
		a.set = ChecklistSet{
			{
				Pairs: Pairs{
					{},
				},
			},
		}
		now := time.Now()
		at := &agentTransaction{
			id:          stun.NewTransactionID(),
			rto:         time.Millisecond * 100,
			start:       now,
			attempt:     1,
			maxAttempts: 1,
			pair:        getPairKey(&a.set[0].Pairs[0]),
		}
		a.t[at.id] = at
		a.collect(at.deadline)
		_, ok := a.t[at.id]
		if ok {
			t.Error("transaction should be removed")
		}
	})
}
