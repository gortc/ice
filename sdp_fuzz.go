// +build gofuzz

package ice

import "gortc.io/ice/sdp"

var c = new(sdp.Candidate)

func FuzzCandidate(data []byte) int {
	c.Reset()
	if err := sdp.ParseAttribute(data, c); err != nil {
		return 0
	}
	return 1
}
