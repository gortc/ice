package ice

type Role byte

// Possible ICE Agent roles.
const (
	Controlling Role = iota
	Controlled
)
