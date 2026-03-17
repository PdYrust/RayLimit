package privilege

// Status reports the current process privilege level.
type Status struct {
	EUID   int
	IsRoot bool
}

var euidFunc = getEUID

// Current reports the effective privilege level for the current process.
func Current() Status {
	euid := euidFunc()
	return Status{
		EUID:   euid,
		IsRoot: euid == 0,
	}
}
