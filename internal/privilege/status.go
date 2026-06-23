package privilege

// Status reports the current process privilege level.
type Status struct {
	EUID   int
	IsRoot bool
}

// Current reports the effective privilege level for the current process.
func Current() Status {
	return currentWith(getEUID)
}

// currentWith builds a Status from the effective user id returned by euidFn.
// It is the single place privilege semantics are derived, so production code
// and tests share one path. Injecting the lookup as a parameter avoids a
// mutable package-level global, keeping Current concurrency-safe.
func currentWith(euidFn func() int) Status {
	euid := euidFn()
	return Status{
		EUID:   euid,
		IsRoot: euid == 0,
	}
}
