package game

import "testing"

// KnownOnly keeps only known opcodes, so one that game reads and wire does not know never reaches Parse.
func TestReadsKnown(t *testing.T) {
	for op, o := range opcodes {
		if o.read != nil && !op.Known() {
			t.Errorf("%v %s is read, but wire does not know it", op, o.name)
		}
	}
}
