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

func TestPrivate(t *testing.T) {
	for _, name := range []string{"Login", "Account", "Characters"} {
		found := false
		for op, o := range opcodes {
			if o.name == name {
				found = true
				if !Private(op) {
					t.Errorf("%v %s is not private", op, name)
				}
			}
		}
		if !found {
			t.Errorf("no opcode named %s", name)
		}
	}
	for op := range private {
		if opcodes[op].name == "" {
			t.Errorf("%v is private, and not in the table", op)
		}
	}
}
