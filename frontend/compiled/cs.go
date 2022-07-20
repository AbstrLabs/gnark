package compiled

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/utils"
)

type Hint2 struct {
	ID     uint32
	Inputs [][]uint64
	Wires  []int
}

type HintsMap map[int]*Hint

type HintsMap2 map[int]*Hint2

func (m HintsMap) ToMap2() HintsMap2 {
	var m2 HintsMap2
	m2 = make(map[int]*Hint2, len(m))
	for k, v := range m {
		var v2 Hint2
		v2.ID = uint32(v.ID)
		v2.Inputs = make([][]uint64, len(v.Inputs))
		for i, e := range v.Inputs {
			x := e.(LinearExpression)
			v2.Inputs[i] = *(*[]uint64)(unsafe.Pointer(&x))
		}
		v2.Wires = v.Wires
		m2[k] = &v2

	}
	return m2
}

func (m *HintsMap) FromMap2(m2 HintsMap2) {
	*m = make(map[int]*Hint, len(m2))
	for k, v2 := range m2 {
		var v Hint
		v.ID = hint.ID(v2.ID)
		v.Inputs = make([]interface{}, len(v2.Inputs))
		for i, e := range v2.Inputs {
			v.Inputs[i] = *(*LinearExpression)(unsafe.Pointer(&e))
		}
		v.Wires = v2.Wires
		(*m)[k] = &v
	}
}

// ConstraintSystem contains common element between R1CS and ConstraintSystem
type ConstraintSystem struct {

	// schema of the circuit
	Schema *schema.Schema

	// number of wires
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// input wires names
	Public, Secret []string

	// logs (added with cs.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry

	// debug info contains stack trace (including line number) of a call to a cs.API that
	// results in an unsolved constraint
	DebugInfo []LogEntry

	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	Counters []Counter // TODO @gbotrel no point in serializing these

	MHints             HintsMap           // maps wireID to hint
	MHintsDependencies map[hint.ID]string // maps hintID to hint string identifier

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependncies for constraints in a level l are solved
	// in previous levels
	Levels [][]int

	CurveID ecc.ID
}

// GetNbVariables return number of internal, secret and public variables
func (cs *ConstraintSystem) GetNbVariables() (internal, secret, public int) {
	return cs.NbInternalVariables, cs.NbSecretVariables, cs.NbPublicVariables
}

// GetCounters return the collected constraint counters, if any
func (cs *ConstraintSystem) GetCounters() []Counter { return cs.Counters }

func (cs *ConstraintSystem) GetSchema() *schema.Schema { return cs.Schema }

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      string
	NbVariables   int
	NbConstraints int
	CurveID       ecc.ID
	BackendID     backend.ID
}

func (c Counter) String() string {
	return fmt.Sprintf("%s[%s] %s - %s: %d variables, %d constraints", c.BackendID, c.CurveID, c.From, c.To, c.NbVariables, c.NbConstraints)
}

func (cs *ConstraintSystem) Curve() ecc.ID {
	return cs.CurveID
}

func (cs *ConstraintSystem) AddDebugInfo(errName string, i ...interface{}) int {

	var l LogEntry

	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case LinearExpression:
			if len(v) > 1 {
				sbb.WriteString("(")
			}
			l.WriteVariable(v, &sbb)
			if len(v) > 1 {
				sbb.WriteString(")")
			}
		case string:
			sbb.WriteString(v)
		case Term:
			l.WriteTerm(v, &sbb)
		default:
			_v := utils.FromInterface(v)
			sbb.WriteString(_v.String())
		}
	}
	sbb.WriteByte('\n')
	debug.WriteStack(&sbb)
	l.Format = sbb.String()

	cs.DebugInfo = append(cs.DebugInfo, l)

	return len(cs.DebugInfo) - 1
}

// bitLen returns the number of bits needed to represent a fr.Element
func (cs *ConstraintSystem) BitLen() int {
	return cs.CurveID.Info().Fr.Bits
}
