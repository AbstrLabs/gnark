/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// constraintSystem represents a Groth16 like circuit
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type constraintSystem struct {

	// input wires
	public, secret []string

	// internal wires
	internal int

	// list of constraints in the form a * b == c
	// a,b and c being linear expressions
	constraints []compiled.R1C

	// Coefficients in the constraints
	coeffs         []big.Int      // list of unique coefficients.
	coeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	coeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)

	// Hints
	mHints            map[int]compiled.Hint // solver hints
	mHintsConstrained map[int]bool          // marks hints compiled.Variables constrained status

	logs      []compiled.LogEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo []compiled.LogEntry // list of logs storing information about R1C

	mDebug map[int]int // maps constraint ID to debugInfo id

	// keep track of Variable that are boolean constrained
	// in most of the cases, range checks, and, xor, or, toBinary, len(v) == 1
	// the only case where we don't have that is AssertIsBoolean, which can takes an arbitrarly large linear expression
	// mTBooleans represent the first, common case with a fast path
	// mLBooleans represent the second, slowest path. key is a hash code of the variable, contains all colliding linear expressions with same hash code
	mTBooleans map[compiled.Term]struct{}
	mLBooleans map[uint64][]compiled.Variable

	counters []Counter // statistic counters

	curveID   ecc.ID
	backendID backend.ID
}

// CompiledConstraintSystem ...
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public Variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() ecc.ID
	FrSize() int

	// ToHTML generates a human readable representation of the constraint system
	ToHTML(w io.Writer) error

	// GetCounters return the collected constraint counters, if any
	GetCounters() []compiled.Counter
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newConstraintSystem(curveID ecc.ID, backendID backend.ID, initialCapacity ...int) constraintSystem {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	cs := constraintSystem{
		coeffs:            make([]big.Int, 4),
		coeffsIDsLarge:    make(map[string]int),
		coeffsIDsInt64:    make(map[int64]int, 4),
		constraints:       make([]compiled.R1C, 0, capacity),
		mDebug:            make(map[int]int),
		mHints:            make(map[int]compiled.Hint),
		mHintsConstrained: make(map[int]bool),
		counters:          make([]Counter, 0),
		mTBooleans:        make(map[compiled.Term]struct{}),
		mLBooleans:        make(map[uint64][]compiled.Variable),
	}

	cs.coeffs[compiled.CoeffIdZero].SetInt64(0)
	cs.coeffs[compiled.CoeffIdOne].SetInt64(1)
	cs.coeffs[compiled.CoeffIdTwo].SetInt64(2)
	cs.coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	cs.coeffsIDsInt64[0] = compiled.CoeffIdZero
	cs.coeffsIDsInt64[1] = compiled.CoeffIdOne
	cs.coeffsIDsInt64[2] = compiled.CoeffIdTwo
	cs.coeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	// cs.public.variables = make([]Variable, 0)
	// cs.secret.variables = make([]Variable, 0)
	// cs.internal = make([]Variable, 0, capacity)
	cs.public = make([]string, 1)
	cs.secret = make([]string, 0)

	// by default the circuit is given a public wire equal to 1
	// cs.public.variables[0] = cs.newPublicVariable("one")
	cs.public[0] = "one"

	cs.curveID = curveID
	cs.backendID = backendID

	return cs
}

// NewHint initializes an internal variable whose value will be evaluated using
// the provided hint function at run time from the inputs. Inputs must be either
// variables or convertible to *big.Int.
//
// The hint function is provided at the proof creation time and is not embedded
// into the circuit. From the backend point of view, the variable returned by
// the hint function is equivalent to the user-supplied witness, but its actual
// value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (cs *constraintSystem) NewHint(f hint.Function, inputs ...interface{}) Variable {
	// create resulting wire
	r := cs.newInternalVariable()
	_, vID, _ := r[0].Unpack()

	// mark hint as unconstrained, for now
	cs.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.Variable, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		t := cs.constant(in).(compiled.Variable)
		hintInputs[i] = t.Clone() // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	cs.mHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

// bitLen returns the number of bits needed to represent a fr.Element
func (cs *constraintSystem) bitLen() int {
	return cs.curveID.Info().Fr.Bits
}

func (cs *constraintSystem) one() compiled.Variable {
	// TODO @gbotrel should we mark it as boolean?
	return compiled.Variable{compiled.Pack(0, compiled.CoeffIdOne, compiled.Public)}
}

// Term packs a Variable and a coeff in a Term and returns it.
// func (cs *constraintSystem) setCoeff(v Variable, coeff *big.Int) Term {
func (cs *constraintSystem) setCoeff(v compiled.Term, coeff *big.Int) compiled.Term {
	_, vID, vVis := v.Unpack()
	return compiled.Pack(vID, cs.coeffID(coeff), vVis)
}

// newR1C clones the linear expression associated with the Variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(_l, _r, _o Variable) compiled.R1C {
	l := _l.(compiled.Variable)
	r := _r.(compiled.Variable)
	o := _o.(compiled.Variable)

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l) > len(r) {
		l, r = r, l
	}

	return compiled.R1C{L: l.Clone(), R: r.Clone(), O: o.Clone()}
}

// NbConstraints enables circuit profiling and helps debugging
// It returns the number of constraints created at the current stage of the circuit construction.
func (cs *constraintSystem) NbConstraints() int {
	return len(cs.constraints)
}

// LinearExpression packs a list of Term in a LinearExpression and returns it.
func (cs *constraintSystem) LinearExpression(terms ...compiled.Term) compiled.Variable {
	res := make(compiled.Variable, len(terms))
	for i, args := range terms {
		res[i] = args
	}
	return res
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public||secret||internal||unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (cs *constraintSystem) reduce(l compiled.Variable) compiled.Variable {
	// ensure our linear expression is sorted, by visibility and by Variable ID
	if !sort.IsSorted(l) { // may not help
		sort.Sort(l)
	}

	var c big.Int
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&cs.coeffs[pcID], &cs.coeffs[ccID])
			l[i-1].SetCoeffID(cs.coeffID(&c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

func (cs *constraintSystem) coeffID64(v int64) int {
	if resID, ok := cs.coeffsIDsInt64[v]; ok {
		return resID
	} else {
		var bCopy big.Int
		bCopy.SetInt64(v)
		resID := len(cs.coeffs)
		cs.coeffs = append(cs.coeffs, bCopy)
		cs.coeffsIDsInt64[v] = resID
		return resID
	}
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *constraintSystem) coeffID(b *big.Int) int {

	// if the coeff is a int64 we have a fast path.
	if b.IsInt64() {
		return cs.coeffID64(b.Int64())
	}

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	bKey, _ := b.GobEncode()
	key := string(bKey)

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	if idx, ok := cs.coeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, bCopy)
	cs.coeffsIDsLarge[key] = resID
	return resID
}

func (cs *constraintSystem) addConstraint(r1c compiled.R1C, debugID ...int) {
	cs.constraints = append(cs.constraints, r1c)
	if len(debugID) > 0 {
		cs.mDebug[len(cs.constraints)-1] = debugID[0]
	}
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *constraintSystem) newInternalVariable() compiled.Variable {
	idx := cs.internal
	cs.internal++
	return compiled.Variable{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)}
}

// newPublicVariable creates a new public Variable
func (cs *constraintSystem) newPublicVariable(name string) compiled.Variable {
	idx := len(cs.public)
	cs.public = append(cs.public, name)
	return compiled.Variable{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)}
}

// newSecretVariable creates a new secret Variable
func (cs *constraintSystem) newSecretVariable(name string) compiled.Variable {
	idx := len(cs.secret)
	cs.secret = append(cs.secret, name)
	return compiled.Variable{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)}
}

// checkVariables perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (cs *constraintSystem) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(cs.secret)
	cptPublic := len(cs.public) - 1
	cptHints := len(cs.mHintsConstrained)

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic+1)
	publicConstrained[0] = true

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l compiled.Variable) {
		for _, t := range l {
			if t.CoeffID() == compiled.CoeffIdZero {
				// ignore zero coefficient, as it does not constraint the Variable
				// though, we may want to flag that IF the Variable doesn't appear else where
				continue
			}
			visibility := t.VariableVisibility()
			vID := t.WireID()

			switch visibility {
			case compiled.Public:
				if vID != 0 && !publicConstrained[vID] {
					publicConstrained[vID] = true
					cptPublic--
				}
			case compiled.Secret:
				if !secretConstrained[vID] {
					secretConstrained[vID] = true
					cptSecret--
				}
			case compiled.Internal:
				if b, ok := cs.mHintsConstrained[vID]; ok && !b {
					cs.mHintsConstrained[vID] = true
					cptHints--
				}
			}
		}
	}
	for _, r1c := range cs.constraints {
		processLinearExpression(r1c.L)
		processLinearExpression(r1c.R)
		processLinearExpression(r1c.O)

		if cptHints|cptSecret|cptPublic == 0 {
			return nil // we can stop.
		}

	}

	// something is a miss, we build the error string
	var sbb strings.Builder
	if cptSecret != 0 {
		sbb.WriteString(strconv.Itoa(cptSecret))
		sbb.WriteString(" unconstrained secret input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(secretConstrained) && cptSecret != 0; i++ {
			if !secretConstrained[i] {
				sbb.WriteString(cs.secret[i])
				sbb.WriteByte('\n')
				cptSecret--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptPublic != 0 {
		sbb.WriteString(strconv.Itoa(cptPublic))
		sbb.WriteString(" unconstrained public input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(publicConstrained) && cptPublic != 0; i++ {
			if !publicConstrained[i] {
				sbb.WriteString(cs.public[i])
				sbb.WriteByte('\n')
				cptPublic--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptHints != 0 {
		sbb.WriteString(strconv.Itoa(cptHints))
		sbb.WriteString(" unconstrained hints")
		sbb.WriteByte('\n')
		// TODO we may add more debug info here --> idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())

}

func (cs *constraintSystem) CurveID() ecc.ID {
	return cs.curveID
}

func (cs *constraintSystem) Backend() backend.ID {
	return cs.backendID
}

// markBoolean marks the Variable as boolean. Goal is to avoid adding multiple boolean constraint
// on the same variable (which was already previously boolean constrained)
func (cs *constraintSystem) markBoolean(v compiled.Variable) {
	v.AssertIsSet()
	// in most of the cases, range checks, and, xor, or, toBinary, len(v) == 1
	// the only case where we don't have that is AssertIsBoolean, which can takes an arbitrarly large linear expression
	if len(v) == 1 {
		cs.mTBooleans[v[0]] = struct{}{}
		return
	}

	_v := v.Clone()
	sort.Sort(_v)
	key := hashCode(_v)
	l, ok := cs.mLBooleans[key]
	if ok {
		// let's ensure we didn't already record it
		for _, i := range l {
			if i.Equal(_v) {
				return
			}
		}
	}
	cs.mLBooleans[key] = append(l, _v)
}

func (cs *constraintSystem) isBoolean(v compiled.Variable) bool {
	v.AssertIsSet()
	if len(v) == 1 {
		_, ok := cs.mTBooleans[v[0]]
		return ok
	}

	_v := v.Clone()
	sort.Sort(_v)
	key := hashCode(_v)
	l, ok := cs.mLBooleans[key]
	if !ok {
		return false
	}
	if ok {
		// let's ensure we didn't already record it
		for _, i := range l {
			if i.Equal(_v) {
				return true
			}
		}
	}
	return false
}

// TODO this is a weird hack in plonk frontend, must die.
func (cs *constraintSystem) unmarkBoolean(v compiled.Variable) {
	v.AssertIsSet()

	if len(v) == 1 {
		delete(cs.mTBooleans, v[0])
		return
	}

	_v := v.Clone()
	sort.Sort(_v)
	key := hashCode(_v)
	l, ok := cs.mLBooleans[key]
	if !ok {
		return // nothing to delete
	}

	for i, vi := range l {
		if vi.Equal(_v) {
			l[i] = l[len(l)-1]
			cs.mLBooleans[key] = l[:len(l)-1]
			return
		}
	}

}

// hashCode returns a fast hash of the linear expression; this is not collision resistant
// but two SORTED equal linear expressions will have equal hashes.
//
// pre conditions: l is sorted
func hashCode(v compiled.Variable) uint64 {
	hashcode := uint64(1)
	for i := 0; i < len(v); i++ {
		hashcode = hashcode*31 + uint64(v[i])
	}
	return hashcode
}
