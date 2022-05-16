/*
Copyright © 2021 ConsenSys Software Inc.

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

package test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/utils"
	"github.com/stretchr/testify/require"

	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/kylelemons/godebug/pretty"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	*require.Assertions
	compiled map[string]frontend.CompiledConstraintSystem // cache compilation
}

// NewAssert returns an Assert helper embedding a testify/require object for convenience
//
// The Assert object caches the compiled circuit:
//
// the first call to assert.ProverSucceeded/Failed will compile the circuit for n curves, m backends
// and subsequent calls will re-use the result of the compilation, if available.
func NewAssert(t *testing.T) *Assert {
	return &Assert{t, require.New(t), make(map[string]frontend.CompiledConstraintSystem)}
}

// Run runs the test function fn as a subtest. The subtest is parametrized by
// the description strings descs.
func (assert *Assert) Run(fn func(assert *Assert), descs ...string) {
	desc := strings.Join(descs, "/")
	assert.t.Run(desc, func(t *testing.T) {
		// TODO(ivokub): access to compiled cache is not synchronized -- running
		// the tests in parallel will result in undetermined behaviour. A better
		// approach would be to synchronize compiled and run the tests in
		// parallel for a potential speedup.
		assert := &Assert{t, require.New(t), assert.compiled}
		fn(assert)
	})
}

// Log logs using the test instance logger.
func (assert *Assert) Log(v ...interface{}) {
	assert.t.Log(v...)
}

type LibsnarkCSMetadata struct {
	nPrimaryInput   int
	nAuxiliaryInput int
	nConstraints    int
	// Number of secret variables in sample run file
	nSecretInput int
}

type ConstructR1CHelper struct {
	LibsnarkCSMetadata
	coeffs    []fr.Element
	coeffsSet map[fr.Element]int
}

func loadLibsnarkCS(filename string) (ret cs.R1CS) {
	f, _ := os.Open(filename)
	defer f.Close()

	var nPrimaryInput int
	var nAuxiliaryInput int
	var nSecretInput int
	var nConstraints int

	_, _ = fmt.Fscanf(f, "%d\n", &nPrimaryInput)
	_, _ = fmt.Fscanf(f, "%d\n", &nAuxiliaryInput)
	_, _ = fmt.Fscanf(f, "%d\n", &nSecretInput)
	_, _ = fmt.Fscanf(f, "%d\n", &nConstraints)

	fmt.Println("number of primary input: ", nPrimaryInput)
	fmt.Println("number of auxiliary input: ", nAuxiliaryInput)
	fmt.Println("number of constraints: ", nConstraints)
	helper := &ConstructR1CHelper{}
	helper.nPrimaryInput = nPrimaryInput
	helper.nAuxiliaryInput = nAuxiliaryInput
	helper.nConstraints = nConstraints
	helper.nSecretInput = nSecretInput
	helper.coeffsSet = make(map[fr.Element]int)
	_ = getCoeffID(fr.NewElement(0), helper)

	constraints := make([]compiled.R1C, nConstraints)
	for i := 0; i < nConstraints; i++ {
		constraints[i] = loadConstraint(f, helper)
	}

	fmt.Println("***************")
	pretty.Print(constraints)
	ret.NbPublicVariables = helper.nPrimaryInput
	ret.NbSecretVariables = helper.nSecretInput
	ret.NbInternalVariables = helper.nAuxiliaryInput - ret.NbSecretVariables
	ret.Levels = make([][]int, nConstraints)
	for i := 0; i < nConstraints; i++ {
		ret.Levels[i] = []int{i}
	}
	ret.Constraints = constraints
	ret.Coefficients = helper.coeffs
	ret.Schema = &schema.Schema{}
	return
}

func loadConstraint(r io.Reader, helper *ConstructR1CHelper) (ret compiled.R1C) {
	ret.L = loadLinearCombination(r, helper)
	ret.R = loadLinearCombination(r, helper)
	ret.O = loadLinearCombination(r, helper)
	return
}

func loadLinearCombination(r io.Reader, helper *ConstructR1CHelper) (ret compiled.Variable) {
	var nTerms int
	var index int
	coeff := make([]byte, 32)
	coeff2 := make([]uint64, 4)

	ret.IsBoolean = new(bool)
	*ret.IsBoolean = false

	_, _ = fmt.Fscanf(r, "%d\n", &nTerms)
	fmt.Println("=======")
	ret.LinExp = make([]compiled.Term, nTerms-1)
	for i := 0; i < nTerms; i++ {
		if i == 0 {
			_, _ = fmt.Fscanf(r, "%d\n", &index)
			if index != 0 {
				panic("expect index to be 0")
			}
			r.Read(coeff)
			xi := new(big.Int).SetBytes(coeff)
			if xi.Sign() != 0 {
				panic("expect first coeff to be 0")
			}
		} else {
			_, _ = fmt.Fscanf(r, "%d\n", &index)
			r.Read(coeff)

			var coeff3 fr.Element
			for j := 0; j < 4; j++ {
				coeff2[j] = binary.LittleEndian.Uint64(coeff[j*8 : (j+1)*8])
				coeff3[j] = coeff2[j]
			}
			fmt.Println("------")
			fmt.Println(index)
			fmt.Println(&coeff3)
			// libsnark x1 -> gnark x0
			ret.LinExp[i-1] = encodeTerm(index-1, coeff3, helper)
		}
	}
	return
}

func encodeTerm(index int, coeff fr.Element, helper *ConstructR1CHelper) (ret compiled.Term) {
	ret.SetWireID(index)
	ret.SetCoeffID(getCoeffID(coeff, helper))
	ret.SetVariableVisibility(getVariableVisibility(index, helper))
	return
}

func getCoeffID(coeff fr.Element, helper *ConstructR1CHelper) int {
	index, exist := helper.coeffsSet[coeff]
	if exist {
		return index
	}
	helper.coeffs = append(helper.coeffs, coeff)
	index = len(helper.coeffs) - 1
	helper.coeffsSet[coeff] = index
	return index
}

func getVariableVisibility(index int, helper *ConstructR1CHelper) schema.Visibility {
	if index < helper.nPrimaryInput {
		return schema.Public
	} else if index < helper.nSecretInput+helper.nPrimaryInput {
		return schema.Secret
	} else if index < helper.nPrimaryInput+helper.nAuxiliaryInput {
		return schema.Internal
	} else {
		panic("invalid variable index")
	}
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness
// 3. run Setup / Prove / Verify with the backend
// 4. if set, (de)serializes the witness and call ReadAndProve and ReadAndVerify on the backend
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, opts ...TestingOption) {
	opt := assert.options(opts...)

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		curve := curve
		// parse the assignment and instantiate the witness
		validWitness, err := frontend.NewWitness(validAssignment, curve)
		assert.NoError(err, "can't parse valid assignment")

		validPublicWitness, err := frontend.NewWitness(validAssignment, curve, frontend.PublicOnly())
		assert.NoError(err, "can't parse valid assignment")

		if opt.witnessSerialization {
			// do a round trip marshalling test
			assert.Run(func(assert *Assert) {
				assert.marshalWitness(validWitness, curve, JSON)
			}, curve.String(), "marshal/json")
			assert.Run(func(assert *Assert) {
				assert.marshalWitness(validWitness, curve, Binary)
			}, curve.String(), "marshal/binary")
			assert.Run(func(assert *Assert) {
				assert.marshalWitness(validPublicWitness, curve, JSON, frontend.PublicOnly())
			}, curve.String(), "marshal-public/json")
			assert.Run(func(assert *Assert) {
				assert.marshalWitness(validPublicWitness, curve, Binary, frontend.PublicOnly())
			}, curve.String(), "marshal-public/binary")
		}

		for _, b := range opt.backends {

			b := b
			assert.Run(func(assert *Assert) {

				checkError := func(err error) { assert.checkError(err, b, curve, validWitness) }

				// 1- compile the circuit
				ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
				checkError(err)

				// must not error with big int test engine (only the curveID is needed for this test)
				err = IsSolved(circuit, validAssignment, curve, backend.UNKNOWN)
				checkError(err)

				switch b {
				case backend.GROTH16:
					cs := ccs.(*cs.R1CS)

					cs.DebugInfo = []compiled.LogEntry{}
					cs.MDebug = make(map[int]int)
					cs.Schema = &schema.Schema{}
					// cs.Levels = [][]int{}
					cs.Coefficients = []fr.Element{cs.Coefficients[0], cs.Coefficients[1]}
					cs2 := loadLibsnarkCS("libsnarkcs")

					pk, vk, err := groth16.Setup(&cs2)
					checkError(err)

					fmt.Println("$$$$$$$$$$$$$$$$")
					pretty.Print(opt.proverOpts)

					pretty.Print(validWitness)
					fmt.Println(validWitness.Vector.(*witness_bn254.Witness))

					witness2 := new(witness.Witness)
					witness2.CurveID = ecc.BN254
					bi, _ := new(big.Int).SetString("3832573639976773850384671636306227436183276778061632734900973793065182854224", 10)
					vector := []fr.Element{
						*new(fr.Element).SetUint64(666),
						*new(fr.Element).SetBigInt(bi),
						*new(fr.Element).SetUint64(233),
					}
					var wn witness_bn254.Witness
					wn = vector
					witness2.Vector = &wn

					// pretty.Print(cs)
					fmt.Println("################")
					// pretty.Print(cs2)

					// ensure prove / verify works well with valid witnesses

					// panic("a")
					proof, err := groth16.Prove(ccs, pk, validWitness, opt.proverOpts...)
					checkError(err)

					proof2, err := groth16.Prove(&cs2, pk, witness2, opt.proverOpts...)
					checkError(err)
					err = groth16.Verify(proof2, vk, validPublicWitness)
					checkError(err)
					if curve == ecc.BN254 {

						fmt.Println("Groth16 bn254")
						pretty.Print(circuit)
						pretty.Print(cs)
						coeffs := cs.Coefficients

						coeffs2 := make([]big.Int, len(coeffs))
						for i := 0; i < len(coeffs); i++ {
							fmt.Println(coeffs[i])
							coeffs[i].ToBigInt(&coeffs2[i])
							fmt.Println(&coeffs2[i])
							fmt.Println(&coeffs[i])
							coeffs[i].ToBigIntRegular(&coeffs2[i])
						}
						fmt.Println("constraints: ")
						constraints := cs.Constraints
						for i := 0; i < len(constraints); i++ {
							pretty.Print(constraints[i].String(coeffs2))
						}
						fmt.Println("num of internal vars: ", cs.CS.NbInternalVariables)
						fmt.Println("num of pub vars: ", cs.CS.NbPublicVariables)
						fmt.Println("num of sec vars: ", cs.CS.NbSecretVariables)
						fmt.Println("num of constraints: ", ccs.GetNbConstraints())

						fmt.Println(validWitness)
						fmt.Println(validPublicWitness)
						f, _ := os.Create("proof")
						defer f.Close()
						proof.WriteRawTo(f)
						f2, _ := os.Create("vk")
						defer f2.Close()
						vk.WriteRawTo(f2)
						f3, _ := os.Create("witness")
						defer f3.Close()
						wb, _ := validPublicWitness.MarshalBinary()
						f3.Write(wb)
					}
					err = groth16.Verify(proof, vk, validPublicWitness)
					checkError(err)

				case backend.PLONK:
					srs, err := NewKZGSRS(ccs)
					checkError(err)

					pk, vk, err := plonk.Setup(ccs, srs)
					checkError(err)

					correctProof, err := plonk.Prove(ccs, pk, validWitness, opt.proverOpts...)
					checkError(err)

					err = plonk.Verify(correctProof, vk, validPublicWitness)
					checkError(err)

				default:
					panic("backend not implemented")
				}
			}, curve.String(), b.String())
		}
	}

	// TODO may not be the right place, but ensures all our tests call these minimal tests
	// (like filling a witness with zeroes, or binary values, ...)
	assert.Run(func(assert *Assert) {
		assert.Fuzz(circuit, 5, opts...)
	}, "fuzz")
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness (must fail)
// 3. run Setup / Prove / Verify with the backend (must fail)
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, opts ...TestingOption) {
	opt := assert.options(opts...)

	popts := append(opt.proverOpts, backend.IgnoreSolverError())

	for _, curve := range opt.curves {

		// parse assignment
		invalidWitness, err := frontend.NewWitness(invalidAssignment, curve)
		assert.NoError(err, "can't parse invalid assignment")
		invalidPublicWitness, err := frontend.NewWitness(invalidAssignment, curve, frontend.PublicOnly())
		assert.NoError(err, "can't parse invalid assignment")

		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {

				checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
				mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

				// 1- compile the circuit
				ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
				checkError(err)

				err = ccs.IsSolved(invalidPublicWitness)
				mustError(err)

				// must error with big int test engine (only the curveID is needed here)
				err = IsSolved(circuit, invalidAssignment, curve, backend.UNKNOWN)
				mustError(err)

				switch b {
				case backend.GROTH16:
					pk, vk, err := groth16.Setup(ccs)
					checkError(err)

					proof, _ := groth16.Prove(ccs, pk, invalidWitness, popts...)

					err = groth16.Verify(proof, vk, invalidPublicWitness)
					mustError(err)

				case backend.PLONK:
					srs, err := NewKZGSRS(ccs)
					checkError(err)

					pk, vk, err := plonk.Setup(ccs, srs)
					checkError(err)

					incorrectProof, _ := plonk.Prove(ccs, pk, invalidWitness, popts...)
					err = plonk.Verify(incorrectProof, vk, invalidPublicWitness)
					mustError(err)

				default:
					panic("backend not implemented")
				}
			}, curve.String(), b.String())
		}
	}
}

func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...TestingOption) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {
				assert.solvingSucceeded(circuit, validWitness, b, curve, &opt)
			}, curve.String(), b.String())
		}
	}
}

func (assert *Assert) solvingSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) {
	// parse assignment
	validWitness, err := frontend.NewWitness(validAssignment, curve)
	assert.NoError(err, "can't parse valid assignment")

	checkError := func(err error) { assert.checkError(err, b, curve, validWitness) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
	checkError(err)

	// must not error with big int test engine
	err = IsSolved(circuit, validAssignment, curve, b)
	checkError(err)

	err = ccs.IsSolved(validWitness, opt.proverOpts...)
	checkError(err)

}

func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...TestingOption) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {
				assert.solvingFailed(circuit, invalidWitness, b, curve, &opt)
			}, curve.String(), b.String())
		}
	}
}

func (assert *Assert) solvingFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) {
	// parse assignment
	invalidWitness, err := frontend.NewWitness(invalidAssignment, curve)
	assert.NoError(err, "can't parse invalid assignment")

	checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
	mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
	if err != nil {
		fmt.Println(reflect.TypeOf(circuit).String())
	}
	checkError(err)

	// must error with big int test engine
	err = IsSolved(circuit, invalidAssignment, curve, b)
	mustError(err)

	err = ccs.IsSolved(invalidWitness, opt.proverOpts...)
	mustError(err)

}

// GetCounters compiles (or fetch from the compiled circuit cache) the circuit with set backends and curves
// and returns measured counters
func (assert *Assert) GetCounters(circuit frontend.Circuit, opts ...TestingOption) []compiled.Counter {
	opt := assert.options(opts...)

	var r []compiled.Counter

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {
				ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
				assert.NoError(err)
				r = append(r, ccs.GetCounters()...)
			}, curve.String(), b.String())
		}
	}

	return r
}

// Fuzz fuzzes the given circuit by instantiating "randomized" witnesses and cross checking
// execution result between constraint system solver and big.Int test execution engine
//
// note: this is experimental and will be more tightly integrated with go1.18 built-in fuzzing
func (assert *Assert) Fuzz(circuit frontend.Circuit, fuzzCount int, opts ...TestingOption) {
	opt := assert.options(opts...)

	// first we clone the circuit
	// then we parse the frontend.Variable and set them to a random value  or from our interesting pool
	// (% of allocations to be tuned)
	w := utils.ShallowClone(circuit)

	fillers := []filler{randomFiller, binaryFiller, seedFiller}

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {
				// this puts the compiled circuit in the cache
				// we do this here in case our fuzzWitness method mutates some references in the circuit
				// (like []frontend.Variable) before cleaning up
				_, err := assert.compile(circuit, curve, b, opt.compileOpts)
				assert.NoError(err)
				valid := 0
				// "fuzz" with zeros
				valid += assert.fuzzer(zeroFiller, circuit, w, b, curve, &opt)

				for i := 0; i < fuzzCount; i++ {
					for _, f := range fillers {
						valid += assert.fuzzer(f, circuit, w, b, curve, &opt)
					}
				}

				// fmt.Println(reflect.TypeOf(circuit).String(), valid)

			}, curve.String(), b.String())

		}
	}
}

func (assert *Assert) fuzzer(fuzzer filler, circuit, w frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) int {
	// fuzz a witness
	fuzzer(w, curve)

	err := IsSolved(circuit, w, curve, b)

	if err == nil {
		// valid witness
		assert.solvingSucceeded(circuit, w, b, curve, opt)
		return 1
	}

	// invalid witness
	assert.solvingFailed(circuit, w, b, curve, opt)
	return 0
}

// compile the given circuit for given curve and backend, if not already present in cache
func (assert *Assert) compile(circuit frontend.Circuit, curveID ecc.ID, backendID backend.ID, compileOpts []frontend.CompileOption) (frontend.CompiledConstraintSystem, error) {
	key := curveID.String() + backendID.String() + reflect.TypeOf(circuit).String()

	// check if we already compiled it
	if ccs, ok := assert.compiled[key]; ok {
		// TODO we may want to check that it was compiled with the same compile options here
		return ccs, nil
	}
	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(curveID, backendID, circuit, compileOpts...)
	// ccs, err := compiler.Compile(curveID, backendID, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(curveID, backendID, circuit, compileOpts...)
	// _ccs, err := compiler.Compile(curveID, backendID, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationNotDeterministic, err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		return nil, ErrCompilationNotDeterministic
	}

	// add the compiled circuit to the cache
	assert.compiled[key] = ccs

	// fmt.Println(key, ccs.GetNbConstraints())

	return ccs, nil
}

// default options
func (assert *Assert) options(opts ...TestingOption) testingConfig {
	// apply options
	opt := testingConfig{
		witnessSerialization: true,
		backends:             backend.Implemented(),
		curves:               ecc.Implemented(),
	}
	for _, option := range opts {
		err := option(&opt)
		assert.NoError(err, "parsing TestingOption")
	}

	if testing.Short() {
		// if curves are all there, we just test with bn254
		if reflect.DeepEqual(opt.curves, ecc.Implemented()) {
			opt.curves = []ecc.ID{ecc.BN254}
		}
		// opt.witnessSerialization = false
	}
	return opt
}

// ensure the error is set, else fails the test
func (assert *Assert) mustError(err error, backendID backend.ID, curve ecc.ID, witness *witness.Witness) {
	if err != nil {
		return
	}
	var json string
	bjson, err := witness.MarshalJSON()
	if err != nil {
		json = err.Error()
	} else {
		json = string(bjson)
	}

	e := fmt.Errorf("did not error (but should have) %s(%s)\nwitness:%s", backendID.String(), curve.String(), json)
	assert.FailNow(e.Error())
}

// ensure the error is nil, else fails the test
func (assert *Assert) checkError(err error, backendID backend.ID, curve ecc.ID, witness *witness.Witness) {
	if err == nil {
		return
	}

	var json string
	e := fmt.Errorf("%s(%s): %w", backendID.String(), curve.String(), err)

	bjson, err := witness.MarshalJSON()
	if err != nil {
		json = err.Error()
	} else {
		json = string(bjson)
	}
	e = fmt.Errorf("%w\nwitness:%s", e, json)

	assert.FailNow(e.Error())
}

type marshaller uint8

const (
	JSON marshaller = iota
	Binary
)

func (m marshaller) String() string {
	if m == JSON {
		return "JSON"
	}
	return "Binary"
}

func (assert *Assert) marshalWitness(w *witness.Witness, curveID ecc.ID, m marshaller, opts ...frontend.WitnessOption) {
	marshal := w.MarshalBinary
	if m == JSON {
		marshal = w.MarshalJSON
	}

	// serialize the vector to binary
	data, err := marshal()
	assert.NoError(err)

	// re-read
	witness := witness.Witness{CurveID: curveID, Schema: w.Schema}
	unmarshal := witness.UnmarshalBinary
	if m == JSON {
		unmarshal = witness.UnmarshalJSON
	}
	err = unmarshal(data)
	assert.NoError(err)

	witnessMatch := reflect.DeepEqual(*w, witness)

	if !witnessMatch {
		assert.Log("original json", string(data))
		// assert.Log("original vector", w.Vector)
		// assert.Log("reconstructed vector", witness.Vector)
	}

	assert.True(witnessMatch, m.String()+" round trip marshaling failed")
}
