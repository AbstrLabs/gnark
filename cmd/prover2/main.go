package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Errorf("Usage: prover arith input")
		os.Exit(1)
	}
	// parseAndEvalXjsnark(os.Args[1], os.Args[2])
	// os.Exit(0)

	circuit := newCircuitFromXjsnark(os.Args[1])

	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, circuit)
	if err != nil {
		panic(err)
	}
	cs := r1cs.(*cs.R1CS)
	log.Print("Load and compile Xjsnark arith file done")
	// pretty.Print(cs.Levels)
	// cs.Levels = make([][]int, 1511)
	// for i := 0; i < 1511; i++ {
	// 	cs.Levels[i] = []int{i}
	// }
	coeffs := make([]big.Int, len(cs.Coefficients))
	for i := 0; i < len(coeffs); i++ {
		cs.Coefficients[i].ToBigIntRegular(&coeffs[i])
	}
	fmt.Println("constraints: ")
	// constraints := cs.Constraints
	// for i := 0; i < 2; i++ {
	// fmt.Println(constraints[14875].String(coeffs))
	// fmt.Println(constraints[7940].String(coeffs))
	// }

	pk, vk, err := groth16.Setup(r1cs)
	log.Print("Generate pk and vk done")

	assignment := loadAssignment(os.Args[2], circuit)
	// fmt.Println(assignment)
	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	// fmt.Println(witness)
	publicWitness, _ := witness.Public()
	log.Print("Load witness done")

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}
	log.Print("Prove done")

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	log.Print("Verify done")
}

type Circuit struct {
	P         []frontend.Variable `gnark:",public"`
	S         []frontend.Variable
	Pi        []uint
	Si        []uint
	outputEnd uint
	Scanner   *bufio.Scanner
	totalVars uint
}

func (circuit *Circuit) Define(api frontend.API) error {
	parseLibsnarkArith(circuit, api)
	return nil
}

func sliceAtoi(sa []string) ([]int, error) {
	si := make([]int, 0, len(sa))
	for _, a := range sa {
		i, err := strconv.Atoi(a)
		if err != nil {
			return si, err
		}
		si = append(si, i)
	}
	return si, nil
}

// func parseAndEvalXjsnark(xjsnarkArithPath, inputPath string) {
// 	var lineno uint
// 	f, err := os.Open(xjsnarkArithPath)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	var totalVars, nPublicInput, nSecretInput, outputEnd uint

// 	scanner := bufio.NewScanner(f)
// 	scanner.Scan()
// 	lineno++

// 	line := scanner.Text()
// 	n, _ := fmt.Sscanf(line, "total %d", &totalVars)
// 	if n != 1 {
// 		log.Fatal("File Format Does not Match, expect total n")
// 	}
// 	for scanner.Scan() {
// 		lineno++
// 		line = scanner.Text()

// 		var id uint
// 		n, _ = fmt.Sscanf(line, "input %d", &id)
// 		if n == 1 {
// 			nPublicInput++
// 			continue
// 		}

// 		n, _ = fmt.Sscanf(line, "nizkinput %d", &id)
// 		if n == 1 {
// 			nSecretInput++
// 			continue
// 		}

// 		// gnark does not support output, we record the ids and just log them in the end
// 		n, _ = fmt.Sscanf(line, "output %d", &id)
// 		if n == 1 {
// 			outputEnd = id
// 			continue
// 		}

// 		break
// 	}

// 	Vars := make([]fr.Element, totalVars)

// 	f2, err := os.Open(inputPath)
// 	if err != nil {
// 		panic(err)
// 	}

// 	var id uint
// 	var hex string

// 	for {
// 		n, _ := fmt.Fscanf(f2, "%d %s\n", &id, &hex)

// 		if n != 2 {
// 			break
// 		}
// 		bi, success := new(big.Int).SetString(hex, 16)
// 		fi := new(fr.Element).SetBigInt(bi)
// 		if !success {
// 			log.Fatal("not a valid hex number")
// 		}
// 		if id < nPublicInput+nSecretInput {
// 			Vars[id] = *fi
// 		}
// 	}

// 	for {
// 		line := scanner.Text()
// 		var t, inStr, outStr string
// 		n, _ := fmt.Sscanf(line, "%s in %s out %s", &t, &inStr, &outStr)
// 		if n == 3 {
// 			inValues, err := sliceAtoi(strings.Split(inStr, "_"))
// 			if err != nil {
// 				log.Fatal(err)
// 			}
// 			outValues, err := sliceAtoi(strings.Split(outStr, "_"))
// 			if err != nil {
// 				log.Fatal(err)
// 			}

// 			if t == "add" {
// 				var in []fr.Element
// 				if len(inValues) > 2 {
// 					in = make([]fr.Element, len(inValues)-2)
// 					for i := 2; i < len(inValues); i++ {
// 						in[i-2] = Vars[inValues[i]]
// 					}
// 				} else {
// 					in = make([]fr.Element, 0)
// 				}
// 				Vars[outValues[0]].Add(&Vars[inValues[0]], &Vars[inValues[1]])
// 				for _, e := range in {
// 					Vars[outValues[0]].Add(&Vars[outValues[0]], &e)
// 				}
// 			} else if t == "mul" {
// 				Vars[outValues[0]].Mul(&Vars[inValues[0]], &Vars[inValues[1]])
// 			} else if strings.Contains(t, "const-mul-neg-") {
// 				constStr := t[len("const-mul-neg-"):]
// 				bi, success := new(big.Int).SetString(constStr, 16)
// 				if !success {
// 					log.Fatal("not a valid hex number")
// 				}
// 				c := new(fr.Element).SetBigInt(bi)
// 				d := new(fr.Element).Neg(c)
// 				// fmt.Println(bi)
// 				// fmt.Println(d)
// 				Vars[outValues[0]].Mul(d, &Vars[inValues[0]])
// 			} else if strings.Contains(t, "const-mul-") {
// 				constStr := t[len("const-mul-"):]
// 				// if constStr == "0" {
// 				// 	fmt.Println("const-mul-0", outValues[0])
// 				// 	Vars[outValues[0]] = fr.NewElement(0)
// 				// } else {
// 				bi, success := new(big.Int).SetString(constStr, 16)
// 				if !success {
// 					log.Fatal("not a valid hex number. line:", line)
// 				}
// 				c := new(fr.Element).SetBigInt(bi)
// 				Vars[outValues[0]].Mul(c, &Vars[inValues[0]])
// 				// }
// 			} else if t == "assert" {
// 				v := new(fr.Element).Mul(&Vars[inValues[0]], &Vars[inValues[1]])
// 				if !v.Equal(&Vars[outValues[0]]) {
// 					log.Print("assert fail, at line: ", lineno, ": ", line)
// 				} else {
// 					log.Print("assert pass at line: ", lineno, ": ", line)
// 				}
// 			} else if t == "xor" {
// 				if Vars[inValues[0]].Equal(&Vars[inValues[1]]) {
// 					Vars[outValues[0]] = fr.NewElement(0)
// 				} else {
// 					Vars[outValues[0]] = fr.NewElement(1)
// 				}
// 			} else if t == "or" {
// 				if Vars[inValues[0]].IsZero() && Vars[inValues[1]].IsZero() {
// 					Vars[outValues[0]] = fr.NewElement(0)
// 				} else {
// 					Vars[outValues[0]] = fr.NewElement(1)
// 				}
// 			} else if t == "zerop" {
// 				// note this actually means non-zerop
// 				if Vars[inValues[0]].IsZero() {
// 					Vars[outValues[0]] = fr.NewElement(0)
// 				} else {
// 					Vars[outValues[0]] = fr.NewElement(1)
// 				}
// 			} else if t == "split" {
// 				for i, e := range outValues {
// 					Vars[e].SetUint64(Vars[inValues[0]].Bit(uint64(i)))
// 				}
// 			} else if t == "pack" {
// 				bi := new(big.Int)
// 				for i, e := range inValues {
// 					var b uint
// 					if Vars[e].IsZero() {
// 						b = 0
// 					} else {
// 						b = 1
// 					}
// 					bi.SetBit(bi, i, b)
// 				}
// 				Vars[outValues[0]].SetBigInt(bi)
// 			} else {
// 				log.Fatal("Unknown opcode:", t)
// 			}
// 		} else {
// 			log.Fatal("Arith file format invalid line:", line, "expected <opcode> in <input vars> out <output vars>")
// 		}
// 		if !scanner.Scan() {
// 			break
// 		}
// 		lineno++
// 	}

// 	if outputEnd != 0 {
// 		outputStart := nPublicInput + nSecretInput
// 		for i := outputStart; i <= outputEnd; i++ {
// 			// TODO: this doesn't work. for now we have to ignore output.
// 			// api.Println(Vars[i])
// 			fmt.Println("output ", i, ": ", &Vars[i])
// 		}
// 	}

// 	for i := 0; i < int(totalVars); i++ {
// 		// TODO: this doesn't work. for now we have to ignore output.
// 		// api.Println(Vars[i])
// 		fmt.Println("Vars ", i, ": ", &Vars[i])
// 	}

// 	if err := scanner.Err(); err != nil {
// 		log.Fatal(err)
// 	}
// }

func newCircuitFromXjsnark(xjsnarkArithPath string) (circuit *Circuit) {
	circuit = new(Circuit)
	f, err := os.Open(xjsnarkArithPath)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	circuit.Scanner = scanner
	circuit.Pi = make([]uint, 0)
	circuit.Si = make([]uint, 0)

	scanner.Scan()
	line := scanner.Text()
	n, _ := fmt.Sscanf(line, "total %d", &circuit.totalVars)
	if n != 1 {
		log.Fatal("File Format Does not Match, expect total n")
	}
	var nPublicInput, nSecretInput uint
	for scanner.Scan() {
		line = scanner.Text()

		var id uint
		n, _ = fmt.Sscanf(line, "input %d", &id)
		if n == 1 {
			nPublicInput++
			circuit.Pi = append(circuit.Pi, id)
			continue
		}

		n, _ = fmt.Sscanf(line, "nizkinput %d", &id)
		if n == 1 {
			nSecretInput++
			circuit.Si = append(circuit.Si, id)
			continue
		}

		// gnark does not support output, we record the ids and just log them in the end
		n, _ = fmt.Sscanf(line, "output %d", &id)
		if n == 1 {
			circuit.outputEnd = id
			continue
		}

		// break
	}

	circuit.P = make([]frontend.Variable, nPublicInput)
	circuit.S = make([]frontend.Variable, nSecretInput)
	fmt.Println(circuit.P)
	fmt.Println(circuit.Pi)
	f, err = os.Open(xjsnarkArithPath)
	if err != nil {
		log.Fatal(err)
	}
	scanner = bufio.NewScanner(f)
	circuit.Scanner = scanner
	return
}

func parseLibsnarkArith(circuit *Circuit, api frontend.API) {
	Vars := make([]frontend.Variable, circuit.totalVars)
	scanner := circuit.Scanner

	fmt.Println(len(circuit.P))
	fmt.Println(len(circuit.Pi))
	// api.AssertIsEqual(circuit.P[0], 1)
	for i, p := range circuit.P {
		Vars[circuit.Pi[i]] = p
	}
	for i, s := range circuit.S {
		Vars[circuit.Si[i]] = s
	}

	for {
		line := scanner.Text()
		var t, inStr, outStr string
		n, _ := fmt.Sscanf(line, "%s in %s out %s", &t, &inStr, &outStr)
		if n == 3 {
			inValues, err := sliceAtoi(strings.Split(inStr, "_"))
			if err != nil {
				log.Fatal(err)
			}
			outValues, err := sliceAtoi(strings.Split(outStr, "_"))
			if err != nil {
				log.Fatal(err)
			}

			if t == "add" {
				var in []frontend.Variable
				if len(inValues) > 2 {
					in = make([]frontend.Variable, len(inValues)-2)
					for i := 2; i < len(inValues); i++ {
						in[i-2] = Vars[inValues[i]]
					}
				} else {
					in = make([]frontend.Variable, 0)
				}
				Vars[outValues[0]] = api.Add(Vars[inValues[0]], Vars[inValues[1]], in...)
			} else if t == "mul" {
				Vars[outValues[0]] = api.Mul(Vars[inValues[0]], Vars[inValues[1]])
			} else if strings.Contains(t, "const-mul-neg-") {
				constStr := t[len("const-mul-neg-"):]
				bi, success := new(big.Int).SetString(constStr, 16)
				if !success {
					log.Fatal("not a valid hex number")
				}
				// c := new(fr.Element).SetBigInt(bi)
				// d := new(fr.Element).Neg(c)
				// fmt.Println(bi)
				// fmt.Println(d)
				Vars[outValues[0]] = api.Mul(api.Neg(bi), Vars[inValues[0]])
			} else if strings.Contains(t, "const-mul-") {
				constStr := t[len("const-mul-"):]
				// if constStr == "0" {
				// 	fmt.Println("const-mul-0", outValues[0])
				// 	Vars[outValues[0]] = fr.NewElement(0)
				// } else {
				bi, success := new(big.Int).SetString(constStr, 16)
				if !success {
					log.Fatal("not a valid hex number. line:", line)
				}
				// c := new(fr.Element).SetBigInt(bi)
				Vars[outValues[0]] = api.Mul(api.ConstantValue(bi), Vars[inValues[0]])
				// }
			} else if t == "assert" {
				api.AssertIsEqual(api.Mul(Vars[inValues[0]], Vars[inValues[1]]), Vars[outValues[0]])
			} else if t == "xor" {
				Vars[outValues[0]] = api.Xor(api.IsZero(Vars[inValues[0]]), api.IsZero(Vars[inValues[1]]))
				api.Println("xor", Vars[inValues[0]], Vars[inValues[1]], "result", Vars[outValues[0]])
			} else if t == "or" {
				Vars[outValues[0]] = api.Or(Vars[inValues[0]], Vars[inValues[1]])
			} else if t == "zerop" {
				// note this actually means non-zerop
				Vars[outValues[0]] = api.Sub(big.NewInt(1), api.IsZero(Vars[inValues[0]]))
			} else if t == "split" {
				l := len(outValues)
				bits := api.ToBinary(Vars[inValues[0]], l)
				for i, e := range bits {
					Vars[outValues[i]] = e
				}
			} else if t == "pack" {
				in := make([]frontend.Variable, len(inValues))
				for i := 0; i < len(inValues); i++ {
					in[i] = Vars[inValues[i]]
				}
				Vars[outValues[0]] = api.FromBinary(in...)
			} else {
				log.Fatal("Unknown opcode:", t)
			}
			for _, e := range outValues {
				api.Println(e, Vars[e])
			}
		} else {
			// log.Fatal("Arith file format invalid line:", line, "expected <opcode> in <input vars> out <output vars>")
		}
		if !scanner.Scan() {
			break
		}
	}

	// if circuit.outputEnd != 0 {
	// 	outputStart := len(circuit.P) + len(circuit.S)
	// 	for i := outputStart; i <= int(circuit.outputEnd); i++ {
	// 		api.Println(Vars[i])
	// 	}
	// }

	// for i := 0; i < int(circuit.totalVars); i++ {
	// 	api.Println(i, Vars[i])
	// }

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("here")
}

func loadAssignment(filename string, circuit *Circuit) (ret *Circuit) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	ret = new(Circuit)
	ret.outputEnd = circuit.outputEnd
	ret.P = make([]frontend.Variable, len(circuit.P))
	// ret.Pi = make([]uint, len(circuit.P))

	ret.S = make([]frontend.Variable, len(circuit.S))
	// ret.Si = make([]uint, len(circuit.S))

	var id uint
	var hex string

	i := 0
	for {
		n, _ := fmt.Fscanf(f, "%d %s\n", &id, &hex)

		if n != 2 {
			break
		}
		bi, success := new(big.Int).SetString(hex, 16)
		if !success {
			log.Fatal("not a valid hex number")
		}
		if i < len(ret.P) {
			ret.P[i] = bi
			// ret.Pi[i] = id

		} else if i < len(ret.P)+len(ret.S) {
			ret.S[i-len(ret.P)] = bi
			// ret.Si[i-len(ret.P)] = id
		}
		i++
	}
	return
}
