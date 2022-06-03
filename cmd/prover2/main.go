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
	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Errorf("Usage: prover arith input")
		os.Exit(1)
	}
	circuit := new(Circuit)
	circuit.LibsnarkArithPath = os.Args[1]
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, circuit)
	fmt.Println(err)
	_, _, _ = groth16.Setup(r1cs)

	fmt.Println(circuit)

	loadWitness(os.Args[2], circuit)
	witness, _ := frontend.NewWitness(circuit, ecc.BN254)
	fmt.Println(circuit)

	fmt.Println(witness)
	// publicWitness, _ := witness.Public()
	// proof, err := groth16.Prove(r1cs, pk, witness)
	// err = groth16.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	panic(err)
	// }
}

type Circuit struct {
	P                 [3]frontend.Variable `gnark:",public"`
	S                 [1]frontend.Variable
	LibsnarkArithPath string
	NPublicInput      uint
	NSecretInput      uint
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

func parseLibsnarkArith(circuit *Circuit, api frontend.API) {
	filename := circuit.LibsnarkArithPath
	f, _ := os.Open(filename)

	scanner := bufio.NewScanner(f)

	var total uint
	scanner.Scan()
	line := scanner.Text()
	fmt.Println(line)
	n, _ := fmt.Sscanf(line, "total %d", &total)
	if n != 1 {
		fmt.Println(n)
		log.Fatal("File Format Does not Match, expect total n")
	}

	for scanner.Scan() {
		line = scanner.Text()

		var id uint
		n, _ = fmt.Sscanf(line, "input %d", &id)
		if n == 1 {
			circuit.NPublicInput++
			continue
		}

		n, _ = fmt.Sscanf(line, "nizkinput %d", &id)
		if n == 1 {
			circuit.NSecretInput++
			continue
		}

		// when at here, all input and nizkinput are consumed
		// circuit.P = make([]frontend.Variable, circuit.NPublicInput)
		// circuit.S = make([]frontend.Variable, circuit.NSecretInput)
		Vars := make([]frontend.Variable, total)
		for i := uint(0); i < circuit.NPublicInput; i++ {
			Vars[i] = circuit.P[i]
		}
		for i := circuit.NPublicInput; i < circuit.NPublicInput+circuit.NSecretInput; i++ {
			Vars[i] = circuit.S[i]
		}

		var t, inStr, outStr string
		n, _ = fmt.Sscanf(line, "%s in %s out %s", &t, &inStr, &outStr)
		if n == 3 {
			inValues, _ := sliceAtoi(strings.Split(inStr, "_"))
			outValues, _ := sliceAtoi(strings.Split(outStr, "_"))
			var in []frontend.Variable
			if len(inValues) > 2 {
				in = make([]frontend.Variable, len(inValues)-2)
				for i := 2; i < len(inValues); i++ {
					in[i-2] = Vars[inValues[i]]
				}
			} else {
				in = make([]frontend.Variable, 0)
			}

			if t == "add" {
				Vars[outValues[0]] = api.Add(Vars[inValues[0]], Vars[inValues[1]], in...)
			} else if t == "nul" {
				Vars[outValues[0]] = api.Mul(Vars[inValues[0]], Vars[inValues[1]])
			} else if strings.Contains(t, "const-mul-") {
				constStr := t[len("const-mul-"):]
				bi, _ := new(big.Int).SetString(constStr, 16)
				c := new(fr.Element).SetBigInt(bi)
				Vars[outValues[0]] = api.Mul(frontend.Variable(c), Vars[inValues[0]])
			} else if t == "assert" {
				api.AssertIsEqual(Vars[inValues[0]], Vars[inValues[1]])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func loadWitness(filename string, circuit *Circuit) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	var id int
	var hex string

	for {
		n, _ := fmt.Fscanf(f, "%d %s\n", &id, &hex)

		if n != 2 {
			break
		}
		bi, _ := new(big.Int).SetString(hex, 16)
		if id < int(circuit.NPublicInput) {
			circuit.P[id] = *new(fr.Element).SetBigInt(bi)
		} else if id < int(circuit.NPublicInput)+int(circuit.NSecretInput) {
			circuit.S[id-int(circuit.NPublicInput)] = *new(fr.Element).SetBigInt(bi)
		}
	}
}
