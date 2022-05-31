package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
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

	loadWitness(os.Args[2], circuit)
	witness, _ := frontend.NewWitness(circuit, ecc.BN254)
	publicWitness, _ := witness.Public()
	pk, vk, err := groth16.Setup(r1cs)
	proof, err := groth16.Prove(r1cs, pk, witness)
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}

type Circuit struct {
	P                 []frontend.Variable `gnark:",public"`
	S                 []frontend.Variable
	LibsnarkArithPath string
}

func (circuit *Circuit) Define(api frontend.API) error {
	parseLibsnarkArith(circuit.LibsnarkArithPath, api)
	return nil
}

func parseLibsnarkArith(filename string, api frontend.API) {

	return
}

func loadWitness(filename string, circuit *Circuit) {

}
