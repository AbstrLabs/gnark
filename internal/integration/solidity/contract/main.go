package main

import (
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	bn256groth16 "github.com/consensys/gnark/internal/backend/bn256/groth16"
	"github.com/consensys/gurvy"
)

// run this from /integration/solidity to regenerate files
// note: this is not in go generate format to avoid solc dependency in circleCI for now.
// go run contract/main.go && abigen --sol contract.sol --pkg solidity --out solidity.go
func main() {
	var circuit cubic.Circuit

	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("cubic.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("cubic.pk")
		if err != nil {
			panic(err)
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}

	f2, _ := os.Open("vk")
	defer f2.Close()
	var newVk bn256groth16.VerifyingKey
	oldVk, _ := vk.(*bn256groth16.VerifyingKey)
	newVk.SetFrom(f2)
	newVk.PublicInputs = oldVk.PublicInputs
	vk = &newVk

	{
		f, err := os.Create("contract.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}
	}

}
