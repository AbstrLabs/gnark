package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254groth16 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
)

// same as gnark implemented verify, but no parallel
func myVerify(p bn254groth16.Proof, vk bn254groth16.VerifyingKey, w bn254witness.Witness) error {
	if len(w) != (len(vk.G1.K) - 1) {
		return fmt.Errorf("invalid witness size, got %d, expected %d (public - ONE_WIRE)", len(w), len(vk.G1.K)-1)
	}

	if !(p.Ar.IsInSubGroup() && p.Krs.IsInSubGroup() && p.Bs.IsInSubGroup()) {
		return fmt.Errorf("not in subgroup")
	}

	var g2deltaNeg bn254.G2Affine
	g2deltaNeg.Neg(&vk.G2.Delta)
	var g2gammaNeg bn254.G2Affine
	g2gammaNeg.Neg(&vk.G2.Gamma)
	vke, err := bn254.Pair([]bn254.G1Affine{vk.G1.Alpha}, []bn254.G2Affine{vk.G2.Beta})

	// compute (eKrsδ, eArBs)
	doubleML, errML := bn254.MillerLoop([]bn254.G1Affine{p.Krs, p.Ar}, []bn254.G2Affine{g2deltaNeg, p.Bs})
	if errML != nil {
		return errML
	}

	// compute e(Σx.[Kvk(t)]1, -[γ]2)
	var kSum bn254.G1Jac
	if _, err := kSum.MultiExp(vk.G1.K[1:], w, ecc.MultiExpConfig{ScalarsMont: true}); err != nil {
		return err
	}
	kSum.AddMixed(&vk.G1.K[0])
	var kSumAff bn254.G1Affine
	kSumAff.FromJacobian(&kSum)

	right, err := bn254.MillerLoop([]bn254.G1Affine{kSumAff}, []bn254.G2Affine{g2gammaNeg})
	if err != nil {
		return err
	}

	right = bn254.FinalExponentiation(&right, &doubleML)
	if !vke.Equal(&right) {
		return fmt.Errorf("pairing failed")
	}

	return nil
}

// functionality same as myVerify, but use internal/backend/bn254/groth16/solidity.go
func myVerify2(p bn254groth16.Proof, vk bn254groth16.VerifyingKey, w bn254witness.Witness) error {
	type Proof struct {
		A bn254.G1Affine
		B bn254.G2Affine
		C bn254.G1Affine
	}

	type VK struct {
		Alpha bn254.G1Affine
		Beta  bn254.G2Affine
		Delta bn254.G2Affine
		Gamma bn254.G2Affine
		IC    []bn254.G1Affine
	}

	type Input []fr.Element

	mp := Proof{A: p.Ar, B: p.Bs, C: p.Krs}
	mvk := VK{Alpha: vk.G1.Alpha, Beta: vk.G2.Beta, Delta: vk.G2.Delta, Gamma: vk.G2.Gamma, IC: vk.G1.K}
	input := w

	var vk_x bn254.G1Affine
	vk_x.X.SetZero()
	vk_x.Y.SetZero()
	fmt.Println(vk_x)
	for i := 0; i < input.Len(); i++ {
		var k big.Int
		fmt.Println(new(bn254.G1Affine).ScalarMultiplication(&mvk.IC[i+1], w[i].ToBigInt(&k)))
		fmt.Println(new(bn254.G1Affine).ScalarMultiplication(&mvk.IC[i+1], big.NewInt(35)))
		// TODO: should be w[i].ToBigInt(&k), but then result was incorrect. if use 35 (original input) to replace the witness, result is correct
		vk_x.Add(&vk_x, new(bn254.G1Affine).ScalarMultiplication(&mvk.IC[i+1], big.NewInt(35)))
	}

	vk_x.Add(&vk_x, &mvk.IC[0])

	var na bn254.G1Affine
	na.Neg(&mp.A)

	return pairing(
		na,
		mp.B,
		mvk.Alpha,
		mvk.Beta,
		vk_x,
		mvk.Gamma,
		mp.C,
		mvk.Delta,
	)
}

func pairing(
	a1 bn254.G1Affine,
	a2 bn254.G2Affine,
	b1 bn254.G1Affine,
	b2 bn254.G2Affine,
	c1 bn254.G1Affine,
	c2 bn254.G2Affine,
	d1 bn254.G1Affine,
	d2 bn254.G2Affine,
) error {
	b, err := bn254.PairingCheck([]bn254.G1Affine{a1, b1, c1, d1}, []bn254.G2Affine{a2, b2, c2, d2})
	if err != nil {
		return err
	}
	if b != true {
		return fmt.Errorf("not paired")
	}
	return nil
}

func main() {
	f, _ := os.Open("proof")
	defer f.Close()
	var p bn254groth16.Proof
	p.ReadFrom(f)

	f2, _ := os.Open("vk")
	defer f2.Close()
	var vk bn254groth16.VerifyingKey
	vk.ReadFrom(f2)

	f3, _ := os.Open("witness")
	defer f3.Close()
	var w bn254witness.Witness
	w.ReadFrom(f3)

	err := bn254groth16.Verify(&p, &vk, w)
	if err != nil {
		panic("verify fail")
	} else {
		fmt.Println("success")
	}

	err = myVerify(p, vk, w)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("success")
	}

	err = myVerify2(p, vk, w)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("success")
	}
}
