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
		vk_x.Add(&vk_x, new(bn254.G1Affine).ScalarMultiplication(&mvk.IC[i+1], w[i].ToBigIntRegular(&k)))
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
	var alpha bn254.G1Affine
	ax, _ := new(big.Int).SetString("11277869759378526546969124575771074807958698845834795760110860050010070883649", 10)
	alpha.X.SetBigInt(ax)
	ay, _ := new(big.Int).SetString("21096352847591364686617688592277265927409501086196542200785515846892919186269", 10)
	alpha.Y.SetBigInt(ay)
	fmt.Println("---")
	fmt.Println(&alpha)
	var aj bn254.G1Jac
	aj.FromAffine(&alpha)
	fmt.Println(&aj)
	// xm := alpha.X.ToRegular()
	// fmt.Println(&xm)
	var beta bn254.G2Affine
	bx0, _ := new(big.Int).SetString("11758142261403163295608845506555627774828420371736554132879876329100319737215", 10)
	bx1, _ := new(big.Int).SetString("7554225344334507119311023967766263980488693208432826234736374432532790891870", 10)
	by0, _ := new(big.Int).SetString("16838074971068588345631214622994804945725658374885832516183540283152629504137", 10)
	by1, _ := new(big.Int).SetString("13629812609392235503574289614193324689551363161071724741437706155184644607605", 10)

	beta.X.A0.SetBigInt(bx0)
	beta.X.A1.SetBigInt(bx1)
	beta.Y.A0.SetBigInt(by0)
	beta.Y.A1.SetBigInt(by1)
	vke, err := bn254.Pair([]bn254.G1Affine{alpha}, []bn254.G2Affine{beta})
	fmt.Println(&beta)

	fmt.Println(&vke)

	f, _ := os.Open("proof")
	defer f.Close()
	var p bn254groth16.Proof
	p.ReadFrom(f)

	f2, _ := os.Open("vk")
	defer f2.Close()
	var vk bn254groth16.VerifyingKey
	vk.ReadFrom(f2)
	fmt.Println("vkalpha")
	fmt.Println(&vk.G1.Alpha.X)
	fmt.Println(vk.G1.Alpha.X.ToRegular())

	f3, _ := os.Open("witness")
	defer f3.Close()
	var w bn254witness.Witness
	w.ReadFrom(f3)

	err = bn254groth16.Verify(&p, &vk, w)
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
