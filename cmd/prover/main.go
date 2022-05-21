package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/kr/pretty"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Errorf("Usage: prover circuit input")
		os.Exit(1)
	}

	cs := loadLibsnarkCS(os.Args[1])
	pk, _, err := groth16.Setup(&cs)
	if err != nil {
		panic(err)
	}
	witness := loadWitness(os.Args[2])
	_, err = groth16.Prove(&cs, pk, witness)
	if err != nil {
		panic(err)
	}
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
	fmt.Println("number of secret inputs: ", nSecretInput)
	fmt.Println("number of constraints: ", nConstraints)
	helper := &ConstructR1CHelper{}
	helper.nPrimaryInput = nPrimaryInput + 1
	helper.nAuxiliaryInput = nAuxiliaryInput
	helper.nConstraints = nConstraints
	helper.nSecretInput = nSecretInput
	helper.coeffsSet = make(map[fr.Element]int)
	_ = getCoeffID(fr.NewElement(0), helper)
	_ = getCoeffID(fr.NewElement(1), helper)
	_ = getCoeffID(fr.NewElement(2), helper)
	one := fr.NewElement(1)
	neg1 := new(fr.Element)
	neg1.Neg(&one)
	_ = getCoeffID(*neg1, helper)

	constraints := make([]compiled.R1C, nConstraints)
	for i := 0; i < nConstraints; i++ {
		constraints[i] = loadConstraint(f, helper)
	}

	fmt.Println("***************")
	pretty.Print(constraints[0])

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
	// fmt.Println("=======")
	ret.LinExp = make([]compiled.Term, nTerms)
	for i := 0; i < nTerms; i++ {
		// if i == 0 {
		// 	_, _ = fmt.Fscanf(r, "%d\n", &index)
		// 	if index != 0 {
		// 		panic("expect index to be 0")
		// 	}
		// 	r.Read(coeff)
		// 	xi := new(big.Int).SetBytes(coeff)
		// 	if xi.Sign() != 0 {
		// 		// fmt.Errorf("at terms ")
		// 		panic("expect first coeff to be 0")
		// 	}
		// } else {
		_, _ = fmt.Fscanf(r, "%d\n", &index)
		r.Read(coeff)

		var coeff3 fr.Element
		for j := 0; j < 4; j++ {
			coeff2[j] = binary.LittleEndian.Uint64(coeff[j*8 : (j+1)*8])
			coeff3[j] = coeff2[j]
		}
		// fmt.Println("------")
		// fmt.Println(index)
		// fmt.Println(&coeff3)

		ret.LinExp[i] = encodeTerm(index, coeff3, helper)
		// }
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

func loadWitness(filename string) *witness.Witness {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	var unused int
	var hex string

	witness := new(witness.Witness)
	witness.CurveID = ecc.BN254
	vector := []fr.Element{}
	// _, _ = fmt.Fscanf(f, "%d %s\n", &unused, &hex)

	for {
		n, _ := fmt.Fscanf(f, "%d %s\n", &unused, &hex)

		if n != 2 {
			break
		}
		bi, _ := new(big.Int).SetString(hex, 16)
		vector = append(vector, *new(fr.Element).SetBigInt(bi))
	}

	var wn witness_bn254.Witness
	wn = vector
	witness.Vector = &wn
	return witness
}
