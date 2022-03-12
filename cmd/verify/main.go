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

type Input = []fr.Element

// functionality same as myVerify, but use internal/backend/bn254/groth16/solidity.go
func myVerify2(p bn254groth16.Proof, vk bn254groth16.VerifyingKey, w bn254witness.Witness) error {
	mp := Proof{A: p.Ar, B: p.Bs, C: p.Krs}
	mvk := VK{Alpha: vk.G1.Alpha, Beta: vk.G2.Beta, Delta: vk.G2.Delta, Gamma: vk.G2.Gamma, IC: vk.G1.K}
	var input Input
	input = w
	return myVerify3(mp, mvk, input)
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

func myVerify3(mp Proof, mvk VK, input Input) error {
	var vk_x bn254.G1Affine
	vk_x.X.SetZero()
	vk_x.Y.SetZero()
	fmt.Println(vk_x)
	for i := 0; i < len(input); i++ {
		var k big.Int
		vk_x.Add(&vk_x, new(bn254.G1Affine).ScalarMultiplication(&mvk.IC[i+1], input[i].ToBigIntRegular(&k)))
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

func g1(x string, y string) bn254.G1Affine {
	var ret bn254.G1Affine
	xi, _ := new(big.Int).SetString(x, 10)
	ret.X.SetBigInt(xi)
	yi, _ := new(big.Int).SetString(y, 10)
	ret.Y.SetBigInt(yi)
	return ret
}

func g2(x0, x1, y0, y1 string) (ret bn254.G2Affine) {
	x0i, _ := new(big.Int).SetString(x0, 10)
	x1i, _ := new(big.Int).SetString(x1, 10)
	y0i, _ := new(big.Int).SetString(y0, 10)
	y1i, _ := new(big.Int).SetString(y1, 10)
	ret.X.A0.SetBigInt(x0i)
	ret.X.A1.SetBigInt(x1i)
	ret.Y.A0.SetBigInt(y0i)
	ret.Y.A1.SetBigInt(y1i)
	return
}

func field(x string) (ret fr.Element) {
	i, _ := new(big.Int).SetString(x, 10)
	ret.SetBigInt(i)
	return
}

func main() {
	alpha := g1("11277869759378526546969124575771074807958698845834795760110860050010070883649", "21096352847591364686617688592277265927409501086196542200785515846892919186269")
	beta := g2(
		"11758142261403163295608845506555627774828420371736554132879876329100319737215",
		"7554225344334507119311023967766263980488693208432826234736374432532790891870",
		"16838074971068588345631214622994804945725658374885832516183540283152629504137",
		"13629812609392235503574289614193324689551363161071724741437706155184644607605",
	)
	// vke, err := bn254.Pair([]bn254.G1Affine{alpha}, []bn254.G2Affine{beta})
	// fmt.Println(&beta)
	// fmt.Println(&vke)
	gamma := g2(
		"5201669945702373471101660952468214135604852618345086137517807780471505572334",
		"10602394879420089663473361862853080722663128926071304335985059744535257873790",
		"12581577093847030052359559579924168004136990652128391769046338185929245997868",
		"18141389394651511704562356720182544464305242233768509738729900005057496164974",
	)
	delta := g2(
		"3125396043730655801868799646562384226237015460720466548049045212663415656424",
		"2110622932252212956082004328256857135556116479448554438033947151398485499952",
		"12715470950710663801179953118099329827210794379710784314515598563121104103633",
		"2344909202244599408945138859049406634995551111230343277152064356536005961634",
	)
	A := g1(
		"5951393489988534461164370680611709267409866360594083877737778916418599414988",
		"15911200437950447155432304569501142842703484580930413083773617123381239262209",
	)
	B := g2(
		"18692208673223486865536725325348789613333705755415866097571972277956334686591",
		"9525394332406297364523601160661018534508777530427125577209985922117749073090",
		"10363876631286966235933139022231896366917759352513473573237667852662522708447",
		"5157029420817723557589787416246670308616711500875201884461136275687207818562",
	)
	C := g1(
		"886393258877818764965969462444800340933446374148586785802734725245191814487",
		"7633944423895293637769171609026108055995512207391115764054777509903560559235",
	)
	IC := []bn254.G1Affine{
		g1("2594313621789524635784591657107144722239993678566416046840641758700540252354",
			"11321838968627584646671160647013312069427462918518222496943797828221334597473"),
		g1("6558753972087296091235267934884141852731630232929028103484987725508598406771",
			"19386825357669042224617535482432790672134136272781237130642878482806057266477"),
		g1("19361041831421332969028457852146357919734847767618053990070843266205788266793",
			"6709470901221834837887200838326577175357656548053794706132896784067716630679"),
		g1("10102998039455946799261847707553277098521417786392719817371057482143600437801",
			"7365152401899673033829223326342986368555705230429761775141557068648096941005"),
		g1("1875261715506059611887250443529179022365884523477023355809603426361576090542",
			"1533379227020581547858217515376123126920418963783951541289135475159493150367"),
		g1("13464385590190083509267243179670179353312540300017020679399938615444935131963",
			"9422736376659310486060978313455683557407048451916073643626594403591647039024"),
		g1("19296193929823788347315845340195845983587365078685416759049688975790780581404",
			"20281048823915676254622475141332619491429463224309025526790279257976919006367"),
		g1("6494363331041965342822054657700000505214565026682571054038421431810502511204",
			"5308320718397321745467682184983508406120637103425125414431271402350449208066"),
		g1("5902262996442243237166449411040073650144473712365434096656741205259128519043",
			"13982636049518029037552825432525079429022838091642551881580691026563769594243"),
		g1("4379445812033778343247448620250232948818739577601535756792847659309827544523",
			"17853004020662858847882330555152000743099247579797757788007106987103935384186"),
	}

	input := []fr.Element{
		field("1"),
		field("3451611916"),
		field("778424106"),
		field("1297035016"),
		field("1945110051"),
		field("589686400"),
		field("2837115548"),
		field("2980338592"),
		field("631778133"),
	}

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

	fmt.Println("haha")
	err = myVerify3(Proof{A: A, B: B, C: C}, VK{Alpha: alpha, Beta: beta, Gamma: gamma, Delta: delta, IC: IC}, input)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("success")
	}
}
