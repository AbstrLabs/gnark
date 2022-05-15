// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multiplier

import (
	"github.com/consensys/gnark/frontend"
)

const N int = 10

type Circuit struct {
	A frontend.Variable `gnark:",public"`
	// "output", also public
	C frontend.Variable `gnark:",public"`
	B frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	var V [N]frontend.Variable
	V[0] = api.Add(api.Mul(circuit.A, circuit.A), circuit.B)
	for i := 1; i < N; i++ {
		V[i] = api.Add(api.Mul(V[i-1], V[i-1]), circuit.B)
	}
	api.AssertIsEqual(circuit.C, V[N-1])
	return nil
}
