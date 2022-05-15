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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestMultiplier(t *testing.T) {
	assert := test.NewAssert(t)

	var cubicCircuit Circuit

	assert.ProverFailed(&cubicCircuit, &Circuit{
		A: 42,
		B: 42,
		C: 3,
	})

	assert.ProverSucceeded(&cubicCircuit, &Circuit{
		A: 666,
		B: 233,
		C: "3832573639976773850384671636306227436183276778061632734900973793065182854224",
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}
