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

package compiled

import "github.com/consensys/gnark/internal/dag"

// R1CS decsribes a set of R1C constraint
type R1CS struct {
	CS
	Constraints []R1C

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependncies for constraints in a level l are solved
	// in previous levels
	Levels []dag.Level
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CS) GetNbConstraints() int {
	return len(r1cs.Constraints)
}
