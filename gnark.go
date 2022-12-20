package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// gnark is a zk-SNARK library written in Go. Circuits are regular structs.
// The inputs must be of type frontend.Variable and make up the witness.
// The witness has a
//
//   - secret part --> known to the prover only
//
//   - public part --> known to the prover and the verifier
//
//     type CubicCircuit struct {
//     X frontend.Variable `gnark:"x"`       // x  --> secret visibility (default)
//     Y frontend.Variable `gnark:",public"` // Y  --> public visibility
//     }
type myCircuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
func (circuit *myCircuit) Define(api frontend.API) error {
	// compute x**3 and store it in the local variable x3.
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	// assert that the statement x**3 + x + 5 == y is true.
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	var circuit myCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	// witness definition
	assignment := myCircuit{X: 3, Y: 35}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		panic(err)
	}
	fmt.Printf("witness=%+v", witness)

	publicWitness, _ := witness.Public()
	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	if err != nil {
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}
		fmt.Printf("proof=%+v", proof)
	}
}
