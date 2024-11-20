package main

import (
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"time"

	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const OUT_DIR = "../resources/gnark"

func main() {

	generateCircuitFiles(&chachaV3.ChaChaCircuit{}, "chacha20")
	generateCircuitFiles(&chachaV3_oprf.ChachaTOPRFCircuit{TOPRF: chachaV3_oprf.TOPRFData{}}, "chacha20_oprf")

	aes128 := &aes_v2.AES128Wrapper{
		AESWrapper: aes_v2.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}

	generateCircuitFiles(aes128, "aes128")

	aes256 := &aes_v2.AES256Wrapper{
		AESWrapper: aes_v2.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}
	generateCircuitFiles(aes256, "aes256")

}

func generateCircuitFiles(circuit frontend.Circuit, name string) {
	circuitArg, err := getArg("--circuit")
	if err == nil {
		if circuitArg != name {
			fmt.Println("skipping circuit ", name)
			return
		}
	}

	curve := ecc.BN254.ScalarField()

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d pub %d secret %d\n", r1css.GetNbConstraints(), r1css.GetNbPublicVariables(), r1css.GetNbSecretVariables())

	_ = os.Remove(OUT_DIR + "/r1cs." + name)
	_ = os.Remove(OUT_DIR + "/pk." + name)
	_ = os.Remove("libraries/verifier/impl/generated/vk." + name)
	f, err := os.OpenFile(OUT_DIR+"/r1cs."+name, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	_, err = r1css.WriteTo(f)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile(OUT_DIR+"/pk."+name, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	_, err = pk1.WriteTo(f2)
	if err != nil {
		panic(err)
	}
	err = f2.Close()
	if err != nil {
		panic(err)
	}

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk."+name, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	_, err = vk1.WriteTo(f3)
	if err != nil {
		panic(err)
	}
	err = f3.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("generated circuit for ", name)
}

/**
 * Helper function to get the value of a command line argument
 * Expects args in the form of "[name] [value]"
 */
func getArg(name string) (string, error) {
	for i, arg := range os.Args {
		if arg == name {
			if i+1 < len(os.Args) {
				return os.Args[i+1], nil
			}

			return "", fmt.Errorf("arg %s has no value", name)
		}
	}

	return "", fmt.Errorf("arg %s not found", name)
}
