/*
Copyright © 2021 Billy G. Allie <bill.allie@defiant.mug.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a TNT encrypted file.",
	Long:  `Decrypt a file encrypted by the TNT Infinite (with respect to the plaintext) Key Encryption System.`,
	Run: func(cmd *cobra.Command, args []string) {
		decrypt(args)
	},
}

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:        "decode",
	Short:      "Decode a TNT encoded file.",
	Long:       `[DEPRECATED] Decode a file encoded by the TNT Infinite (with respect to the plaintext) Key Encryption System.`,
	Deprecated: "use \"decrypt\" instead.",
	Run: func(cmd *cobra.Command, args []string) {
		decrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(decodeCmd)
}

func decrypt(args []string) {
	initEngine(args)
	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("D")
	tntMachine.BuildCipherMachine()
	// get input and output files
	fin, fout := getInputAndOutputFiles(false)
	// Process the header line from the encrypted file.
	var ofName string
	var bRdr *bufio.Reader
	var err error
	bRdr = bufio.NewReader(fin)
	line, err := bRdr.ReadString('\n')
	if err == nil {
		fields := strings.Split(line[:len(line)-1], "|")
		switch len(fields) {
		case 1: // Oldest TNT output format - It just contains ending block count.
			ofName = ""
			iCnt, _ = new(big.Int).SetString(fields[0], 10)
		case 2: // Older TNT output format - It contains the original filename and ending block count
			ofName = fields[0]
			iCnt, _ = new(big.Int).SetString(fields[1], 10)
		default:
			if fields[0] != "+TNT" {
				fmt.Fprintln(os.Stderr, "ERROR: Input file is not a recognized TNT output format!")
				os.Exit(100)
			}
			ofName = fields[1]
			iCnt, _ = new(big.Int).SetString(fields[2], 10)
		}
	}
	// If an output file was not given in the command line arguments, but one
	// was given in the header line of the input file, use that filename.
	if len(outputFileName) == 0 {
		if len(ofName) > 0 {
			var err error
			fout, err = os.Create(ofName)
			checkError(err)
		}
	}
	// Set the starting index from the header file.
	tntMachine.SetIndex(iCnt)
	// Set up the filter to decrypt the input file and send it to the output file.
	defer fout.Close()
	decRdr := cipherHelper(bRdr, tntMachine.Left(), tntMachine.Right())
	_, err = io.Copy(fout, decRdr)
	checkError(err)
	wg.Wait() // Wait for the decryption machine to finish it's clean up.
	// shutdown the encryption machine by processing a CypherBlock with zero
	// value length field.
	var blk tntengine.CipherBlock
	tntMachine.Left() <- blk
	<-tntMachine.Right()
	// allow the tntMachine to be garbage collected.
	tntMachine = *new(tntengine.TntEngine)
}
