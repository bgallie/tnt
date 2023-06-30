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

// fromBinaryHelper provides the neams to decrypt the pure binary input
// into the output pipe stream.  The data can be read using the returned
// PipeReader.
func fromBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer rWrtr.Close()
		var err error = nil
		encText := []byte(nil)
		blk := make(tntengine.CipherBlock, tntengine.CipherBlockBytes)

		for err != io.EOF {
			b := make([]byte, 2048)
			rCnt, err := rdr.Read(b)
			checkError(err)
			if err != io.EOF {
				encText = append(encText, b[:rCnt]...)
				for len(encText) >= tntengine.CipherBlockBytes {
					cnt := copy(blk, encText)
					leftMost <- blk
					blk = <-rightMost
					bw, err1 := rWrtr.Write(blk)
					checkError(err1)
					bytesWritten += int64(bw)
					encText = encText[cnt:]
				}
			} else {
				break
			}
		}
		if len(encText) > 0 {
			cnt := copy(blk, encText)
			leftMost <- blk[:cnt]
			blk = <-rightMost
			bw, err1 := rWrtr.Write(blk)
			checkError(err1)
			bytesWritten += int64(bw)
		}

		fmt.Fprintf(os.Stderr, "Bytes written: %d\n", bytesWritten)
	}()

	return rRdr
}

func decrypt(args []string) {
	initEngine(args)

	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("D")
	tntMachine.BuildCipherMachine()
	fin, fout := getInputAndOutputFiles(false)
	defer fout.Close()
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

	tntMachine.SetIndex(iCnt)
	// leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	// decRdr, decWrtr := io.Pipe()
	// err = nil
	// wg.Add(1)
	decRdr := fromBinaryHelper(bRdr)
	// go func() {
	// 	defer wg.Done()
	// 	defer decWrtr.Close()
	// 	var rCnt int
	// 	// encText := make([]byte, 0)
	// 	aRdr := fromBinaryHelper(bRdr)
	// 	blk := make(tntengine.CipherBlock, tntengine.CipherBlockBytes)
	// 	for err != io.EOF {
	// 		b := make([]byte, 2048)
	// 		rCnt, err = aRdr.Read(b)
	// 		checkError(err)
	// 		if err != io.EOF {
	// 			encText = append(encText, b[:rCnt]...)
	// 			for len(encText) > 0 {
	// 				cnt := copy(blk, encText[:])
	// 				leftMost <- blk[:cnt]
	// 				blk = <-rightMost
	// 				_, err1 := decWrtr.Write(blk[:cnt])
	// 				checkError(err1)
	// 				encText = encText[cnt:]
	// 			}
	// 		}
	// 	}
	// }()

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
