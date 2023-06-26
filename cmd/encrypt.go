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
	"sync"

	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
)

var (
	cnt          string
	wg           sync.WaitGroup
	bytesWritten int64
	headerLine   string
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt plaintext using TNT",
	Long:  `Encrypt plaintext using the TNT Infinite (with respect to the plaintext) Key Encryption System.`,
	Run: func(cmd *cobra.Command, args []string) {
		encrypt(args)
	},
}

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:        "encode",
	Short:      "Encode plaintext using TNT",
	Long:       `[DEPRECATED] Encode plaintext using the TNT Infinite (with respect to the plaintext) Key Encryption System.`,
	Deprecated: "use \"encrypt\" instead.",
	Run: func(cmd *cobra.Command, args []string) {
		encrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(encodeCmd)
	encryptCmd.Flags().StringVarP(&cnt, "count", "n", "", `initial block count
The inital block count can be given as a fraction (eg. 1/3 or 1/2) of the maximum blocks encrypted before the key repeats.
The inital block count is only effective on the first use of the secret key.`)
	encodeCmd.Flags().StringVarP(&cnt, "count", "n", "", `initial block count
The inital block count can be given as a fraction (eg. 1/3 or 1/2) of the maximum blocks encrypted before the key repeats.
The inital block count is only effective on the first use of the secret key.`)
}

func encrypt(args []string) {
	initEngine(args)

	// Get the starting block count.  cnt can be a number or a fraction such
	// as "1/2", "2/3", or "3/4".  If it is a fraction, then the starting block
	// count is calculated by multiplying the maximal states of the tntEngine
	// by the fraction.
	if len(cnt) != 0 {
		var good bool
		flds := strings.Split(cnt, "/")
		if len(flds) == 1 {
			iCnt, good = new(big.Int).SetString(cnt, 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the count to a big.Int: [%s]\n", cnt))
			}
		} else if len(flds) == 2 {
			m := new(big.Int).Set(tntMachine.MaximalStates())
			a, good := new(big.Int).SetString(flds[0], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the numerator to a big.Int: [%s]\n", flds[0]))
			}
			b, good := new(big.Int).SetString(flds[1], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the denominator to a big.Int: [%s]\n", flds[1]))
			}
			iCnt = m.Div(m.Mul(m, a), b)
		} else {
			cobra.CheckErr(fmt.Sprintf("Incorrect initial count: [%s]\n", cnt))
		}
	} else {
		iCnt = new(big.Int).Set(tntengine.BigZero)
	}

	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("E")
	tntMachine.BuildCipherMachine()

	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encrypt the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)
	mKey = tntMachine.CounterKey()
	if cMap[mKey] == nil {
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
		if cnt != "" {
			fmt.Fprintln(os.Stderr, "Ignoring the block count argument - using the value from the .tnt file.")
		}
	}
	// Now we can set the index of the ciper machine.
	tntMachine.SetIndex(iCnt)

	var encIn *io.PipeReader
	// leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	fin, fout := getInputAndOutputFiles(true)
	headerLine = "+TNT|"
	if len(inputFileName) > 0 && inputFileName != "-" {
		headerLine += inputFileName
	}
	headerLine += fmt.Sprintf("|%s\n", tntMachine.Index())
	fout.WriteString(headerLine)
	encIn = toBinaryHelper(fin)

	defer fout.Close()
	bRdr := bufio.NewReader(encIn)
	_, err := io.Copy(fout, bRdr)
	checkError(err)
	wg.Wait()
	cMap[mKey] = tntMachine.Index()
	checkError(writeCounterFile(cMap))
	// shutdown the encryption machine by processing a CypherBlock with zero
	// value length field.
	var blk tntengine.CipherBlock
	tntMachine.Left() <- blk
	<-tntMachine.Right()
	// allow the tntMachine to be garbage collected.
	tntMachine = *new(tntengine.TntEngine)

}

// toBinaryHelper provides the means to output pure binary encrypted
// data to the output file..
func toBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	var cnt int
	var err error
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	checkError(err)
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer rWrtr.Close()
		plainText := make([]byte, 0)
		blk := make(tntengine.CipherBlock, tntengine.CipherBlockBytes)
		err = nil

		for err != io.EOF {
			b := make([]byte, 2048)
			cnt, err = rdr.Read(b)
			checkError(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)
				for len(plainText) > 0 {
					cnt := copy(blk, plainText)
					leftMost <- blk[:cnt]
					blk = <-rightMost
					bw, err1 := rWrtr.Write(blk[:cnt])
					checkError(err1)
					bytesWritten += int64(bw)
					// pt := make([]byte, 0)
					// pt = append(pt, plainText[len(blk):]...)
					plainText = plainText[:cnt]
				}
			}
		}

		// if len(plainText) > 0 {
		// 	cnt = copy(blk[:], plainText[:])
		// 	leftMost <- blk
		// 	blk = <-rightMost
		// 	_, err1 := rWrtr.Write(blk[:])
		// 	checkError(err1)
		// 	bytesWritten += int64(len(blk))
		// }

		fmt.Fprintf(os.Stderr, "Bytes written: %d\n", bytesWritten)
		// // shutdown the decryption machine by processing a CypherBlock with zero
		// // value length field.
		// leftMost <- blk[:0]
		// <-rightMost
	}()

	return rRdr
}
