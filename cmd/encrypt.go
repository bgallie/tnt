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
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
)

var (
	cnt        string
	wg         sync.WaitGroup
	headerLine string
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
	iCnt = new(tntengine.Counter)
	if len(cnt) != 0 {
		var good bool
		flds := strings.Split(cnt, "/")
		if len(flds) == 1 {
			iCnt, good = new(tntengine.Counter).SetString(cnt)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the count to a tntengine.Counter: [%s]\n", cnt))
			}
		} else if len(flds) == 2 {
			iCnt.SetIndex(tntMachine.MaximalStates())
			a, err := strconv.ParseUint(flds[0], 10, 64)
			if err != nil {
				cobra.CheckErr(fmt.Sprintf("failed converting the numerator to a tntengine.Counter: [%s]\n", flds[0]))
			}
			b, err := strconv.ParseUint(flds[1], 10, 64)
			if err != nil {
				cobra.CheckErr(fmt.Sprintf("failed converting the denominator to a tntengine.Counter: [%s]\n", flds[1]))
			}
			iCnt.Mul(a).Div(b)
		} else {
			cobra.CheckErr(fmt.Sprintf("Incorrect initial count: [%s]\n", cnt))
		}
	} else {
		iCnt.SetIndex(tntengine.BigZero)
	}
	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("E")
	tntMachine.BuildCipherMachine()
	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encrypt the file.
	cMap = make(map[string]*tntengine.Counter)
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
	// Get the input and output files
	fin, fout := getInputAndOutputFiles(true)
	// Create and output the header line.
	headerLine = "+TNT|"
	if len(inputFileName) > 0 && inputFileName != "-" {
		headerLine += inputFileName
	}
	headerLine += fmt.Sprintf("|%s\n", tntMachine.Index())
	fout.WriteString(headerLine)
	// Set up the fileter to encode the input file and send it to the output file.
	encIn := cipherHelper(bufio.NewReaderSize(fin, 2048), tntMachine.Left(), tntMachine.Right())
	defer fout.Close()
	_, err := io.Copy(fout, encIn)
	checkError(err)
	// Wait for the encryption to finish
	wg.Wait()
	// Update the counter map with the new block counts.
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
