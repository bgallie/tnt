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
	"encoding/gob"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	dbug "runtime/debug"
	"strings"
	"time"

	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/spf13/viper"
)

var (
	cfgFile        string
	tntMachine     tntengine.TntEngine
	iCnt           *big.Int
	cMap           map[string]*big.Int
	mKey           string
	cntrFileName   string
	inputFileName  string
	outputFileName string
	GitCommit      string = "not set"
	GitState       string = "not set"
	GitSummary     string = "not set"
	GitDate        string = "not set"
	BuildDate      string = "not set"
	Version        string = ""
)

const (
	tntCountFile = ".tnt"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "tnt",
	Short:   "An Infinite Key Encryption System",
	Long:    `tnt is a program the encrypts/decrypts files using an infinite (with respect to the plaintext) key.`,
	Version: Version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tnt.yaml)")
	rootCmd.PersistentFlags().StringVarP(&inputFileName, "inputFile", "i", "-", "Name of the plaintext file to encrypt/decrypt.")
	rootCmd.PersistentFlags().StringVarP(&outputFileName, "outputFile", "o", "", "Name of the file containing the encrypted/decrypted plaintext.")

	// Extract version information from the stored build information.
	bi, ok := dbug.ReadBuildInfo()
	if ok {
		Version = bi.Main.Version
		rootCmd.Version = Version
		GitDate = getBuildSettings(bi.Settings, "vcs.time")
		GitCommit = getBuildSettings(bi.Settings, "vcs.revision")
		if len(GitCommit) > 1 {
			GitSummary = fmt.Sprintf("%s-1-%s", Version, GitCommit[0:7])
		}
		GitState = "clean"
		if getBuildSettings(bi.Settings, "vcs.modified") == "true" {
			GitState = "dirty"
		}
	}

	// Get the build date (as the modified date of the executable) if the build date
	// is not set.
	if BuildDate == "not set" {
		fpath, err := os.Executable()
		cobra.CheckErr(err)
		fpath, err = filepath.EvalSymlinks(fpath)
		cobra.CheckErr(err)
		fsys := os.DirFS(filepath.Dir(fpath))
		fInfo, err := fs.Stat(fsys, filepath.Base(fpath))
		cobra.CheckErr(err)
		BuildDate = fInfo.ModTime().UTC().Format(time.RFC3339)
	}
}

func getBuildSettings(settings []dbug.BuildSetting, key string) string {
	for _, v := range settings {
		if v.Key == key {
			return v.Value
		}
	}
	return ""
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".tnt" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".tnt")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Get the counter file name based on the current user.
	u, err := user.Current()
	cobra.CheckErr(err)
	cntrFileName = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, tntCountFile)
}

func initEngine(args []string) {
	// Obtain the passphrase used to encrypt the file from either:
	// 1. User input from the terminal (most secure)
	// 2. The 'TNT_SECRET' environment variable (less secure)
	// 3. Arguments from the entered command line (least secure - not recommended)
	var secret string
	if len(args) == 0 {
		if viper.IsSet("TNT_SECRET") {
			secret = viper.GetString("TNT_SECRET")
		} else {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := term.ReadPassword(int(os.Stdin.Fd()))
				cobra.CheckErr(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
			}
		}
	} else {
		secret = strings.Join(args, " ")
	}

	if len(secret) == 0 {
		cobra.CheckErr("You must supply a password.")
		// } else {
		// 	fmt.Printf("Secret: [%s]\n", secret)
	}

	// Initialize the tntengine with the secret key and the named proforma file.
	tntMachine.Init([]byte(secret))
}

/*
getInputAndOutputFiles will return the input and output files to use while
encrypting/decrypting data.  If input and/or output files names were given,
then those files will be opened.  Otherwise stdin and stdout are used.
*/
func getInputAndOutputFiles(encode bool) (*os.File, *os.File) {
	var fin *os.File
	var err error

	if len(inputFileName) > 0 {
		if inputFileName == "-" {
			fin = os.Stdin
		} else {
			fin, err = os.Open(inputFileName)
			cobra.CheckErr(err)
		}
	} else {
		fin = os.Stdin
	}

	var fout *os.File

	if len(outputFileName) > 0 {
		if outputFileName == "-" {
			fout = os.Stdout
		} else {
			fout, err = os.Create(outputFileName)
			cobra.CheckErr(err)
		}
	} else if inputFileName == "-" {
		fout = os.Stdout
	} else if encode {
		outputFileName = inputFileName + ".tnt"
		fout, err = os.Create(outputFileName)
		cobra.CheckErr(err)
	} else {
		if strings.HasSuffix(inputFileName, ".tnt") {
			outputFileName = inputFileName[:len(inputFileName)-5]
			fout, err = os.Create(outputFileName)
			cobra.CheckErr(err)
		} else {
			fout = os.Stdout
		}
	}
	// fmt.Fprintf(os.Stderr, "Input: [%s] Output:[%s]\n", inputFileName, outputFileName)
	return fin, fout
}

// checkFatal checks for error that are not io.EOF and io.ErrUnexpectedEOF and logs them.
func checkError(e error) {
	if e != io.EOF && e != io.ErrUnexpectedEOF {
		cobra.CheckErr(e)
	}
}

func readCounterFile(defaultMap map[string]*big.Int) map[string]*big.Int {
	f, err := os.OpenFile(cntrFileName, os.O_RDONLY, 0600)
	if err != nil {
		return defaultMap
	}

	defer f.Close()
	cmap := make(map[string]*big.Int)
	dec := gob.NewDecoder(f)
	checkError(dec.Decode(&cmap))
	return cmap
}

func writeCounterFile(wMap map[string]*big.Int) error {
	f, err := os.OpenFile(cntrFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer f.Close()
	enc := gob.NewEncoder(f)
	return enc.Encode(wMap)
}
