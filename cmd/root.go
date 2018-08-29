// Copyright 2018 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package cmd

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var P11Lib string
var P11TokenLabel string
var P11Pin string

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "p11import",
	Short: "Utility for PKCS#11 tokens",
	Long:  ``,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&P11Lib, "lib", "", "Path to PKCS#11 library [required]")
	rootCmd.PersistentFlags().StringVar(&P11TokenLabel, "token", "", "Token label [required]")
	rootCmd.PersistentFlags().StringVar(&P11Pin, "pin", "", "Token user PIN (insecure). To avoid "+
		"leaving PINs in your command history, omit this flag and enter the PIN when prompted.")
	rootCmd.MarkPersistentFlagRequired("lib")
	rootCmd.MarkPersistentFlagRequired("token")
}

// getPIN returns the token user PIN, reading it from the arguments (if supplied) or prompting the user to enter it
// at the terminal.
func getPIN(cmd *cobra.Command) string {
	if cmd.Flags().Changed("pin") {
		return P11Pin
	}

	fmt.Print("Token user PIN: ")
	pinBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	handleError(err)

	return string(pinBytes)
}

// handleError prints the error and exits, if err != nil
func handleError(err error) {
	if err != nil {
		log.Printf("An error occurred: %s", err.Error())
		os.Exit(1)
	}
}
