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
	"log"

	"github.com/spf13/cobra"
	"github.com/thales-e-security/p11tool/p11"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Deletes all keys from a token (except those specified)",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		doDelete(cmd)
	},
}

var keysToKeep []string

func init() {
	rootCmd.AddCommand(deleteCmd)
	deleteCmd.Flags().StringArrayVar(&keysToKeep, "keep", nil,
		"Labels of keys to keep\nexample: --keep foo --keep bar --keep baz")
}

func doDelete(cmd *cobra.Command) {
	if len(keysToKeep) > 0 {
		log.Println("Deleting keys except:")
		for _, k := range keysToKeep {
			log.Println("- " + k)
		}
	} else {
		log.Println("Deleting all keys on token")
	}

	p11Token, err := p11.NewToken(p11Lib, p11TokenLabel, getPIN(cmd))
	handleError(err)

	defer p11Token.Finalise()
	handleError(p11Token.DeleteAllExcept(keysToKeep))

	log.Println("Finished.")
}
