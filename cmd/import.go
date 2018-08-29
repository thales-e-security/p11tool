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

// importCmd represents the import command
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Imports an AES key",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		doImport(cmd)
	},
}

var key []byte
var label string

func init() {
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().BytesHexVar(&key, "key", nil, "Plaintext key [required]")
	importCmd.Flags().StringVar(&label, "label", "", "Label for imported key [required]")

	importCmd.MarkFlagRequired("label")
	importCmd.MarkFlagRequired("key")
}

func doImport(cmd *cobra.Command) {
	p11Token, err := p11.NewToken(P11Lib, P11TokenLabel, getPIN(cmd))
	handleError(err)

	defer p11Token.Finalise()

	handleError(p11Token.ImportKey(key, label))

	log.Println("Key imported successfully")
}
