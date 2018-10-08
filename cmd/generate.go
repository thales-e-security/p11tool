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
	"github.com/spf13/cobra"
	"github.com/thales-e-security/p11tool/p11"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new AES or RSA key in the token of the given size",
	Run: func(cmd *cobra.Command, args []string) {
		doGenerate(cmd)
	},
}

var keytype string
var keysize int

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVar(&label, "label", "", "Label for generated key [required]")
	generateCmd.Flags().StringVar(&keytype, "keytype", "", "Key type for generated key (RSA or AES) [required]")
	generateCmd.Flags().IntVar(&keysize, "keysize", 0, "Size of generated key (AES 128,192,256 - RSA 1024,2048,3072,4096) [required]")
	generateCmd.MarkFlagRequired("label")
	generateCmd.MarkFlagRequired("keytype")
	generateCmd.MarkFlagRequired("keysize")
}

func doGenerate(cmd *cobra.Command) {

	var labelToUse *string
	if cmd.Flags().Changed("label") {
		labelToUse = &label
	}

	p11Token, err := p11.NewToken(p11Lib, p11TokenLabel, getPIN(cmd))
	handleError(err)

	defer p11Token.Finalise()
	handleError(p11Token.GenerateKey(labelToUse, &keytype, keysize))
}
