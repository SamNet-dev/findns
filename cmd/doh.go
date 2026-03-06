package main

import "github.com/spf13/cobra"

var dohCmd = &cobra.Command{
	Use:   "doh",
	Short: "Test DoH (DNS-over-HTTPS) resolvers",
}

func init() {
	rootCmd.AddCommand(dohCmd)
}
