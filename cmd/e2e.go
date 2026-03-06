package main

import "github.com/spf13/cobra"

var e2eCmd = &cobra.Command{
	Use:   "e2e",
	Short: "End-to-end tunnel connectivity test",
}

func init() {
	rootCmd.AddCommand(e2eCmd)
}
