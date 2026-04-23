// Leona — mobile application security toolkit.
//
// See https://github.com/leonasec/leona
// Licensed under Apache 2.0.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build-time variables, overridden by ldflags during release.
var (
	version = "0.1.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "leona",
		Short: "Mobile application security toolkit for the deception era",
		Long: `Leona scans mobile applications for security issues, detects
attack tools by their irreducible signatures, and—when the full
suite ships—deceives attackers rather than denying them service.

Start by scanning an APK:

  leona scan myapp.apk

For the full roadmap and design philosophy, see
  https://github.com/leonasec/leona`,
		SilenceUsage: true,
	}

	root.AddCommand(newScanCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newVersionCmd())

	return root
}

func newScanCmd() *cobra.Command {
	var (
		format  string
		output  string
		rulesEd string
	)

	cmd := &cobra.Command{
		Use:   "scan [apk-file]",
		Short: "Scan an APK for security issues",
		Long: `Scan runs the Leona static analysis engine against a mobile
application package and emits a report.

Supported formats: text (default), json, html, sarif.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apkPath := args[0]
			if _, err := os.Stat(apkPath); err != nil {
				return fmt.Errorf("cannot read %s: %w", apkPath, err)
			}
			// Placeholder until the scanner engine lands.
			fmt.Printf("leona: scanning %s (format=%s, rules=%s)\n",
				apkPath, format, rulesEd)
			fmt.Println("leona: scan engine not yet implemented — landing in v0.1.0")
			if output != "" {
				fmt.Printf("leona: will write to %s\n", output)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text",
		"Output format: text, json, html, sarif")
	cmd.Flags().StringVarP(&output, "output", "o", "",
		"Output file (default: stdout)")
	cmd.Flags().StringVar(&rulesEd, "rules", "builtin",
		"Rule set to apply: builtin, <path>, or <url>")

	return cmd
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List and manage detection rules",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List built-in detection rules",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("leona: rule engine not yet implemented — landing in v0.1.0")
		},
	})

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("leona %s\n  commit: %s\n  built:  %s\n",
				version, commit, date)
		},
	}
}
