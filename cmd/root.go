/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Version: "0.1.2",
	Use:     "sieve-monitor",
	Short:   "Sieve trace file processor",
	Long: `
Scans for a directory named 'sieve_trace' in each user's home directory.
For each file found matching the pattern '~/sieve_trace/*.trace', the 
contents are sent to the user as a message from "SIEVE_DAEMON".
After sending, deletes the trace file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		DaemonizeDisabled = viper.GetBool("foreground")
		monitor := NewMonitor()
		Daemonize(func() {
			if viper.GetBool("verbose") {
				fmt.Println(FormatJSON(&monitor))
			}
			err := monitor.Run()
			cobra.CheckErr(err)
		}, "/var/log/sieve-monitor", &monitor.stop)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
func init() {
	cobra.OnInitialize(initConfig)
	OptionString("logfile", "l", "stderr", "log filename")
	OptionSwitch("debug", "", "produce debug output")
	OptionSwitch("verbose", "v", "increase verbosity")
	OptionSwitch("foreground", "", "do not daemonize")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", os.Getenv("SIEVE-MONITOR_CONFIG_FILE"), "config file (default is $HOME/.sieve-monitor.yaml)")
}
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".sieve-monitor")
	}
	viper.SetEnvPrefix(rootCmd.Name())
	if err := viper.ReadInConfig(); err == nil {
		if viper.GetBool("verbose") {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
	OpenLog()
}
