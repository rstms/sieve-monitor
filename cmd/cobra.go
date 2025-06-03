package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var ViperPrefix = ""
var LogFile *os.File

func ViperKey(name string) string {
	return ViperPrefix + strings.ReplaceAll(name, "-", "_")
}

func OptionSwitch(name, flag, description string) {

	if flag == "" {
		rootCmd.PersistentFlags().Bool(name, false, description)
	} else {
		rootCmd.PersistentFlags().BoolP(name, flag, false, description)
	}

	viper.BindPFlag(ViperKey(name), rootCmd.PersistentFlags().Lookup(name))
}

func OptionString(name, flag, defaultValue, description string) {

	if flag == "" {
		rootCmd.PersistentFlags().String(name, defaultValue, description)
	} else {
		rootCmd.PersistentFlags().StringP(name, flag, defaultValue, description)
	}

	viper.BindPFlag(ViperKey(name), rootCmd.PersistentFlags().Lookup(name))
}

func OpenLog() {
	filename := viper.GetString("logfile")
	LogFile = nil
	if filename == "stdout" || filename == "-" {
		log.SetOutput(os.Stdout)
	} else if filename == "stderr" {
		log.SetOutput(os.Stderr)
	} else {
		fp, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			log.Fatalf("failed opening log file: %v", err)
		}
		LogFile = fp
		log.SetOutput(LogFile)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	if viper.GetBool("debug") {
		log.SetFlags(log.Flags() | log.Lshortfile)
	}

	_, name := filepath.Split(os.Args[0])
	prefix := fmt.Sprintf("%s[%d] ", name, os.Getpid())
	log.Printf("prefix='%s'\n", prefix)
	log.SetPrefix(prefix)

}

func CloseLog() {
	if LogFile != nil {
		err := LogFile.Close()
		cobra.CheckErr(err)
		LogFile = nil
	}
}

func FormatJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("failed formatting JSON: %v", err)
	}
	return string(data)
}

func IsDir(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func IsFile(pathname string) bool {
	_, err := os.Stat(pathname)
	return !os.IsNotExist(err)
}
