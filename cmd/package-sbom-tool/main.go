// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"deepin-sbom-tools/pkg/log"
	"deepin-sbom-tools/pkg/subcmds"
	"deepin-sbom-tools/pkg/version"
	"flag"
	"fmt"
	"os"
)

var verbose bool
var toolVersion bool

func main() {
	// 创建主命令的 flag 集合
	rootCmd := flag.NewFlagSet("root", flag.ExitOnError)
	rootCmd.Usage = func() {
		fmt.Println("Usage: ", os.Args[0], " <command> [arguments]")
		fmt.Println("Commands:")
		for _, cmd := range subcmds.GetSubCmds() {
			fmt.Printf("  %-10s\t%s\n", cmd.Info.CmdName, cmd.Info.CmdDesc)
		}
		fmt.Println("Arguments:")
		rootCmd.PrintDefaults()
	}

	// 定义主命令的参数
	rootCmd.BoolVar(&verbose, "v", false, "enable verbose mode")
	rootCmd.BoolVar(&toolVersion, "version", false, "display the version of tool")

	if len(os.Args) < 2 {
		rootCmd.Usage()
		os.Exit(1)
	}

	// 解析主命令的参数
	rootCmd.Parse(os.Args[1:])

	log.NewLogger("", log.LevelInfo)
	for _, v := range os.Args {
		if v == "-v" {
			log.SetLogLevel(log.LevelDebug)
			log.Debug("enable debug")
		}
	}

	if toolVersion {
		fmt.Printf("%s: %s\n", os.Args[0], version.VERSION)
		return
	}
	// 获取子命令名称
	subCmd := rootCmd.Arg(0)
	// 执行子命令
	errCode := subcmds.Exec(subCmd)
	if errCode == subcmds.ErrNoCmd {
		log.Error("Unknown subcommand:", subCmd)
		rootCmd.Usage()
	}
	if errCode != 0 {
		os.Exit(1)
	}
}
