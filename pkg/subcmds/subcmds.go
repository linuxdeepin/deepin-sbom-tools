// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package subcmds

import (
	"deepin-sbom-tools/pkg/log"
	"deepin-sbom-tools/pkg/subcmds/generate_cmd"
	"deepin-sbom-tools/pkg/subcmds/identity_cmd"
	"deepin-sbom-tools/pkg/subcmds/sign_cmd"
	"deepin-sbom-tools/pkg/subcmds/validate_cmd"
	"deepin-sbom-tools/pkg/subcmds/verify_cmd"
	"flag"
	"os"
)

type Subcmd struct {
	Info CmdInfo
	args []string      // 子命令参数
	flag *flag.FlagSet // 子命令参数解析器

}

type CmdInfo struct {
	CmdName string     // 子命令名称
	CmdDesc string     // 子命令描述
	CmdFunc SubcmdFunc // 子命令运行函数

}

type SubcmdFunc interface {
	ParseArgs(flag *flag.FlagSet, args []string) error
	Run() error
}

type errCode int

const (
	ErrParseArgs errCode = iota + 1
	ErrRun
	ErrNoCmd
)

var subcmds []*Subcmd

func init() {
	Register(CmdInfo{
		CmdName: "generate",
		CmdDesc: "generate package sbom info file",
		CmdFunc: generate_cmd.New(),
	})
	Register(CmdInfo{
		CmdName: "validate",
		CmdDesc: "verify the validity of the sbom file format",
		CmdFunc: validate_cmd.New(),
	})
	Register(CmdInfo{
		CmdName: "identity",
		CmdDesc: "package identity",
		CmdFunc: identity_cmd.New(),
	})
	Register(CmdInfo{
		CmdName: "sign",
		CmdDesc: "sign the sbom file",
		CmdFunc: sign_cmd.New(),
	})
	Register(CmdInfo{
		CmdName: "verify",
		CmdDesc: "verify signature of sbom file",
		CmdFunc: verify_cmd.New(),
	})
}

func Register(info CmdInfo) {
	cmd := &Subcmd{
		Info: info,
	}
	subcmds = append(subcmds, cmd)
}

func GetSubCmds() []*Subcmd {
	return subcmds
}

func Exec(name string) errCode {
	for _, cmd := range subcmds {
		if cmd.Info.CmdName == name {
			cmd.args = os.Args[2:]
			cmd.flag = flag.NewFlagSet(cmd.Info.CmdName, flag.ExitOnError)
			err := cmd.Info.CmdFunc.ParseArgs(cmd.flag, cmd.args)
			if err != nil {
				log.Error(err)
				cmd.flag.Usage()
				return ErrParseArgs
			}
			err = cmd.Info.CmdFunc.Run()
			if err != nil {
				log.Errorf("Failed to execute %s: %v", name, err)
				return ErrRun
			}
			return 0
		}
	}
	return ErrNoCmd
}
