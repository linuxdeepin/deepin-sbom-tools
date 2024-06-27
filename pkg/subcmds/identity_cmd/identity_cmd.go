// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package identity_cmd

import (
	"deepin-sbom-tools/pkg/log"
	"deepin-sbom-tools/pkg/tool"
	"flag"
	"fmt"
	"os"
)

type identityOpt struct {
	filePath string
	verify   string
	verbose  bool
}

func New() *identityOpt {
	return &identityOpt{}
}

func (u *identityOpt) ParseArgs(flag *flag.FlagSet, args []string) error {
	flag.StringVar(&u.filePath, "f", "", "package to be identitied")
	flag.StringVar(&u.verify, "verify", "", "verify package identitiy")
	flag.BoolVar(&u.verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "identity [arguments]")
		fmt.Println("Example:", os.Args[0], "identity -f example.deb ")
		fmt.Println("arguments:")
		flag.PrintDefaults()
	}
	// 解析命令行参数
	flag.Parse(args)

	// 必要参数判断
	if u.filePath == "" {
		return fmt.Errorf("deb must exist")
	}

	return nil
}

func (u *identityOpt) Run() error {

	debSha1, err := tool.CalculateSHA1(u.filePath) //deb hash
	if err != nil {
		return err
	}
	if u.verify != "" {
		if debSha1 == u.verify {
			log.Info("identity verification successful")
			return nil
		} else {
			log.Info("identity verification failed")
			log.Debug("expect:  " + debSha1)
			log.Debug("receive: " + u.verify)
			return fmt.Errorf("identity inconsistent")
		}

	}
	log.Info("generate pacakgeID:", debSha1)
	return nil
}
