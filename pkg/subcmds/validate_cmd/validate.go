// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package validate_cmd

import (
	"deepin-sbom-tools/pkg/log"
	"flag"
	"fmt"
	"os"

	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdxlib"
)

type validateOpt struct {
	input   string
	format  string
	verbose bool
}

func New() *validateOpt {
	return &validateOpt{}
}

func (v *validateOpt) ParseArgs(flag *flag.FlagSet, args []string) error {
	flag.StringVar(&v.input, "i", "", "the sbom file which will be validated")
	flag.StringVar(&v.format, "f", "spdx-json", "the SPDX file format")
	flag.BoolVar(&v.verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "validate [arguments]")
		fmt.Println("Example:", os.Args[0], "validate -i sbom.spdx.json")
		fmt.Println("arguments:")
		flag.PrintDefaults()
	}

	// 解析命令行参数
	flag.Parse(args)

	// 必要参数判断
	if v.input == "" {
		return fmt.Errorf("the sbom file must exist")
	}
	return nil
}

func (v *validateOpt) Run() error {

	f, err := os.Open(v.input)
	if err != nil {
		return err
	}
	defer f.Close()
	doc, err := json.Read(f)
	if err != nil {
		return err
	}
	err = spdxlib.ValidateDocument(doc)
	if err != nil {
		log.Info(v.input, "validate failed")
		return err
	}
	log.Info(v.input, "validate success")
	return nil

}
