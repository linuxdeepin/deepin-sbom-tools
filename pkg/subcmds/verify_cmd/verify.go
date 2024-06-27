// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package verify_cmd

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"deepin-sbom-tools/pkg/log"
	"deepin-sbom-tools/pkg/signverify"
)

type verifyOpt struct {
	f       string
	s       string
	pubk    string
	verbose bool
}

func New() *verifyOpt {
	return &verifyOpt{}
}

func (v *verifyOpt) ParseArgs(flag *flag.FlagSet, args []string) error {

	flag.StringVar(&v.f, "f", "", "the original file , this argument must be present")
	flag.StringVar(&v.s, "s", "", "the signature file to be verified, this argument must be present")
	flag.StringVar(&v.pubk, "pubk", "", "the sign public key")
	flag.BoolVar(&v.verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "verify [arguments]")
		fmt.Println("Example:", os.Args[0], "verify -f sbom.spdx.json  -s sbom.spdx.json.sign -pubk key")
		fmt.Println("arguments:")
		flag.PrintDefaults()
	}

	// 解析命令行参数
	flag.Parse(args)

	// 必要参数判断
	if v.f == "" || v.s == "" || v.pubk == "" {
		return fmt.Errorf("both file, signature and pubkey must exist")
	}
	return nil
}

func (v *verifyOpt) Run() error {

	filePath, err := filepath.Abs(v.f)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	signPath, err := filepath.Abs(v.s)
	if err != nil {
		return err
	}
	signData, err := ioutil.ReadFile(signPath)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(string(signData))
	if err != nil {
		return err
	}
	log.Debug(len(signature), signature)

	pubkey, err := ioutil.ReadFile(v.pubk)
	if err != nil {
		return err
	}

	keyHander, err := signverify.DetectKeyType(nil, pubkey)
	if err != nil {
		return err
	}
	err = keyHander.Verify(data, signature)
	if err != nil {
		return err
	}
	log.Info(v.f, "verify success")
	return nil
}
