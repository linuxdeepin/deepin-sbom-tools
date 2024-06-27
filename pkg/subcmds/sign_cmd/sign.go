// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package sign_cmd

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

const (
	ErrAbsDir           = "[ERR] failed to abs the dir"
	ErrReadConfig       = "[ERR] failed to read the llconfig"
	ErrUnmarshalConfig  = "[ERR] failed to unmarshal the llconfig"
	ErrNoSigned         = "[ERR] no signed"
	ErrChunkELFDigest   = "[ERR] failed to chunk elf digest"
	ErrPKCS7Sign        = "[ERR] failed to sign pkcs#7|"
	ErrPKCS7Decode      = "[ERR] failed to decode pkcs#7"
	ErrSignFile         = "[ERR] failed to sign the file"
	ErrCopySignFile     = "[ERR] failed to copy sign file"
	ErrChmodSignFile    = "[ERR] failed to chmod file mode"
	ErrInsertSignV2File = "[ERR] failed to insert signV2 file"
	messageHereSameCert = "Here a same certificate present or p7 is wrong"
)

type signOpt struct {
	f       string
	prik    string
	o       string
	verbose bool
}

func New() *signOpt {
	return &signOpt{}
}

func (s *signOpt) ParseArgs(flag *flag.FlagSet, args []string) error {

	flag.StringVar(&s.f, "f", "", "the file to be signed")
	flag.StringVar(&s.prik, "prik", "", "the sign private key")
	flag.StringVar(&s.o, "o", "./", "the directory to save sign file")
	flag.BoolVar(&s.verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "sign [arguments]")
		fmt.Println("Example:", os.Args[0], "sign -f sbom.spdx.json -k key ")
		fmt.Println("arguments:")
		flag.PrintDefaults()
	}

	// 解析命令行参数
	flag.Parse(args)

	// 必要参数判断
	if s.f == "" || s.prik == "" {
		return fmt.Errorf("both file and private key must exist")
	}
	return nil
}

func (s *signOpt) Run() error {

	fileName := filepath.Base(s.f)
	filePath, err := filepath.Abs(s.f)
	if err != nil {
		return err
	}
	data, _ := ioutil.ReadFile(filePath)
	prikey, err := ioutil.ReadFile(s.prik)
	if err != nil {
		return err
	}

	keyHander, err := signverify.DetectKeyType(prikey, nil)
	if err != nil {
		return err
	}
	signature, err := keyHander.Sign(data)
	if err != nil {
		return err
	}

	signData := base64.RawStdEncoding.EncodeToString(signature)
	log.Debug(len(signature), signature)

	dirPath, _ := filepath.Abs(s.o)
	signFile := dirPath + "/" + fileName + ".sign"
	f, err := os.Create(signFile) //sbom.spdx.json.sign
	if err != nil {
		return err
	}

	defer f.Close()
	_, err = f.WriteString(signData)
	if err != nil {
		return err
	}

	log.Info(s.f, "sign success. save:", signFile)
	return nil
}
