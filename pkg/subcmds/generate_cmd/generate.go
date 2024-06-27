// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package generate_cmd

import (
	"bufio"
	"path/filepath"
	"strings"

	"deepin-sbom-tools/pkg/doc"
	"deepin-sbom-tools/pkg/log"
	"deepin-sbom-tools/pkg/modules/deb"
	"deepin-sbom-tools/pkg/modules/rpm"
	"deepin-sbom-tools/pkg/plugin"
	"flag"
	"fmt"
	"os"

	"github.com/spdx/tools-golang/json"
)

var Plugins []plugin.Plugin

type generateOpt struct {
	input   string
	output  string
	format  string
	ns      string
	verbose bool
}

func New() *generateOpt {
	return &generateOpt{}
}

func (g *generateOpt) ParseArgs(flag *flag.FlagSet, args []string) error {
	flag.StringVar(&g.input, "i", "", "the package file which will be analyzed")
	flag.StringVar(&g.output, "o", "./", "the directory to save SPDX file")
	flag.StringVar(&g.format, "f", "spdx-json", "the SPDX file format")
	flag.StringVar(&g.ns, "ns", "https://www.deepin.org/namespace/package", "the sbom document namespace base url.")
	flag.BoolVar(&g.verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "generate [arguments]")
		fmt.Println("Example:", os.Args[0], "generate -i example.deb")
		fmt.Println("arguments:")
		flag.PrintDefaults()
	}

	// 解析命令行参数
	flag.Parse(args)

	// 必要参数判断
	if g.input == "" {
		return fmt.Errorf("the package file must exist")
	}
	return nil
}

func (g *generateOpt) Run() error {
	Plugins = []plugin.Plugin{
		deb.New(),
		rpm.New(),
	}

	pkgFilePath := g.input

	if f, err := os.Stat(g.output); err != nil || !f.IsDir() {
		return err
	}

	//2. pakcage process
	/*
		获取输入文件
		遍历可用插件 IsValid()
		解析软件包，获取包依赖 ParsePkgInfo()
	*/
	var plug plugin.Plugin
	isFoundPlug := false
	for _, plug = range Plugins {
		if plug.IsValid(pkgFilePath) {
			isFoundPlug = true
			plugInfo := plug.GetPlugInfo()
			log.Debug(plugInfo.PlugName, plugInfo.PlugVer)
			break
		}
	}
	if !isFoundPlug {
		return fmt.Errorf("%s unknown package type", pkgFilePath)
	}

	pkgInfo, err := plug.ParsePkgInfo(pkgFilePath)
	if err != nil {
		return err
	}

	//3. create document
	if !strings.HasSuffix(g.ns, "/") {
		g.ns = g.ns + "/"
	}
	document, err := doc.CreateDocument(pkgInfo, g.ns)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(g.output+"/"+"sbom.spdx.json", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	f.Truncate(0)

	defer f.Close()
	w := bufio.NewWriter(f)
	err = json.Write(document, w, json.EscapeHTML(false), json.Indent("\t"))
	if err != nil {
		return err
	}
	err = w.Flush()
	if err != nil {
		return err
	}
	path, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}
	log.Infof("SBOM written to %s\n", path)
	return nil
}
