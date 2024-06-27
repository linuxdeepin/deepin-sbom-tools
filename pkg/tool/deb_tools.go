// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package tool

import (
	"archive/tar"
	"bufio"
	"bytes"
	"deepin-sbom-tools/pkg/log"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz"
)

// IsDebFile 判断文件是否为 Deb 包文件
func IsDebFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// 读取文件的前六个字节
	magicBytes := make([]byte, 7)
	_, err = io.ReadFull(file, magicBytes)
	if err != nil {
		return false, err
	}

	// 判断文件是否以 "!<arch>" 开头
	return string(magicBytes) == "!<arch>", nil
}

type DebControl struct {
	Name          string
	Version       string
	Architecture  string
	Maintainer    string //upstream
	Depends       []string
	DependsOrig   string
	Homepage      string
	Section       string
	Description   string
	InstalledSize int
}

// Add to the field
func (d *DebControl) addToField(name string, data string) {
	switch name {
	case "Description":
		d.Description += " " + strings.TrimSpace(data)
	}
}

// Generic method to set any field
func (d *DebControl) setField(data ...string) error {
	if len(data) != 2 {
		return errors.New("data must have two elements only")
	}
	switch strings.TrimSpace(data[0]) {
	case "Package":
		d.Name = strings.TrimSpace(data[1])
	case "Version":
		d.Version = strings.TrimSpace(data[1])
	case "Architecture":
		d.Architecture = strings.TrimSpace(data[1])
	case "Section":
		d.Section = strings.TrimSpace(data[1])
	case "Homepage":
		d.Homepage = strings.TrimSpace(data[1])
	case "Maintainer":
		d.Maintainer = strings.TrimSpace(data[1])
	case "Description":
		d.Description = strings.TrimSpace(data[1])
	case "Depends":
		d.DependsOrig = strings.TrimSpace(data[1])
		d.Depends = parseDepends(strings.TrimSpace(data[1]))
	case "Installed-Size":
		i, err := strconv.Atoi(strings.TrimSpace(data[1]))
		if err == nil {
			d.InstalledSize = i
		} else {
			d.InstalledSize = 0
		}
	}

	return nil
}

// 解析Depends字段的函数
func parseDepends(depends string) []string {
	var vals []string
	if strings.Contains(depends, ",") || strings.Contains(depends, "|") || strings.Contains(depends, "(") {
		vals = regexp.MustCompile(`[\\,\\|]`).Split(depends, -1)
	} else {
		vals = strings.Split(depends, " ")
	}
	var result []string
	for _, val := range vals {
		val = strings.TrimSpace(val)
		if val != "" {
			result = append(result, strings.TrimSpace(val))
		}
	}
	return result
}

func ParseControlInfo(debPath string) (DebControl, error) {
	//读取deb包元信息
	output, err := exec.Command("dpkg", "-f", debPath).Output()
	if err != nil {
		return DebControl{}, err
	}

	var debCon DebControl
	var line string
	var namedata []string
	var currentName string
	scn := bufio.NewScanner(strings.NewReader(string(output)))
	for scn.Scan() {
		// Single field values
		line = scn.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			debCon.addToField(currentName, line) //description
		} else {
			namedata = strings.SplitN(line, ":", 2)
			currentName = namedata[0]
			debCon.setField(namedata...) // field
		}
	}
	return debCon, nil
}

// 提取 DEB 包的sbom信息
func extractControlInfo(debFile string) ([]byte, error) {
	var sbomTar = "sbom.tar.xz"
	var sbomContent bytes.Buffer
	// 解压 deb文件
	tmpDir, err := ioutil.TempDir("", "arDeb_")
	if err != nil {
		return nil, err
	}
	absPath, _ := filepath.Abs(debFile)
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("ar", "-x", absPath)
	cmd.Dir = tmpDir
	err = cmd.Run()
	if err != nil {
		return nil, errors.New("decompress deb file error")
	}

	sbomTarFile, err := os.Open(tmpDir + "/" + sbomTar)
	if err != nil {
		log.Debug(err)
		return nil, errors.New(sbomTar + " don't exist in deb")
	}
	defer sbomTarFile.Close()

	xzReader, err := xz.NewReader(sbomTarFile)
	if err != nil {
		return nil, err
	}
	// 解压 tar 归档
	tarReader := tar.NewReader(xzReader)

	// 读取 sbom 文件内容
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// fmt.Println(header.Name)
		if header.Name == "sbom.spdx.json" {
			// 读取 sbom 文件内容
			_, err := io.Copy(&sbomContent, tarReader)
			if err != nil {
				return nil, err
			}
		}
	}

	return sbomContent.Bytes(), nil
}

func GetDebSignInfo(deb string) ([]byte, error) {
	f, err := os.Open(deb)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	output, err := exec.Command("ar", "-p", deb, "sign").Output()
	if err != nil {
		return nil, err
	}
	return output, nil

}
