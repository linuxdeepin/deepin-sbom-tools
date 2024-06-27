// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package deb

import (
	"deepin-sbom-tools/pkg/plugin"
	"deepin-sbom-tools/pkg/tool"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/utils"
)

type Deb struct {
	debInfo plugin.PkgInfo
}

func (d *Deb) GetPMVersion() (string, error) {
	output, err := exec.Command("dpkg", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (d *Deb) GetPlugInfo() plugin.PlugInfo {
	return plugin.PlugInfo{
		PlugName: "DEB",
		PlugVer:  "0.0.1",
	}
}

func (d *Deb) IsValid(path string) bool {
	_, err := d.GetPMVersion()
	if err != nil {
		return false
	}
	ok, err := tool.IsDebFile(path)
	if err != nil {
		return false
	}
	return ok
}

func (d *Deb) ParsePkgInfo(pkgPath string) (plugin.PkgInfo, error) {
	debCon, err := tool.ParseControlInfo(pkgPath)
	if err != nil {
		return plugin.PkgInfo{}, err
	}
	d.debInfo.Architecture = debCon.Architecture
	d.debInfo.Name = debCon.Name
	d.debInfo.Version = debCon.Version
	d.debInfo.Section = debCon.Section
	d.debInfo.Homepage = debCon.Homepage
	d.debInfo.Maintainer = debCon.Maintainer
	d.debInfo.Description = debCon.Description
	d.debInfo.Depends = debCon.Depends
	d.debInfo.InstalledSize = debCon.InstalledSize

	res := d.debInfo

	// 包文件hash
	tmpDir, err := ioutil.TempDir("/tmp", "*")
	if err != nil {
		return res, err
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	if err := exec.Command("dpkg-deb", "-R", pkgPath, tmpDir).Run(); err != nil {
		return res, err
	}
	allFilePaths, err := utils.GetAllFilePaths(tmpDir, []string{"DEBIAN"})
	if err != nil {
		return res, err
	}
	for _, f := range allFilePaths {
		if sha1, sha256, md5, sm3, err := tool.GetHashesForFilePath(path.Join(tmpDir, f)); err != nil {
			return res, err
		} else {
			res.FileList = append(res.FileList, &plugin.FileInfo{
				FileName: f,
				Hash: []common.Checksum{
					{Algorithm: common.SHA1, Value: sha1},
					{Algorithm: common.SHA256, Value: sha256},
					{Algorithm: common.MD5, Value: md5},
					{Algorithm: "SM3", Value: sm3},
				},
			})
		}
	}
	//解压读取文件信息，解析文件license,读取copyright
	//licensecheck:3.0.31-3
	copyrightName := tmpDir + "/usr/share/doc/" + res.Name + "/copyright"
	// out, err := exec.Command("licensecheck", "--copyright", "-m", "--deb-fmt", copyrightName).Output()
	// if err != nil {
	// 	return res, err
	// }

	// parts := strings.Split(strings.TrimRight(string(out), "\n"), "\t")
	// for i, part := range parts {
	// 	if i == 1 { //license
	// 		if part == "UNKNOWN" {
	// 			res.LicenseDeclared = "NOASSERTION"
	// 		} else {
	// 			res.LicenseDeclared = part
	// 		}
	// 	} else if i == 2 { //copyright
	// 		res.Copyright = strings.Replace(part, "-format/1.0/", "", -1)
	// 	}
	// }
	licenseStr := tool.FmtLicenses("AND", tool.GetLicenses(copyrightName))
	if licenseStr == "" {
		res.LicenseDeclared = "NOASSERTION"
	} else {
		res.LicenseDeclared = licenseStr
	}
	return res, nil
}

func New() *Deb {
	deb := new(Deb)
	return deb
}
