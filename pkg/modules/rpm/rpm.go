// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package rpm

import (
	"deepin-sbom-tools/pkg/plugin"
	"os/exec"
)

type Rpm struct{}

func (r *Rpm) GetPMVersion() (string, error) {
	output, err := exec.Command("rpm", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (r *Rpm) GetPlugInfo() plugin.PlugInfo {
	return plugin.PlugInfo{
		PlugName: "RPM",
		PlugVer:  "0.0.2",
	}

}

func (r *Rpm) IsValid(path string) bool {
	_, err := r.GetPMVersion()
	return err == nil
}

func (r *Rpm) ParsePkgInfo(path string) (plugin.PkgInfo, error) {

	return plugin.PkgInfo{}, nil
}

func New() *Rpm {
	rpm := new(Rpm)
	return rpm
}
