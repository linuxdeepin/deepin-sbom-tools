// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package plugin

import "github.com/spdx/tools-golang/spdx/v2/common"

// 插件接口
// 软件包通用接口
type Plugin interface {
	GetPlugInfo() PlugInfo                     //获取通用软件包管理器信息
	GetPMVersion() (string, error)             //软件包管理器版本
	IsValid(path string) bool                  //是否需要解析器解析当前软件包
	ParsePkgInfo(path string) (PkgInfo, error) //解析包信息
}

// 插件信息
type PlugInfo struct {
	PlugName string
	PlugVer  string
}

// 软件包通用信息
type FileInfo struct {
	FileName string
	Hash     []common.Checksum
}

// 通用包信息
type PkgInfo struct {
	Name             string
	Version          string
	Architecture     string
	Maintainer       string //upstream
	Copyright        string
	Depends          []string
	LicenseDeclared  string
	DownloadLocation string
	Homepage         string
	Section          string
	Description      string
	InstalledSize    int
	FileList         []*FileInfo //包文件
}
