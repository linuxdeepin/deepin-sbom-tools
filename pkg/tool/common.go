// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package tool

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/licensecheck"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/utils"
	"github.com/tjfoc/gmsm/sm3"
)

func fileHash(filePath string, algorithms map[common.ChecksumAlgorithm]hash.Hash) ([]common.Checksum, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	res := []common.Checksum{}
	for k, v := range algorithms {
		if _, err := io.Copy(v, file); err == nil {
			res = append(res, common.Checksum{Algorithm: k, Value: hex.EncodeToString(v.Sum(nil))})
		}
	}

	return res, nil
}

func PackageCheckSum(filePath string) ([]common.Checksum, error) {
	return fileHash(filePath, map[common.ChecksumAlgorithm]hash.Hash{
		common.MD5:    md5.New(),
		common.SHA256: sha256.New(),
	})
}

func CutPrefix(s, prefix string) string {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

func GetHashesForFilePath(p string) (string, string, string, string, error) {
	var sha1, sha256, md5 string
	var data []byte
	var err error
	if sha1, sha256, md5, err = utils.GetHashesForFilePath(p); err != nil {
		return "", "", "", "", err
	}
	if data, err = ioutil.ReadFile(p); err != nil {
		return "", "", "", "", err
	}
	return sha1, sha256, md5, fmt.Sprintf("%x", sm3.Sm3Sum(data)), nil
}

func CalculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CalculateSHA1(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func GetLicenses(file string) []string {
	text, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	cov := licensecheck.Scan([]byte(text))
	// fmt.Printf("%.1f%% of text covered by licenses:\n", cov.Percent)
	var licenseList []string
	for _, m := range cov.Match {
		// fmt.Printf("%s at [%d:%d] IsURL=%v\n", m.ID, m.Start, m.End, m.IsURL)
		var flag bool
		for _, license := range licenseList {
			if license == m.ID {
				flag = true
				break
			}
		}
		if flag {
			continue
		}
		licenseList = append(licenseList, m.ID)
	}
	return licenseList
}

func FmtLicenses(operator string, licenseList []string) string {
	len := len(licenseList)
	if len == 0 {
		return ""
	}
	if len == 1 {
		return licenseList[0]
	}

	var sb strings.Builder
	sb.WriteByte('(')
	for i, license := range licenseList {
		sb.WriteString(license)
		if i < len-1 {
			sb.WriteString(" " + operator + " ")
		}
	}
	sb.WriteByte(')')
	return sb.String()
}
