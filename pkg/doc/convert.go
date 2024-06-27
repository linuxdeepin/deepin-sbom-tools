// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doc

import (
	"crypto/sha1"
	"deepin-sbom-tools/pkg/plugin"
	"deepin-sbom-tools/pkg/version"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func genSPDXIdentifier(prefix string, s string) common.ElementID {
	hSHA1 := sha1.New()
	hSHA1.Write([]byte(s))
	return common.ElementID(fmt.Sprintf("%s-%x", prefix, hSHA1.Sum(nil)))
}

func CreateDocument(topLevelPkg plugin.PkgInfo, namespaceBase string) (*v2_3.Document, error) {
	//todo 空参数检查
	if topLevelPkg.Maintainer == "" {
		return nil, errors.New("not enough parameters")
	}
	docName := topLevelPkg.Name + "_" + topLevelPkg.Version + "_" + topLevelPkg.Architecture
	doc := &v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      docName,
		DocumentNamespace: namespaceBase + docName,
		CreationInfo: &v2_3.CreationInfo{
			Creators: []common.Creator{{
				Creator:     fmt.Sprintf("deepin-sbom-tools_" + version.VERSION),
				CreatorType: "Tool",
			}},
			Created: time.Now().UTC().Format(time.RFC3339),
		},
	}
	{
		doc.Packages = append(doc.Packages, &v2_3.Package{
			PackageName:             topLevelPkg.Name,
			PackageSPDXIdentifier:   genSPDXIdentifier("PACKAGE", topLevelPkg.Name),
			PackageDownloadLocation: "NOASSERTION",
			PackageVersion:          topLevelPkg.Version,
			PackageSupplier: &common.Supplier{
				Supplier:     strings.Replace(strings.Replace(topLevelPkg.Maintainer, "<", "(", -1), ">", ")", -1),
				SupplierType: "Organization",
			},
			PackageLicenseDeclared: topLevelPkg.LicenseDeclared,
			PackageCopyrightText:   topLevelPkg.Copyright,
			FilesAnalyzed:          false,
			PackageDescription:     topLevelPkg.Description,
			PackageHomePage:        topLevelPkg.Homepage,
		})
		doc.Relationships = append(doc.Relationships, &v2_3.Relationship{
			RefA:         common.DocElementID{ElementRefID: doc.SPDXIdentifier},
			RefB:         common.DocElementID{ElementRefID: doc.Packages[0].PackageSPDXIdentifier},
			Relationship: "DESCRIBES",
		})
		for cnt, pkg := range topLevelPkg.Depends {
			var name string
			var ver string
			idx := strings.Split(pkg, " ")
			if len(idx) == 3 {
				name = idx[0]
				ver = strings.TrimRight(idx[2], ")")
			} else {
				name = pkg
			}
			name = strings.Split(name, ":")[0]
			doc.Packages = append(doc.Packages, &v2_3.Package{
				PackageName:             name,
				PackageVersion:          ver,
				PackageSPDXIdentifier:   genSPDXIdentifier("DEPEND", pkg),
				PackageDownloadLocation: "NOASSERTION",
			})
			doc.Relationships = append(doc.Relationships, &v2_3.Relationship{
				RefA:         common.DocElementID{ElementRefID: doc.Packages[0].PackageSPDXIdentifier},
				RefB:         common.DocElementID{ElementRefID: doc.Packages[cnt+1].PackageSPDXIdentifier},
				Relationship: "DEPENDS_ON",
			})
		}
	}
	{
		// fmt.Println(topLevelPkg.FileList)
		for _, v := range topLevelPkg.FileList {
			doc.Files = append(doc.Files, &v2_3.File{
				FileName:           v.FileName,
				FileSPDXIdentifier: genSPDXIdentifier("FILE", v.FileName),
				Checksums:          v.Hash,
				FileCopyrightText:  "NOASSERTION",
			})
		}
	}
	return doc, nil
}
