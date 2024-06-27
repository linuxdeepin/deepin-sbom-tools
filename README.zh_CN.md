
# deepin通用软件包标识化工具
[English](./README.md) | [简体中文](./README.zh_CN.md)

## 目录
- [总览](#overview)
- [工具集合](#sets)
  - [package-sbom-tool](#package-sbom-tool)
- [TODO](#todo)
- [快速开始](#quick-start)



## 总览<a name="overview"></a>
deepin通用软件包SBOM工具集包含软件包deepin-sbom-tools

**deepin-sbom-tools**

包含软件包软件包标识化生成工具`package-sbom-tool` 
 ```bash
deepin-sbom-tools include:
|_/package-sbom-tool  
 ```


## 工具集合<a name="sets"></a>
 - package-sbom-tool (通用软件包唯一标识生成、SBOM生成工具\验证，SBOM签名\验证)



### package-sbom-tool<a name="package-sbom-tool"></a>

```bash
Usage:  ./package-sbom-tool  <command> [arguments]
Commands:
  generate      generate package sbom info file
  validate      verify the validity of the sbom file format
  identity      package identity
  sign          sign the sbom file
  verify        verify signature of sbom file
Arguments:
  -v    enable verbose mode
  -version
        display the version of tool
```


package-sbom-tool用于针对通用软件包生成符合SPDX标准的SBOM信息。
它是一个命令行工具，工具所采集的软件包信息包括了文件组成、依赖信息、版权、许可证。
工具产生的SBOM信息符合SPDX v2.3规范。

#### 功能特性

项目的主要功能或特性。

1. 支持DEB包元信息解析、文件指纹生成、版权、许可证提取
2. 支持包信息SPDX json格式输出
3. 支持对软件包生成唯一标识。
4. 支持对sbom文件进行签名，生成签名文件。
5. 支持对sbom文件签名信息进行验证。保证真实性和完整性。
6. ......


#### 支持的通用软件包格式

- DEB
- RPM (todo)
- Snap (todo)
- Flatpak (todo)
- Appimage (todo)


## TODO<a name="todo"></a>

**已完成**

1. deb软件包SBOM生成、验证。
2. 软件包唯一标识生成、验证。
3. sbom文件签名、验证。



## 快速开始<a name="quick-start"></a>

提供一些简短的步骤，让用户能够快速启动你的项目。

### 安装依赖

```bash
go get github.com/google/licensecheck 
go get github.com/panjf2000/ants 
go get github.com/spdx/tools-golang 
go get github.com/tjfoc/gmsm
go get github.com/ulikunitz/xz
```

### 编译


```bash
make
```


### 运行

1. 生成example.deb软件包sbom信息。
```bash
package-sbom-tool generate -i example.deb
```

2. 验证example.deb软件包sbom信息。
```bash
package-sbom-tool validate -i sbom.spdx.json
```

3. 对example.deb软件包生成标识以及验证。
```bash
package-sbom-tool identity -f example.deb
package-sbom-tool identity -f example.deb -verify pacakgeID
```

4. 对sbom信息签名
```bash
package-sbom-tool sign -f sbom.spdx.json -prik priv.key
```

5. 对sbom.signd签名信息验证
```bash
package-sbom-tool verify -f sbom.spdx.json -s sbom.spdx.json.signed -pubk pub.key
```