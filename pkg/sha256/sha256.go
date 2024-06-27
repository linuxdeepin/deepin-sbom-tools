// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package sha256

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/panjf2000/ants"
)

var defaultChunkSize int = 1024 * 1024

// @description	分块摘要计算
// @auth		zhangya@uniontech.com	Thu 14 Apr 2022 01:42:30
// @param		要计算的数据
// @return		摘要结果，错误
func ChunkSha256(data []byte) ([]byte, error) {
	list, err := calcChunkHash(data)
	if err != nil {
		return nil, err
	}

	safeTyHash := sha256.New()
	for i := 0; i < len(list); i++ {
		safeTyHash.Write(list[i][:])
	}

	return safeTyHash.Sum(nil), nil
}

// @description	计算所有块的sha256摘要
// @auth		zhangya@uniontech.com	Thu 14 Apr 2022 01:42:30
// @param		要计算的数据
// @return		所有块的摘要结果列表，错误
func calcChunkHash(data []byte) ([][]byte, error) {
	list, num := makeChunk(data)

	var wg sync.WaitGroup
	pool, err := ants.NewPoolWithFunc(num, func(index interface{}) {
		idx := index.(int)
		end := (idx + 1) * defaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		safeTyHash := sha256.New()
		safeTyHash.Write(data[idx*defaultChunkSize : end])

		res := safeTyHash.Sum(nil)

		if len(res) != 0 {
			list[idx] = res
		}
		wg.Done()
	})
	if err != nil {
		return nil, err
	}
	defer pool.Release()

	for i := 0; i < num; i++ {
		wg.Add(1)
		_ = pool.Invoke(i)
	}
	wg.Wait()

	return list, nil
}

// @description	对数据按1M进行分块
// @auth		zhangya@uniontech.com	Thu 14 Apr 2022 01:42:30
// @param		要计算的数据
// @return		摘要的保存列表，分块的数目
func makeChunk(data []byte) ([][]byte, int) {
	total := len(data)
	num := total >> 20
	if total%defaultChunkSize != 0 {
		num += 1
	}

	var list = make([][]byte, num)
	return list, num
}

func IsoChunkSha256(l int64, fd *os.File) ([]byte, error) {
	list, err := isoCalcChunkHash(l, fd)
	if err != nil {
		return nil, err
	}

	safeTyHash := sha256.New()
	for i := 0; i < len(list); i++ {
		safeTyHash.Write(list[i][:])
	}

	return safeTyHash.Sum(nil), nil
}

type chunkObject struct {
	index int
	buf   []byte
}

func isoCalcChunkHash(l int64, fd *os.File) ([][]byte, error) {
	list, num := isoMakeChunk(l)
	var wg sync.WaitGroup
	pool, err := ants.NewPoolWithFunc(int(num), func(chunk interface{}) {
		data := chunk.(chunkObject).buf
		idx := chunk.(chunkObject).index
		safeTyHash := sha256.New()
		safeTyHash.Write(data)

		res := safeTyHash.Sum(nil)

		if len(res) != 0 {
			list[idx] = res
		}
		wg.Done()
	})
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer pool.Release()
	var i = 0
	buf := make([]byte, defaultChunkSize)
	for {
		_, err := fd.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				fmt.Println("Read file error!", err)
				return nil, err
			}
		}
		chunkData := make([]byte, defaultChunkSize)
		copy(chunkData, buf)
		wg.Add(1)
		_ = pool.Invoke(chunkObject{
			i,
			chunkData,
		})
		i++
	}

	wg.Wait()
	return list, nil
}

func isoMakeChunk(total int64) ([][]byte, int64) {
	num := total >> 20
	if total%int64(defaultChunkSize) != 0 {
		num += 1
	}

	var list = make([][]byte, num)
	return list, num
}

// @title		doSha256
// @description	对文件或者文件内容做sha256摘要
// @auth		hushijia@uniontech.com	2020/8/24	20:06
// @param		i,retFlag	interface{},int	“处理string和[]byte类型的数据“,“指定返回的类型”
// @return		fileSHA,err	interface{},error	“sha值”,“错误信息”
func doSha256(i interface{}, retFlag int) (interface{}, error) {
	var retStringType = 1
	var retByteArrayType = 2
	safeTyHash := sha256.New()
	switch i.(type) {
	case string:
		f, err := os.Open(i.(string))
		if err != nil {
			return nil, errors.New("failed to open file")
		}
		defer f.Close()
		if _, err := io.Copy(safeTyHash, f); err != nil {
			return nil, errors.New("failed to sha256 file")
		}
	case []byte:
		safeTyHash.Write(i.([]byte))
	default:
		return nil, errors.New("sha256 input error")
	}
	if retFlag == retStringType {
		fileSHA := hex.EncodeToString(safeTyHash.Sum(nil))
		return fileSHA, nil
	} else if retFlag == retByteArrayType {
		return safeTyHash.Sum(nil), nil
	}
	return nil, errors.New("failed to sha256 file")
}

// @title		Sha256FileToString
// @description	对文件做sha256摘要
// @auth		hushijia@uniontech.com	2020/8/24	20:06
// @param		fileName	string	“处理string类型的文件“
// @return		ret,err	string,error	“string类型sha值”,“错误信息”
func Sha256FileToString(fileName string) (string, error) {
	ret, err := doSha256(fileName, 1)
	if err != nil {
		return "", err
	}
	return ret.(string), err
}

// @title		Sha256File
// @description	对文件做sha256摘要
// @auth		hushijia@uniontech.com	2020/8/24	20:06
// @param		fileName	string	“处理string类型的文件“
// @return		ret,err	[]byte,error	“[]byte类型sha值”,“错误信息”
func Sha256File(fileName string) ([]byte, error) {
	ret, err := doSha256(fileName, 2)
	if err != nil {
		return nil, err
	}
	return ret.([]byte), err
}

// @title		Sha256ToString
// @description	对文件内容做sha256摘要
// @auth		hushijia@uniontech.com	2020/8/24	20:06
// @param		fileInfo	[]byte	“处理[]byte类型的数据“
// @return		ret,err	string,error	“string类型sha值”,“错误信息”
func Sha256ToString(fileInfo []byte) (string, error) {
	ret, err := doSha256(fileInfo, 1)
	if err != nil {
		return "", err
	}
	return ret.(string), err
}

// @title		Sha256
// @description	对文件内容做sha256摘要
// @auth		hushijia@uniontech.com	2020/8/24	20:06
// @param		fileInfo	[]byte	“处理[]byte类型的数据“
// @return		ret,err	[]byte,error	“[]byte类型sha值”,“错误信息”
func Sha256(fileInfo []byte) ([]byte, error) {
	ret, err := doSha256(fileInfo, 2)
	if err != nil {
		return nil, err
	}
	return ret.([]byte), err
}
