// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package signverify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	sm2x509 "github.com/tjfoc/gmsm/x509"
)

type SignatureVerifier interface {
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte) error
}

type RSAKey struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type SM2Key struct {
	privateKey *sm2.PrivateKey
	publicKey  *sm2.PublicKey
}

func NewRSAKey(privateKeyPEM []byte, publicKeyPEM []byte) (*RSAKey, error) {
	var rsaKey RSAKey
	if privateKeyPEM != nil {
		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the private key")
		}
		priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) //需要支持pkcs1格式
		if err != nil {
			return nil, err
		}
		rsaKey.privateKey = priKey.(*rsa.PrivateKey)
	}
	if publicKeyPEM != nil {
		block, _ := pem.Decode(publicKeyPEM)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the publickey key")
		}
		pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey.publicKey = pubkey.(*rsa.PublicKey)
	}

	return &rsaKey, nil

}

func (r *RSAKey) Sign(data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := r.privateKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
func (r *RSAKey) Verify(data []byte, signature []byte) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, hashed[:], signature)
}

func NewSM2Key(privateKeyPEM []byte, publicKeyPEM []byte) (*SM2Key, error) {
	var sm2Key SM2Key
	if privateKeyPEM != nil {
		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the private key")
		}
		priKey, err := sm2x509.ParsePKCS8PrivateKey(block.Bytes, nil) //需要支持pkcs1格式
		if err != nil {
			return nil, err
		}
		sm2Key.privateKey = priKey
	}
	if publicKeyPEM != nil {
		block, _ := pem.Decode(publicKeyPEM)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the public key")
		}
		pubKey, err := sm2x509.ParseSm2PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		sm2Key.publicKey = pubKey
	}
	return &sm2Key, nil
}

func (s *SM2Key) Sign(data []byte) ([]byte, error) {
	sign, err := s.privateKey.Sign(rand.Reader, data, nil) // Marshal(r,s)
	if err != nil {
		return nil, err
	}
	return sign, nil
}
func (s *SM2Key) Verify(data []byte, signature []byte) error {
	ok := s.publicKey.Verify(data, signature)
	if ok {
		return nil
	} else {
		return fmt.Errorf("sm2 verify fail")
	}
}

func DetectKeyType(privateKeyPEM []byte, publicKeyPEM []byte) (SignatureVerifier, error) {
	rsaHander, err := NewRSAKey(privateKeyPEM, publicKeyPEM)
	if err == nil {
		return rsaHander, nil
	}

	sm2Hander, err := NewSM2Key(privateKeyPEM, publicKeyPEM)
	if err == nil {
		return sm2Hander, nil
	}

	return nil, errors.New("unsupported private key type")
}
