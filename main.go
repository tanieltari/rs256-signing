package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func main() {
	payload, err := GenerateRandomPayload(8)
	if err != nil {
		log.Fatalln("failed to generate payload")
	}
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		log.Fatalln("failed to generate private key")
	}
	publicKey := &privateKey.PublicKey

	privateKeyPem := ExportRsaPrivateKeyAsPemStr(privateKey)
	publicKeyPem, err := ExportRsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		log.Fatalln("failed to export public key pem")
	}

	signature, err := SignPayload(payload, privateKey)
	if err != nil {
		log.Fatalln("failed to sign card id")
	}

	signatureValid, err := VerifySignature(payload, signature, publicKey)
	if err != nil {
		log.Fatalln("failed to verify signature")
	}

	fmt.Printf("Payload: 0x%x\n", payload)
	fmt.Printf("Signature valid: %t\n", signatureValid)
	fmt.Printf("Signature length: %d bytes\n", len(signature))
	fmt.Printf("Signature: 0x%x\n", signature)
	fmt.Printf("%s\n", privateKeyPem)
	fmt.Printf("%s\n", publicKeyPem)
}

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateRandomPayload(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func ExportRsaPrivateKeyAsPemStr(prvKey *rsa.PrivateKey) string {
	buf := x509.MarshalPKCS1PrivateKey(prvKey)
	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: buf,
		},
	)
	return string(pem)
}

func ExportRsaPublicKeyAsPemStr(pubKey *rsa.PublicKey) (string, error) {
	buf, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: buf,
		},
	)
	return string(pem), nil
}

func SignPayload(payload []byte, prvKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(payload)
	if err != nil {
		return nil, err
	}
	hashBuf := hash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, prvKey, crypto.SHA256, hashBuf, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifySignature(payload, signature []byte, pubKey *rsa.PublicKey) (bool, error) {
	hash := sha256.New()
	_, err := hash.Write(payload)
	if err != nil {
		return false, err
	}
	hashBuf := hash.Sum(nil)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashBuf, signature, nil)
	if err != nil {
		// Error means verification failed
		return false, nil
	}
	return true, nil
}
