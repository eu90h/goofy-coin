package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	_ "os"
	"reflect"
	"testing"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

type Signature struct {
	r, s *big.Int
}

func sign(message []byte, key *ecdsa.PrivateKey) *SignedMessage {
	cert := new(SignedMessage)
	hecksum := sha256.Sum256(message)
	b64 := base64.URLEncoding.EncodeToString(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, hecksum[:])
	check(err)
	cert.Message = b64
	cert.R = r.Text(16)
	cert.S = s.Text(16)
	return cert
}

func CreateClientCertificate(key *ecdsa.PrivateKey) *SignedMessage {
	bs := append(key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()...)
	return sign(bs, key)
}

var myKey *ecdsa.PrivateKey

func getFingerprint(key *ecdsa.PrivateKey) string {
	bs := append(key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()...)
	hecksum := sha256.Sum256(bs)
	b64 := base64.URLEncoding.EncodeToString(hecksum[:])
	return b64
}
func MakeAnotherAccount() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	fmt.Println(key.PublicKey.X.Text(16))

	fmt.Println(key.PublicKey.Y.Text(16))

	msg := CreateClientCertificate(key)
	jsonMsg, err := json.Marshal(msg)
	check(err)
	fmt.Println(string(jsonMsg))
	values := url.Values{}
	values.Add("message", msg.Message)
	values.Add("r", msg.R)
	values.Add("s", msg.S)
	resp, err := http.PostForm("http://localhost:8080/api/user/create", values)
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}
	return key, err
}

func TestCertificateSigning(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	myKey = key
	fmt.Println(key.PublicKey.X.Text(16))

	fmt.Println(key.PublicKey.Y.Text(16))

	msg := CreateClientCertificate(key)
	jsonMsg, err := json.Marshal(msg)
	check(err)
	fmt.Println(string(jsonMsg))
	values := url.Values{}
	values.Add("message", msg.Message)
	values.Add("r", msg.R)
	values.Add("s", msg.S)
	resp, err := http.PostForm("http://localhost:8080/api/user/create", values)
	check(err)
	if resp.StatusCode != http.StatusOK {
		t.Fail()
	}
}

func TestCoinCreation(t *testing.T) {
	receiver := getFingerprint(myKey)
	cmd := CreateCoinCommand{receiver}
	json, err := json.Marshal(&cmd)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(json))
	msg := sign(json, myKey)
	values := url.Values{}
	values.Add("message", msg.Message)
	values.Add("r", msg.R)
	values.Add("s", msg.S)
	resp, err := http.PostForm("http://localhost:8080/api/coin/create", values)
	check(err)
	if resp.StatusCode != http.StatusOK {
		t.Fail()
	}
	data, err := ioutil.ReadAll(resp.Body)
	check(err)
	fmt.Println(string(data))
}

func TestCoinTransfer(t *testing.T) {
	fmt.Println("creating another id...")
	someOtherKey, err := MakeAnotherAccount()
	check(err)
	if reflect.DeepEqual(someOtherKey, myKey) {
		t.Fail()
	}
	fmt.Println("second ID created!")
	receiver := getFingerprint(someOtherKey)
	sender := getFingerprint(myKey)
	cmd := TransferCoinCommand{sender, receiver}
	json, err := json.Marshal(&cmd)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(json))

	msg := sign(json, myKey)
	values := url.Values{}
	values.Add("message", msg.Message)
	values.Add("r", msg.R)
	values.Add("s", msg.S)
	resp, err := http.PostForm("http://localhost:8080/api/coin/transfer", values)
	check(err)
	if resp.StatusCode != http.StatusOK {
		t.Fail()
	}
	data, err := ioutil.ReadAll(resp.Body)
	check(err)
	fmt.Println(string(data))
}
