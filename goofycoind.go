package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/segmentio/ksuid"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"reflect"
)

type KeyParams struct {
	D, X, Y *big.Int
	Tag     string
}

type UserModel struct {
	ID      string
	PubKeyX string
	PubKeyY string
	Coins   []CoinModel `gorm:"foreignkey:OwnerID"`
}

type CoinModel struct {
	ID      string
	OwnerID string
}
type SignedMessage struct {
	Message string
	R       string
	S       string
}

func createNewCoin(ownerKey *ecdsa.PrivateKey) (*SignedMessage, string) {
	id := ksuid.New().String()
	coinStr := "CreateCoin " + id
	checksum := sha256.Sum256([]byte(coinStr))
	r, s, err := ecdsa.Sign(rand.Reader, ownerKey, checksum[:])
	if err != nil {
		panic(err)
	}
	//TODO: verify the newly created signature
	msg := new(SignedMessage)
	msg.Message = coinStr
	msg.R = r.Text(16)
	msg.S = s.Text(16)
	return msg, id
}

func TransferCoinHandler(w http.ResponseWriter, r *http.Request) {
	b64Message := r.PostFormValue("message")
	message, err := base64.URLEncoding.DecodeString(b64Message)
	if err != nil {
		panic(err)
	}
	var cmd *TransferCoinCommand
	json.Unmarshal(message, &cmd)
	//disallow sending a coin from yourself to yourself, since it's pointless
	if cmd.Sender == cmd.Receiver {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	R := r.PostFormValue("r")
	S := r.PostFormValue("s")
	pr := new(big.Int)
	pr, success := pr.SetString(R, 16)
	if !success {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	ps := new(big.Int)
	ps, success = ps.SetString(S, 16)
	if !success {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	if VerifyMessage(cmd.Sender, message, pr, ps) {
		//check to see if sender and receiver exist
		sendingUser, userFound := lookupUser(cmd.Sender)
		if !userFound {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}
		receivingUser, userFound := lookupUser(cmd.Receiver)
		if !userFound {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}

		//check if the sender actually owns a coin
		cs := getUsersCoins(sendingUser)
		if cs[0].OwnerID != sendingUser.ID || len(cs) <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}
		c := cs[0]
		db.Model(&c).Update("owner_id", receivingUser.ID)

		//check if the coin's owner has properly changed
		sendersCoins := getUsersCoins(sendingUser)
		receiversCoins := getUsersCoins(receivingUser)
		if len(sendersCoins) != 0 && len(receiversCoins) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}

		//everything appears OK, so notify the sender
		w.WriteHeader(http.StatusOK)
	} else {
		//signature failed to verify
		w.WriteHeader(http.StatusBadRequest)
	}
}

type CreateCoinCommand struct {
	Receiver string
}
type TransferCoinCommand struct {
	Sender   string
	Receiver string
}

func CreateCoinHandler(w http.ResponseWriter, r *http.Request) {
	b64Message := r.PostFormValue("message")
	message, err := base64.URLEncoding.DecodeString(b64Message)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	var cmd *CreateCoinCommand
	json.Unmarshal(message, &cmd)
	R := r.PostFormValue("r")
	S := r.PostFormValue("s")
	pr := new(big.Int)
	pr, success := pr.SetString(R, 16)
	if !success {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	ps := new(big.Int)
	ps, success = ps.SetString(S, 16)
	if !success {
		w.WriteHeader(http.StatusBadRequest)
		//TODO: send a JSON encoded error response
		return
	}
	if VerifyMessage(cmd.Receiver, message, pr, ps) {
		response, coinID := createNewCoin(goofyKey)
		user, userFound := lookupUser(cmd.Receiver)
		if !userFound {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}

		c := CoinModel{coinID, cmd.Receiver}
		db.Create(&c)
		db.Model(user).Update("coins", [1]string{c.ID})
		db.Model(user).Association("Coins").Append(c)

		json, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}
		u2, userFound := lookupUser(cmd.Receiver)
		if !userFound {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}
		//ensure the user posesses the created coin
		cs := getUsersCoins(u2)
		if len(cs) <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			//TODO: send a JSON encoded error response
			return
		}

		//everything looks OK, so send back a response
		w.WriteHeader(http.StatusOK)
		w.Write(json)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (u *UserModel) PublicKey() *ecdsa.PublicKey {
	pubKey := new(ecdsa.PublicKey)
	x := new(big.Int)
	_, err := x.SetString(u.PubKeyX, 16)
	if !err {
		panic(err)
	}
	y := new(big.Int)
	_, err = y.SetString(u.PubKeyY, 16)
	if !err {
		panic(err)
	}
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = elliptic.P256()
	return pubKey
}

func lookupUser(fingerprint string) (*UserModel, bool) {
	user := UserModel{}
	db.Where("ID = ?", fingerprint).First(&user)
	return &user, !reflect.DeepEqual(user, UserModel{})
}

func getUsersCoins(user *UserModel) []CoinModel {
	coins := []CoinModel{}
	db.Where("owner_id = ?", user.ID).Find(&coins)
	return coins
}

func VerifyMessage(fingerprint string, msg []byte, r *big.Int, s *big.Int) bool {
	//NOTE: do we actually need to lookup the user here?
	//			maybe passing in a UserModel is better?
	user, userFound := lookupUser(fingerprint)
	if !userFound {
		//TODO: do something better than panic
		panic("cant find user " + fingerprint)
	}
	pubKey := user.PublicKey()
	checksum := sha256.Sum256(msg)
	verified := ecdsa.Verify(pubKey, checksum[:], r, s)
	return verified
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	b64Message := r.PostFormValue("message")
	R := r.PostFormValue("r")
	S := r.PostFormValue("s")
	message, err := base64.URLEncoding.DecodeString(b64Message)
	if err != nil {
		panic(err)
	}
	checksum := sha256.Sum256(message)
	X := message[0:32]
	Y := message[32:]
	x := new(big.Int)
	x = x.SetBytes(X)
	y := new(big.Int)
	y = y.SetBytes(Y)
	xs := x.Text(16)
	ys := y.Text(16)
	fmt.Println(xs)
	fmt.Println(ys)

	pubKey := new(ecdsa.PublicKey)
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = elliptic.P256()

	pr := new(big.Int)
	pr, success := pr.SetString(R, 16)
	if !success {
		panic(err)
	}
	ps := new(big.Int)
	ps, success = ps.SetString(S, 16)
	if err != nil {
		panic(err)
	}
	if ecdsa.Verify(pubKey, checksum[:], pr, ps) {
		fingerprint := base64.URLEncoding.EncodeToString(checksum[:])
		user := UserModel{ID: fingerprint, PubKeyX: xs, PubKeyY: ys, Coins: []CoinModel{}}
		db.NewRecord(&user)
		db.Create(&user)
		u2, _ := lookupUser(fingerprint)
		if user.ID != u2.ID || user.PubKeyX != u2.PubKeyX || user.PubKeyY != u2.PubKeyY { //reflect.DeepEqual(user, u2) == false {
			panic(u2)
		}
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func initDB() *gorm.DB {
	dbFile := "tutcoin.db"
	db, err := gorm.Open("sqlite3", dbFile)
	if err != nil {
		panic(err)
	}
	if DEBUG {
		fmt.Println("dropping tables...")
		db.DropTable("user_models")
		db.DropTable("coin_models")
		db.LogMode(true)
	}
	if !db.HasTable("user_models") {
		fmt.Println("creating user_models table...")
		db.CreateTable(&UserModel{})
	}
	if !db.HasTable("coin_models") {
		fmt.Println("creating coin_models table...")
		db.CreateTable(&CoinModel{})
	}
	return db
}

func writeKey(filePath string, key *ecdsa.PrivateKey) error {
	keyParams := KeyParams{key.D, key.PublicKey.X, key.PublicKey.Y, "p256"}
	jsonKeyParams, err := json.Marshal(keyParams)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filePath, jsonKeyParams, 0644)
	return err
}

func readKey(filePath string, key *ecdsa.PrivateKey) error {
	jsonKeyParams, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	keyParams := new(KeyParams)
	err = json.Unmarshal(jsonKeyParams, keyParams)
	key.D = keyParams.D
	key.PublicKey = ecdsa.PublicKey{elliptic.P256(), keyParams.X, keyParams.Y}
	return err
}

func loadOrCreateServerKey() *ecdsa.PrivateKey {
	filename := "serverKeys.json"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Println("generating server keys...")
		key := generateKeys(elliptic.P256(), "p256")
		fmt.Println("saving server keys to " + filename)
		err := writeKey(filename, key)
		if err != nil {
			panic(err)
		}
		return key
	} else {
		fmt.Println("loading goofy keys...")
		var key = new(ecdsa.PrivateKey)
		err := readKey(filename, key)
		if err != nil {
			panic(err)
		}
		return key
	}
}

func generateKeys(c elliptic.Curve, tag string) *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		panic(tag + ": public key invalid: " + err.Error())
	}
	return priv
}

var DEBUG = true
var db = initDB()
var goofyKey = loadOrCreateServerKey()

func main() {
	fmt.Println("SERVER KEY:")
	fmt.Println(goofyKey)
	http.HandleFunc("/api/user/create", CreateUserHandler)
	http.HandleFunc("/api/coin/create", CreateCoinHandler)
	http.HandleFunc("/api/coin/transfer", TransferCoinHandler)

	http.ListenAndServe(":8080", nil)
}
