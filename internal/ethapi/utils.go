package ethapi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"time"

	"github.com/usechain/go-usechain/accounts/cacertreg"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/ecies"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
)

const (
	IDCard          = "01"
	PassPort        = "02"
	DriverCard      = "03"
	SocialCard      = "04"
	EducationCert   = "10"
	ImmovablesCert  = "20"
	DepositCert     = "21"
	Car             = "22"
	Stock           = "23"
	Career          = "30"
	Other           = "40"
	BusinessLicense = "50"
)

//when user upload identity information first time, it will checks if information format is ok
func checkInfoFormat(idInfo string) error {
	var info cacertreg.IDInformation
	err := json.Unmarshal([]byte(idInfo), &info)
	if err != nil {
		return err
	}
	if info.Idtype == "" {
		return idTypeEmptyError
	}
	if info.Idnum == "" || info.Name == "" || info.Sex == "" || info.Country == "" || info.Address == "" || info.Birthdate == "" {
		return infoMissingError
	}
	//=======================temporary code
	if info.Idtype == IDCard || info.Idtype == SocialCard {
		result := checkIDcardNum(info.Idnum)
		if !result {
			return idNumNotValidateError
		}
	}
	if info.Idtype == PassPort {

	}
	//=======================temporary code
	return nil
}

//Verify that the ID number is valid
func checkIDcardNum(num string) bool {
	if len(num) != 18 {
		return false
	}
	provinceCode := []string{"11", "12", "13", "14", "15", "21", "22",
		"23", "31", "32", "33", "34", "35", "36", "37", "41", "42", "43",
		"44", "45", "46", "50", "51", "52", "53", "54", "61", "62", "63",
		"64", "65", "71", "81", "82", "91"}
	province := num[:2]
	for _, value := range provinceCode {
		if value == province {
			break
		} else if value == "91" { //the lastNumber but nof find true code
			return false
		}
	}
	date := num[6:10] + "-" + num[10:12] + "-" + num[12:14] + " 00:00:00"
	timeLayout := "2006-01-02 15:04:05" //time template
	loc, _ := time.LoadLocation("Local")
	_, err := time.ParseInLocation(timeLayout, date, loc)
	if err != nil {
		return false
	}
	//check validate code
	power := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	refNumber := []string{"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"}
	var result int
	for index, value := range power {
		tmp, err := strconv.Atoi(string(num[index]))
		if err != nil {
			return false
		}
		result += tmp * value
	}
	lastNum := num[17:]
	if lastNum == "x" {
		lastNum = "X"
	}
	if lastNum != refNumber[(result%11)] {
		return false
	}

	return true
}

func EncryptUserData(userData []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	encrypted, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(pubKey), userData, nil, nil)
	return encrypted, err
}
func GetUserIdFromData(jsonData []byte) string {
	var data map[string]string
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Error("Unpack data error!")
	}
	idType := data["certype"]
	idNum := data["id"]
	userId := crypto.Keccak256Hash([]byte(idType + "-" + idNum)).Hex()
	return userId
}
func GetUserData() []byte {
	userDataPath := filepath.Join(node.DefaultDataDir(), "userData.json")
	dataBytes, _ := readData(userDataPath)
	return dataBytes
}

// GetCert will read user.crt and return certificate string
func GetCert() string {
	certPath := filepath.Join(node.DefaultDataDir(), "user.crt")
	// parse user certificate
	certBytes, _ := readData(certPath)
	certAscii := hex.EncodeToString(certBytes[:])
	return certAscii
}
func readData(filename string) ([]byte, error) {
	userData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("Can not read user data", err)
	}
	return userData, err
}

//get public key from contract use index string.
func getPubKeyFromContract(index string) ([]byte, error) {
	//getPubKeyUseID(useID)
	var tmpKey string
	pubKeyBytes, err := hexutil.Decode(tmpKey)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}
