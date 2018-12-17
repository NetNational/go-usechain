package cacertreg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/usechain/go-usechain/console"
	"github.com/usechain/go-usechain/crypto"
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

//CARegResp indicates the response content when applying for a CA certificate.
type CARegResp struct {
	Limit  int
	Offset int
	Order  string
	Status int
	msg    string
	Data   caRegRespData
}
type caRegRespData struct {
	IDKey string
}

// fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

//CAVerify user register. If flag is true,it means register by console, else it's cmd.
func CAVerify(flag bool, filePath string, photos []string) (string, error) {
	UserInfoInteraction()

	IDKey, err := UserAuthOperation(flag, filePath, photos)
	if err != nil {
		return "", err
	}
	return IDKey, nil
}

//UserAuthOperation use userID and photo to register ca cert.
func UserAuthOperation(flag bool, filePath string, photo []string) (string, error) {
	//read file
	var file string
	if flag {
		file = filepath.Join(node.DefaultDataDir(), "userData.json")
	} else {
		file = filePath
	}
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	infoMap := make(map[string]string)
	err = json.Unmarshal(bytes, &infoMap)
	if err != nil {
		return "", err
	}

	if infoMap["id"] == "" {
		return "", errors.New("useid can not be empty")
	}
	if infoMap["certtype"] == "" {
		return "", errors.New("certType can not be empty")
	}

	//Use a spliced string of number and types as hash
	combinationStr := infoMap["certtype"] + "-" + infoMap["id"]
	IDKey, err := postVerifactionData(combinationStr, photo)
	if err != nil {
		log.Error("Failed to upload user info :", "err", err)
		return "", err
	}
	return IDKey, nil
}
func postVerifactionData(combinationStr string, filename []string) (string, error) {
	//Create form
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)

	//read file and write data to form
	count := 1
	for _, v := range filename {
		formFile, err := writer.CreateFormFile(fmt.Sprintf("uploadfile%d", count), v)
		count++
		if err != nil {
			log.Error("Create form file failed,", "err", err)
			return "", err
		}
		if v == "" {
			log.Error("photo path can not be empty")
			return "", errors.New("photo path can not be empty")
		}
		// read only
		srcFile, err := os.OpenFile(v, os.O_RDONLY, 0)
		if err != nil {
			log.Error("Open source file failed:", "err", err)
			return "", err
		}
		_, err = io.Copy(formFile, srcFile)
		srcFile.Close()
	}

	//add user data field
	idField, err := writer.CreateFormField("data")
	r := strings.NewReader(geneUserData(combinationStr)) //only id and name for now
	_, err = io.Copy(idField, r)

	//add CSR field
	idHex, err := geneKeyFromID(combinationStr)
	if err != nil {
		return "", err
	}
	CSR := geneCSR(idHex)
	CSRField, err := writer.CreateFormField("CSR")
	r = strings.NewReader(CSR)
	_, err = io.Copy(CSRField, r)

	writer.Close()
	contentType := writer.FormDataContentType()
	resp, err := http.Post(CAurl, contentType, buf)
	if err != nil {
		log.Error("Post failed,", "err", err)
		return "", err
	}
	respStr := readerToString(resp.Body)
	fmt.Println(respStr)
	regResp := new(CARegResp)
	err = json.Unmarshal([]byte(respStr), &regResp)
	if err != nil {
		log.Error("unmarshal failed,", "err", err)
		return "", err
	}
	IDKey := regResp.Data.IDKey
	return IDKey, nil
}

func geneUserData(userID string) string {
	values := map[string]string{"userID": userID}
	userData, _ := json.Marshal(values)
	return string(userData)
}

func geneCSR(idHex string) string {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("Generate RSA key pair error: %v", err)
	}
	publicKey := keyBytes.PublicKey
	separator := string(os.PathSeparator)
	savePEMKey(node.DefaultDataDir()+separator+"userrsa.prv", keyBytes)
	savePublicPEMKey(node.DefaultDataDir()+separator+"userrsa.pub", publicKey)

	subj := pkix.Name{
		CommonName: idHex,
		// Locality:   []string{idHex},
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csrBuf.String()
}

func geneKeyFromID(infoHash string) (string, error) {
	idHex := crypto.Keccak256Hash([]byte(infoHash)).Hex()
	fmt.Printf("idHex: %v\n", idHex)
	return idHex, nil
}

var CAurl = "http://usechain.cn:8548/UsechainService/cert/cerauth"
var CAquery = "http://usechain.cn:8548/UsechainService/user/cerauth"

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	log.Info("Private key saved at " + fileName)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	log.Info("Public key saved at " + fileName)
	checkError(err)
}
func readerToString(r io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return buf.String()
}
func checkError(err error) {
	if err != nil {
		fatalf("Fatal error ", err.Error())
		// os.Exit(1)
	}
}

//VerifyQuery after user registered, user can get query info and stores ca file.
func VerifyQuery(idKey, chainID string) error {

	if chainID != "" {
		chainID += "_"
	}
	err := queryID(CAquery, idKey, chainID)
	if err != nil {
		return err
	}
	return nil
}

func queryID(CAserver string, idKey, chainID string) error {
	u, _ := url.Parse(CAserver)
	q := u.Query()
	q.Add("idKey", idKey)
	u.RawQuery = q.Encode()
	log.Info("query url for idKey:", "idKey", idKey)
	resp, err := http.Get(u.String())
	if err != nil || resp.StatusCode != 200 {
		log.Error("Your idKey is %s, please try again later")
		if err == nil {
			return errors.New("response's statuscode is not 200!please try again later")
		}
		return err
	}

	CAbuf := new(bytes.Buffer)
	CAbuf.ReadFrom(resp.Body)
	jsondata, _ := simplejson.NewJson(CAbuf.Bytes())
	certBytes, _ := jsondata.Get("data").Get("cert").Bytes()
	if len(certBytes) == 0 {
		log.Error("Failed to download CA file \n", certBytes)
		return errors.New("Failed to download CA file")
	}
	cert := string(certBytes[:])

	userCert := filepath.Join(node.DefaultDataDir(), (chainID + idKey + ".crt"))
	err = ioutil.WriteFile(userCert, []byte(cert), 0644)
	checkError(err)
	log.Info("CAbuf:", "CAbuf", CAbuf.String())
	log.Info("Verification successful, your CA file stored in " + userCert)

	return nil
}

//UserInfoInteraction when user enter console to register, user's information must be written to file.
func UserInfoInteraction() {
	fmt.Println("What kind of information do you want to verify?")
	fmt.Println(IDCard + ".IDCard")
	fmt.Println(PassPort + ".PassPort")
	fmt.Println(DriverCard + ".DriverCard")
	fmt.Println(SocialCard + ".SocialCard")
	fmt.Println(EducationCert + ".EducationCert")
	fmt.Println(ImmovablesCert + ".ImmovablesCert")
	fmt.Println(DepositCert + ".DepositCert")
	fmt.Println(Car + ".Car")
	fmt.Println(Stock + ".Stock")
	fmt.Println(Career + ".Career")
	fmt.Println(BusinessLicense + ".BusinessLicense")
	fmt.Println(Other + ".Other")
	typeInput, err := console.Stdin.PromptInput("choose one:")
	if err != nil {
		fatalf("Failed to read type: %v", err)
	}
	fmt.Println("Please fill in the following information")
	genInfoMap(typeInput)
}

func genInfoMap(typeInput string) {
	infoMap := make(map[string]string)
	switch typeInput {
	case IDCard:
		infoMap["certtype"] = IDCard
		genIDCardInfo(infoMap)
	case PassPort:

	case DriverCard:

	case SocialCard:

	case EducationCert:

	default:
		fatalf("Information type is not exist")
	}
	storeFile(infoMap)
}
func getInput(attribute string) string {
	attr, err := console.Stdin.PromptInput(attribute)
	if err != nil {
		fatalf("Failed to read "+attribute+": %v", err)
	}
	return attr
}
func genIDCardInfo(infoMap map[string]string) {
	infoMap["name"] = getInput("name:")
	infoMap["id"] = getInput("id:")
	infoMap["country"] = getInput("country:")
	infoMap["address"] = getInput("home address:")
	infoMap["birthdate"] = getInput("birthday:")
	infoMap["ename"] = getInput("ename(opt):")
}
func storeFile(infoMap map[string]string) {
	infoBytes, err := json.Marshal(infoMap)
	if err != nil {
		fatalf("store information file failed: %v", err)
	}
	filePath := filepath.Join(node.DefaultDataDir(), "userData.json")
	err = ioutil.WriteFile(filePath, infoBytes, 0644)
	if err != nil {
		fatalf("sotre information file failed: %v", err)
	}
	log.Info("user data file saved at " + filePath)
}
