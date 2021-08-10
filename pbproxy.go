package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"flag"

	//"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

//crypto code
func getkey(pwd string) []byte {
	salt := []byte("1221")
	key := pbkdf2.Key([]byte(pwd), salt, 4096, 32, sha1.New)
	return key
}

func decrypt(pwd string, ciphert string) []byte {
	key := getkey(pwd)
	fulltext := []byte(ciphert)
	nonce := fulltext[:12]
	ciphertext := fulltext[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//automatically 32 byte key will select aesgcm-256
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

func encrypt(pwd string, plain string) []byte {
	key := getkey(pwd)
	plaintext := []byte(plain)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)
	return ciphertext
}

//crypto code
func sshdtopbproxyc(conn net.Conn, connsshd net.Conn, pwdFile string) {
	//getting data from sshd server

	for {
		buf := make([]byte, 3000)
		data, err := connsshd.Read(buf)
		buf = buf[:data]
		//fmt.Println(string(buf))
		if err != nil {
			connsshd.Close()
			break
		}
		if data != 0 {
			//conn.Write(buf)
			conn.Write(encrypt(pwdFile, string(buf)))
		}

	}
}

func stdin_server(conn net.Conn, connsshd net.Conn, pwdFile string) {
	//reader logic
	//bufio.NewReader(os.Stdin)
	for {
		buf := make([]byte, 3000)
		data, err := os.Stdin.Read(buf)
		//buf = bytes.Trim(buf, "\x00")
		buf = buf[:data]
		if err != nil {
			break
		}
		if data != 0 {
			conn.Write(encrypt(pwdFile, string(buf)))
		}
	}
}

func stdout_client(conn net.Conn, pwdfile string) {

	for {
		buf := make([]byte, 3000)
		data, err := conn.Read(buf)
		//buf = bytes.Trim(buf, "\x00")
		buf = buf[:data]
		if err != nil {

			conn.Close()
			break
		}
		if data != 0 {
			os.Stdout.Write(decrypt(pwdfile, string(buf)))
		}

	}
}

func Execute_Client(dstIp string, dstPort string, pwdFile string) {
	conn, err := net.Dial("tcp", dstIp+":"+dstPort)
	if err != nil {
		os.Exit(1)
	}

	//write to server
	go stdout_client(conn, pwdFile)

	//reader logic
	for {
		buf := make([]byte, 3000)
		data, err := os.Stdin.Read(buf)
		buf = buf[:data]
		if err != nil {
			//fmt.Println(err)
			conn.Close()
			break
		}
		if data != 0 {
			conn.Write(encrypt(pwdFile, string(buf)))
		}
	}

}

func handleConnections(conn net.Conn, dstIp string, dstPort string, pwdFile string) {

	//connect to ssd here...
	connsshd, err := net.Dial("tcp", dstIp+":"+dstPort)
	if err != nil {
		//fmt.Println(err)
		os.Exit(1)
	}
	defer connsshd.Close()
	defer conn.Close()
	//go routine for sshd to pbproxyc
	go sshdtopbproxyc(conn, connsshd, pwdFile)
	//go routine
	go stdin_server(conn, connsshd, pwdFile)

	//read from client
	for {
		buf := make([]byte, 3000)
		data, err := conn.Read(buf)
		buf = buf[:data]
		if err != nil {
			conn.Close()
			break
		}
		if data != 0 {
			//send to sshd...
			//decrypt and send
			connsshd.Write(decrypt(pwdFile, string(buf)))
		}
	}
}

func Execute_Server(dstIp string, dstPort string, pwdFile string, listenPort string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		os.Exit(1)
	}
	for {

		conn, err := ln.Accept()

		if err != nil {
			os.Exit(1)
		}
		go handleConnections(conn, dstIp, dstPort, pwdFile)
	}
}

//main function
func main() {

	var pwdfileI string
	var listenPortI string
	var dstIp string
	var dstPort string
	// flags declaration using flag package
	flag.StringVar(&pwdfileI, "p", "None", "Provide the file")
	flag.StringVar(&listenPortI, "l", "None", "Provide the file")
	flag.Parse()

	//read pwdfile
	password, _ := ioutil.ReadFile(pwdfileI)
	//test
	//fmt.Println(string(encrypt(string(password), "shashank")))
	//fmt.Println(string(decrypt(string(password), string(encrypt(string(password), "shashankken")))))

	if listenPortI == "None" {
		if len(os.Args) == 5 {
			dstIp = os.Args[len(os.Args)-2]
			dstPort = os.Args[len(os.Args)-1]
		} else {
			//fmt.Println("Issue with input arguments")
			os.Exit(1)
		}
		Execute_Client(dstIp, dstPort, string(password))
	} else {
		if len(os.Args) == 7 {
			dstIp = os.Args[len(os.Args)-2]
			dstPort = os.Args[len(os.Args)-1]
		} else {
			//fmt.Println("Issue with input arguments")
			os.Exit(1)
		}
		Execute_Server(dstIp, dstPort, string(password), listenPortI)

	}

}
