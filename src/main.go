package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	passwordFile = "./hashpass/pass.txt"
)

var hardKey = []byte("my_key_watercrh7")

func main() {
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		fmt.Println("No password found... Creating a new one...")
		createPassword()
	} else {
		fmt.Print("Insert your password: ")
		password, err := readPassword()
		if err != nil {
			log.Fatal("Error reading password:", err)
		}

		if comparePassword(password) {
			fmt.Println("Password is correct... Access open.")
		} else {
			fmt.Println("Wrong password.")
		}
	}
}

func createPassword() {

	fmt.Print("Insert password: ")
	password, err := readPassword()
	if err != nil {
		log.Fatal("Error reading pass:", err)
	}

	hashedPassword := hashPassword(password)

	err = cryptPass([]byte(hashedPassword))
	if err != nil {
		log.Fatal("Error encrypting and saving pass:", err)
	}

	fmt.Println("Pass sucessfully created and saved")
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func cryptPass(hashedInputPassword []byte) error {
	file, err := os.Create(passwordFile)
	defer file.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	_, err = file.Write(iv)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(hardKey)
	if err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	password := make([]byte, aes.BlockSize+len(hashedInputPassword))
	stream.XORKeyStream(password[aes.BlockSize:], hashedInputPassword)

	_, err = file.Write(password[aes.BlockSize:])
	if err != nil {
		return err
	}

	return nil
}

func comparePassword(inputPassword string) bool {
	encryptedPassword, err := os.ReadFile(passwordFile)
	if err != nil {
		log.Fatal("Error reading encrypted password:", err)
	}

	iv := encryptedPassword[:aes.BlockSize]
	password := encryptedPassword[aes.BlockSize:]

	hashedInputPassword := hashPassword(inputPassword)

	block, err := aes.NewCipher(hardKey)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(password, password)

	return string(password) == string(hashedInputPassword)
}

func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(password)), nil
}
