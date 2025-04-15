package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/starius/kuznyechik"
	kyber "github.com/symbolicsoft/kyber-k2so"
)

const (
	PublicKeySize    = 800  // размер публичного ключа
	SecretKeySize    = 2400 // размер секретного ключа
	CiphertextSize   = 768  // размер капсулы для Kyber‑512 (Krystal‑512)
	SharedSecretSize = 32   // размер общего секрета
	NonceSize        = 12   // размер nonce для Kuznyechik-GCM
)

// шифровка.
func encryptKuznyechikGCM(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := kuznyechik.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}



// дешифровка.
func decryptKuznyechikGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := kuznyechik.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}



// отправление.
func sendMessage(conn net.Conn, key []byte, message string) error {
	nonce, cipherText, err := encryptKuznyechikGCM(key, []byte(message))
	if err != nil {
		return err
	}
	if _, err := conn.Write(nonce); err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(cipherText)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := conn.Write(cipherText); err != nil {
		return err
	}
	return nil
}



// получить.
func readMessage(conn net.Conn, key []byte) (string, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return "", err
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	cipherText := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, cipherText); err != nil {
		return "", err
	}
	plaintext, err := decryptKuznyechikGCM(key, nonce, cipherText)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	startGen := time.Now()
	privateKey, publicKey, err := kyber.KemKeypair512()
	if err != nil {
		log.Fatal(err)
	}
	genDuration := time.Since(startGen)
	fmt.Printf("Клиент: Ключи сгенерированы за %v\n", genDuration)
	fmt.Printf("Клиент: Публичный ключ (hex): %s\n", hex.EncodeToString(publicKey[:]))

	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("Клиент: Подключен к серверу.")

	if _, err := conn.Write(publicKey[:]); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Клиент: Публичный ключ отправлен серверу.")

	ciphertextSlice := make([]byte, CiphertextSize)
	if _, err := io.ReadFull(conn, ciphertextSlice); err != nil {
		log.Fatal(err)
	}
	var kemCiphertext [CiphertextSize]byte
	copy(kemCiphertext[:], ciphertextSlice)
	fmt.Println("Клиент: Получена капсула от сервера.")

	startDec := time.Now()
	sharedSecret, err := kyber.KemDecrypt512(kemCiphertext, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	decDuration := time.Since(startDec)
	fmt.Printf("Клиент: Decapsulation выполнена за %v\n", decDuration)
	fmt.Printf("Клиент: Общий секрет (hex): %s\n", hex.EncodeToString(sharedSecret[:]))
	sharedKey := sharedSecret[:] 
	go func() {
		for {
			msg, err := readMessage(conn, sharedKey)
			if err != nil {
				log.Println("Клиент: ошибка чтения сообщения:", err)
				return
			}
			fmt.Printf("Сервер: %s\n", msg)
		}
	}()


	consoleReader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Клиент (введите сообщение): ")
		text, err := consoleReader.ReadString('\n')
		if err != nil {
			log.Println("Клиент: ошибка чтения с консоли:", err)
			break
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if err := sendMessage(conn, sharedKey, text); err != nil {
			log.Println("Клиент: ошибка отправки сообщения:", err)
			break
		}
	}
}
