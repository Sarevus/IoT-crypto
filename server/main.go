package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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
	PublicKeySize    = 800  // публичный ключ клиента
	SecretKeySize    = 2400 // секретный ключ (генерируется клиентом)
	CiphertextSize   = 768  // размер капсулы (ciphertext) для Kyber‑512 (Krystal‑512)
	SharedSecretSize = 32   // размер общего секрета
	NonceSize        = 12   // размер nonce для Kuznyechik-GCM (обычно 12 байт)
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



//дешифровка.
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



//отправка.
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



//принятие.
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
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Сервер: Ожидание подключения на порту 9000...")
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("Сервер: Клиент подключился.")
	clientPubKeySlice := make([]byte, PublicKeySize)
	if _, err := io.ReadFull(conn, clientPubKeySlice); err != nil {
		log.Fatal(err)
	}
	var clientPubKey [PublicKeySize]byte
	copy(clientPubKey[:], clientPubKeySlice)
	fmt.Println("Сервер: Получен публичный ключ от клиента.")
	startEnc := time.Now()
	kemCiphertext, sharedSecret, err := kyber.KemEncrypt512(clientPubKey)
	if err != nil {
		log.Fatal(err)
	}
	encDuration := time.Since(startEnc)
	fmt.Printf("Сервер: Encapsulation выполнена за %v\n", encDuration)
	if _, err := conn.Write(kemCiphertext[:]); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Сервер: Капсула отправлена клиенту.")
	message := []byte("Подключение удалось!")
	key := sharedSecret[:] 
	nonce, cipherText, err := encryptKuznyechikGCM(key, message)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := conn.Write(nonce); err != nil {
		log.Fatal(err)
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(cipherText)))
	if _, err := conn.Write(lenBuf); err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write(cipherText); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Сервер: Зашифрованное сообщение отправлено клиенту.")

	go func() {
		for {
			msg, err := readMessage(conn, key)
			if err != nil {
				log.Println("Сервер: ошибка чтения сообщения:", err)
				return
			}
			fmt.Printf("Клиент: %s\n", msg)
		}
	}()

	consoleReader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Сервер (введите сообщение): ")
		text, err := consoleReader.ReadString('\n')
		if err != nil {
			log.Println("Сервер: ошибка чтения с консоли:", err)
			break
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if err := sendMessage(conn, key, text); err != nil {
			log.Println("Сервер: ошибка отправки сообщения:", err)
			break
		}
	}
}
