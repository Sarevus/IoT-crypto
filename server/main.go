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
	// Размеры ключей и ciphertext (для выбранной реализации Kyber‑512)
	PublicKeySize    = 800  // публичный ключ клиента
	SecretKeySize    = 2400 // секретный ключ (генерируется клиентом)
	CiphertextSize   = 768  // размер капсулы (ciphertext) для Kyber‑512 (Krystal‑512)
	SharedSecretSize = 32   // размер общего секрета
	NonceSize        = 12   // размер nonce для Kuznyechik-GCM (обычно 12 байт)
)

// encryptKuznyechikGCM шифрует сообщение с использованием Kuznyechik в режиме GCM.
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

// decryptKuznyechikGCM дешифрует сообщение с использованием Kuznyechik в режиме GCM.
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

// sendMessage шифрует и отправляет сообщение через соединение.
func sendMessage(conn net.Conn, key []byte, message string) error {
	nonce, cipherText, err := encryptKuznyechikGCM(key, []byte(message))
	if err != nil {
		return err
	}
	// Отправляем: nonce, 4-байтную длину ciphertext и сам ciphertext.
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

// readMessage читает зашифрованное сообщение, дешифрует его и возвращает строку.
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
	// Сервер слушает TCP-порт 9000
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

	// 1. Получаем публичный ключ, отправленный клиентом (800 байт)
	clientPubKeySlice := make([]byte, PublicKeySize)
	if _, err := io.ReadFull(conn, clientPubKeySlice); err != nil {
		log.Fatal(err)
	}
	var clientPubKey [PublicKeySize]byte
	copy(clientPubKey[:], clientPubKeySlice)
	fmt.Println("Сервер: Получен публичный ключ от клиента.")

	// 2. Выполняем encapsulation: генерируем капсулу и общий секрет.
	startEnc := time.Now()
	kemCiphertext, sharedSecret, err := kyber.KemEncrypt512(clientPubKey)
	if err != nil {
		log.Fatal(err)
	}
	encDuration := time.Since(startEnc)
	fmt.Printf("Сервер: Encapsulation выполнена за %v\n", encDuration)

	// 3. Отправляем капсулу клиенту (768 байт)
	if _, err := conn.Write(kemCiphertext[:]); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Сервер: Капсула отправлена клиенту.")

	// 4. Дополнительно отправляем зашифрованное сообщение о успешном подключении.
	message := []byte("Подключение удалось!")
	key := sharedSecret[:] // общий секрет используется как симметричный ключ
	nonce, cipherText, err := encryptKuznyechikGCM(key, message)
	if err != nil {
		log.Fatal(err)
	}
	// Отправляем: nonce (12 байт), 4-байтную длину ciphertext и сам ciphertext.
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

	// Запускаем горутину для чтения входящих сообщений от клиента.
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

	// Основной цикл: ввод с консоли и отправка сообщений клиенту.
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
