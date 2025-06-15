package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	// "io"
	// "strings"

	"golang.org/x/crypto/argon2"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ------------------------------------------Trabajo con bytes----------------------------------------------------
func DescifrarBytes(datos []byte, clave []byte, nonce []byte) (string, error) {
	// Validar longitud mínima
	if len(datos) < aes.BlockSize {
		return "", errors.New("los datos son demasiado cortos para contener un nonce válido")
	}

	// Extraer el nonce (IV)
	// nonce := datos[:aes.BlockSize]
	contenidoCifrado := datos

	// Crear el bloque AES
	bloque, err := aes.NewCipher(clave)
	if err != nil {
		return "", err
	}

	// Crear el stream CTR
	stream := cipher.NewCTR(bloque, nonce)

	// Descifrar
	datosDescifrados := make([]byte, len(contenidoCifrado))
	stream.XORKeyStream(datosDescifrados, contenidoCifrado)

	// Retornar como string
	return string(datosDescifrados), nil
}

// -------------------------------------- Funciones auxiliares no exportables -----------------------------------------
func obtenerAESconCTR(key []byte, iv []byte) (cipher.Stream, error) {
	//Si la clave no es de 128 o 256 bits => Error
	if !(len(key) == 16 || len(key) == 32) {
		return nil, errors.New("la clave no es de 128 o 256 bits")
	}

	CifradorDeUnBloque, err := aes.NewCipher(key)
	check(err)
	CifradorVariosBloquesConCTR := cipher.NewCTR(CifradorDeUnBloque, iv[:16])
	return CifradorVariosBloquesConCTR, nil
}

func ObtenerSHA256(Clave string) []byte {
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(Clave))
	check(err)
	retorno := h.Sum(nil)
	return retorno
}

// GenerateFileKey genera una clave aleatoria de 32 bytes (AES-256)
func GenerateFileKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes = 256 bits para AES-256
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != len(key) {
		return nil, errors.New("no se pudo generar una clave completa")
	}
	return key, nil
}

// ----------------------------------------- Funciones principales nuevas --------------------------------------------
func EncryptFileKey(fileKey, masterKey []byte) ([]byte, []byte, error) {
	nonce, err := GenerateRandomNonce(aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}

	stream, err := obtenerAESconCTR(masterKey, nonce)
	if err != nil {
		return nil, nil, err
	}
	encrypted := make([]byte, len(fileKey))
	stream.XORKeyStream(encrypted, fileKey)

	return encrypted, nonce, nil
}

// DecryptFileKey descifra una clave de archivo cifrada usando la clave maestra
func DecryptFileKey(encrypted []byte, nonce []byte, masterKey []byte) ([]byte, error) {
	stream, err := obtenerAESconCTR(masterKey, nonce)
	if err != nil {
		return nil, err
	}

	fileKey := make([]byte, len(encrypted))
	stream.XORKeyStream(fileKey, encrypted)

	return fileKey, nil
}

func EncryptAndSignStr(plainText string, key []byte) (string, error) {
	// Generar nonce aleatorio cada vez que se cifre ---> aumenta la seguridad contra ataques por repetición y evita fuga de datos
	nonce, err := GenerateRandomNonce(aes.BlockSize) //aes.BlockSize porque CTR lo necesita (16 Bytes)
	if err != nil {
		return "", err
	}

	stream, err := obtenerAESconCTR(key, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainText))
	stream.XORKeyStream(ciphertext, []byte(plainText))

	// Combinar nonce + ciphertext
	data := append(nonce, ciphertext...) //Esto es necesario porque para descifrar, se necesita el mismo nonce

	// Agregar HMAC para autenticación del mensaje ---> permite verificar la integridad para evitar ataques de tipo bit flipping
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sign := mac.Sum(nil)

	// Concatenar todo: nonce + ciphertext + hmac
	final := append(data, sign...) //También ese necesario conservar el estado de la firma HMAC

	// Codificar en base64 y devolver string
	return base64.StdEncoding.EncodeToString(final), nil
}

func VerifyAndDecryptStr(encoded string, key []byte) (string, error) {
	//Primero decodificamos la string
	datos, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	//Comprobamos estado de los datos
	if len(datos) < aes.BlockSize+sha256.Size { //Hay que tener en cuenta el tamaño tanto del aes.BlockSize como el de sha256
		return "", errors.New("Datos corruptos o incompletos para contener un nonce válido")
	}

	// Separar nonce, ciphertext y HMAC
	nonce := datos[:aes.BlockSize]
	ciphertext := datos[aes.BlockSize : len(datos)-sha256.Size]
	signReceived := datos[len(datos)-sha256.Size:]

	// Primero verificamos que no se hayan alterado los datos con HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(datos[:len(datos)-sha256.Size])
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signReceived, expectedMAC) {
		fmt.Printf("HMAC ---> received: %s, expected: %s", signReceived, expectedMAC)
		return "", errors.New("firma HMAC inválida: los datos han sido modificados")
	}

	//Creamos el bloque AES con stream CTR
	stream, err := obtenerAESconCTR(key, nonce)
	if err != nil {
		return "", err
	}

	//Descifrar
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

func VerifyAndDecryptBytes(datos []byte, key []byte) (string, error) {
	// Comprobamos estado de los datos
	if len(datos) < aes.BlockSize+sha256.Size {
		fmt.Println("Entra a la medicion")
		return "", errors.New("Datos corruptos o incompletos para contener un nonce válido")
	}

	// Separar nonce
	// , ciphertext y HMAC
	nonce := datos[:aes.BlockSize]
	ciphertext := datos[aes.BlockSize : len(datos)-sha256.Size]
	signReceived := datos[len(datos)-sha256.Size:]

	// Verificar HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(datos[:len(datos)-sha256.Size])
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signReceived, expectedMAC) {
		fmt.Println("Entra al HMAC")
		return "", errors.New("firma HMAC inválida: los datos han sido modificados")
	}

	stream, err := obtenerAESconCTR(key, nonce)
	if err != nil {
		fmt.Println("Entra al AESCTR")
		return "", err
	}

	fmt.Println("EncryptedData:", len(ciphertext), ciphertext)
	fmt.Println("Nonce:", len(nonce), nonce)

	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	fmt.Println("Clave archivo:", len(plaintext), plaintext)
	return string(plaintext), nil
}

func GenerateRandomNonce(size int) ([]byte, error) { //Mejor que el nonce sea único e impredecible, mejor que inicializar desde SHA256
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

//-------------------------------------------Trabajo con claves maestras------------------------------------------

const ( //Hiperparámetros para derivar de forma segura con Argon2
	saltLength   = 16
	keyLength    = 32
	nonceSize    = 12
	saltPath     = "config/salt.bin"
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// Deriva la clave maestra con Argon2
func DeriveMasterKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLength)
}

// Genera un salt aleatorio
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	return salt, err
}

// Guarda el salt en disco
func saveSalt(salt []byte) error {
	return os.WriteFile(saltPath, salt, 0600)
}

// Carga el salt desde disco, o lo genera si no existe
func LoadOrCreateSalt() ([]byte, error) {
	if _, err := os.Stat(saltPath); errors.Is(err, os.ErrNotExist) {
		salt, err := generateSalt()
		if err != nil {
			return nil, err
		}
		if err := saveSalt(salt); err != nil {
			return nil, err
		}
		return salt, nil
	}
	return os.ReadFile(saltPath)
}

// Genera una clave maestra y la guarda cifrada en un archivo
func GenerateAndSaveMasterKey(path, password string) error {
	// Paso 1: generar clave real (clave de uso)
	claveReal := make([]byte, keyLength)
	if _, err := rand.Read(claveReal); err != nil {
		return err
	}

	// Paso 2: generar salt y derivar clave
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// passwordByte, err := base64.StdEncoding.DecodeString(password)
	// if err != nil {
	// 	return err
	// }
	claveDerivada := DeriveMasterKey([]byte(password), salt)

	// Paso 3: cifrar clave real con AES-GCM
	block, err := aes.NewCipher(claveDerivada)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block) //Usamos modo GCM para evitar facilitar programación
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	cifrado := gcm.Seal(nil, nonce, claveReal, nil)

	// Paso 4: guardar en archivo: salt + nonce + cifrado
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(append(append(salt, nonce...), cifrado...))
	return err
}

// Carga y descifra la clave maestra desde archivo
func LoadMasterKey(path, password string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < saltLength+nonceSize+keyLength {
		return nil, errors.New("archivo inválido o corrupto")
	}

	salt := data[:saltLength]
	nonce := data[saltLength : saltLength+nonceSize]
	cifrado := data[saltLength+nonceSize:]

	// passwordByte, err := base64.StdEncoding.DecodeString(password)
	// if err != nil {
	// 	return nil, err
	// }
	claveDerivada := DeriveMasterKey([]byte(password), salt)

	block, err := aes.NewCipher(claveDerivada)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	claveReal, err := gcm.Open(nil, nonce, cifrado, nil)
	if err != nil {
		return nil, errors.New("contraseña incorrecta o archivo dañado")
	}
	return claveReal, nil
}

func ChangeMasterKey(path string, passwordActual, newPassword string) error {
	// Cargar clave real descifrada con la contraseña actual
	claveReal, err := LoadMasterKey(path, passwordActual)
	if err != nil {
		return fmt.Errorf("clave actual incorrecta: %w", err)
	}
	fmt.Printf("Clave real actual (hex): %x\n", claveReal)

	// Derivar nueva clave desde nueva contraseña
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// new , _ := base64.StdEncoding.EncodeToString()
	claveDerivadaNueva := DeriveMasterKey([]byte(newPassword), salt)

	fmt.Printf("Clave derivada nueva (hex): %x\n", claveDerivadaNueva)

	// Cifrar clave real con la nueva clave derivada
	block, err := aes.NewCipher(claveDerivadaNueva)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	cifrado := gcm.Seal(nil, nonce, claveReal, nil)

	// Sobrescribir el archivo con los nuevos datos
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(append(append(salt, nonce...), cifrado...))
	return err
}
