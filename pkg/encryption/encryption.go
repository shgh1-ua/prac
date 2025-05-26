package encryption

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// func main() {
// 	key := obtenerSHA256("Clave")
// 	iv := obtenerSHA256("<inicializar>")

// 	textoEnClaro := "Texto en claro"
// 	nombreArchivoDatos := "datos.zip.enc"

// 	//----------CIFRADO--------------
// 	cifrarStringEnArchivo(textoEnClaro, nombreArchivoDatos, key, iv)

// 	//----------DESCIFRADO-----------
// 	textoEnClaroDescifrado := descifrarArchivoEnString(nombreArchivoDatos, key, iv)

//		//----------Comprobación-----------
//		if textoEnClaroDescifrado == textoEnClaro {
//			fmt.Println("Cifrado realizado correctamente")
//		} else {
//			fmt.Println("Algo ha fallado con el cifrado")
//		}
//	}
//
// ------------------------------------------Trabajo con archivos----------------------------------------------------
func DescifrarArchivoEnString(nombreArchivoDatos string, key []byte, iv []byte) string {
	archivoOrigenComprimidoCifrado, err := os.Open(nombreArchivoDatos)
	check(err)

	var bufferDeBytesParaDescifraryDescomprimir bytes.Buffer

	var lectorConDescifrado cipher.StreamReader
	lectorConDescifrado.S, err = obtenerAESconCTR(key, iv)
	lectorConDescifrado.R = archivoOrigenComprimidoCifrado
	check(err)

	lectorConDescifradoDescompresion, err := zlib.NewReader(lectorConDescifrado)
	check(err)

	_, err = io.Copy(&bufferDeBytesParaDescifraryDescomprimir, lectorConDescifradoDescompresion)
	check(err)
	archivoOrigenComprimidoCifrado.Close()

	textoEnClaroDescifrado := bufferDeBytesParaDescifraryDescomprimir.String()
	return textoEnClaroDescifrado
}

func CifrarStringEnArchivo(textoEnClaro string, nombreArchivoDatos string, key []byte, iv []byte) {
	lectorTextoEnClaro := strings.NewReader(textoEnClaro)

	archivoDestinoComprimidoyCifrado, err := os.Create(nombreArchivoDatos)
	check(err)

	var escritorConCifrado cipher.StreamWriter
	escritorConCifrado.S, err = obtenerAESconCTR(key, iv)
	escritorConCifrado.W = archivoDestinoComprimidoyCifrado
	check(err)

	escritorConCompresionyCifrado := zlib.NewWriter(escritorConCifrado)

	_, err = io.Copy(escritorConCompresionyCifrado, lectorTextoEnClaro)
	check(err)

	escritorConCompresionyCifrado.Close()
	archivoDestinoComprimidoyCifrado.Close()
}

// ------------------------------------------Trabajo con strings----------------------------------------------------
// Cifra un texto plano usando AES en modo CTR y lo retorna como una cadena en base64.
func CifrarString(textoPlano string, clave, nonce []byte) (string, error) {
	// Crear el bloque AES a partir de la clave
	block, err := aes.NewCipher(clave)
	if err != nil {
		return "", fmt.Errorf("error al crear el cifrador AES: %v", err)
	}

	// Asegurarse de que el nonce tiene el tamaño adecuado
	if len(nonce) != aes.BlockSize {
		return "", errors.New("el tamaño del nonce debe ser igual al tamaño del bloque AES")
	}

	// Crear el modo CTR
	stream := cipher.NewCTR(block, nonce)

	// Crear un buffer para el texto cifrado
	cifrado := make([]byte, len(textoPlano))

	// Cifrar el texto plano
	stream.XORKeyStream(cifrado, []byte(textoPlano))

	// Codificar el resultado en base64
	return base64.StdEncoding.EncodeToString(cifrado), nil
}

// Toma un texto cifrado en base64, lo descifra usando AES en modo CTR y devuelve el texto original.
func DescifrarString(textoCifradoBase64 string, clave, nonce []byte) string {
	// Decodificar el texto cifrado de base64
	cifrado, _ := base64.StdEncoding.DecodeString(textoCifradoBase64) //si queremos tratar el error poner err en _ y descomentar lo demás, como en la fuciòn cifrarString
	// if err != nil {
	// 	return "", fmt.Errorf("error al decodificar el texto cifrado: %v", err)
	// }

	// Crear el bloque AES a partir de la clave
	block, _ := aes.NewCipher(clave) //si queremos tratar el error poner err en _ y descomentar lo demás, como en la fuciòn cifrarString
	// if err != nil {
	// 	return "", fmt.Errorf("error al crear el cifrador AES: %v", err)
	// }

	// Asegurarse de que el nonce tiene el tamaño adecuado
	// if len(nonce) != aes.BlockSize {
	// 	return "", errors.New("el tamaño del nonce debe ser igual al tamaño del bloque AES")
	// }

	// Crear el modo CTR
	stream := cipher.NewCTR(block, nonce)

	// Crear un buffer para el texto descifrado
	descifrado := make([]byte, len(cifrado))

	// Descifrar el texto cifrado
	stream.XORKeyStream(descifrado, cifrado)

	// Convertir el texto descifrado a string
	return string(descifrado) //, nil
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

func DeriveMasterKey(password, salt []byte) []byte { //A partir de la contraseña del usuario
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32) // AES-256
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

func GenerateRandomNonce(size int) ([]byte, error) { //Mejor que el nonce sea único e impredecible, mejor que inicializar desde SHA256
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
