package encryption

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
