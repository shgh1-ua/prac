package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"prac/pkg/encryption"

	"go.etcd.io/bbolt"
)

/*
	Implementación de la interfaz Store mediante BoltDB (versión bbolt)
*/

// BboltStore contiene la instancia de la base de datos bbolt.
type BboltStore struct {
	db        *bbolt.DB
	masterKey []byte
	fileKey   []byte
}

// NewBboltStore abre la base de datos bbolt en la ruta especificada.
func NewBboltStore(path string) (*BboltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("error al abrir base de datos bbolt: %v", err)
	}
	return &BboltStore{db: db}, nil
}

// SetMasterKey configura la clave maestra
func (s *BboltStore) SetMasterKey(key []byte) {
	s.masterKey = key
}

// SetFileKey configura la clave maestra
func (s *BboltStore) SetFileKey(key []byte) {
	s.fileKey = key
}

// GetMasterKey configura la clave maestra
func (s *BboltStore) GetMasterKey() ([]byte, error) {
	if s.masterKey == nil {
		return nil, fmt.Errorf("clave maestra no configurada")
	}
	return s.masterKey, nil
}

// GetFileKey configura la clave maestra
func (s *BboltStore) GetFileKey() ([]byte, error) {
	if s.fileKey == nil {
		return nil, fmt.Errorf("clave de archivo no configurada")
	}
	return s.fileKey, nil
}

// func (s *BboltStore) Put(namespace string, key, value []byte) error {
// 	// fmt.Println("Estamos en bbolt con namespace: ", namespace, " key: ", key, " y value: ", value)
// 	//Ciframos antes de mandar al servidor. Lo hacemos suponiendo que el servidor no es de confiar por sea cual fuere la razón (administrador poco confiable, datos comprometidos, uso de http, etc.)
// 	// cipherKey := encryption.ObtenerSHA256("Clave")
// 	// iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
// 	// Al guardar un historial médico
// 	// textoEnClaro := string(value)
// 	//----------CIFRADO--------------
// 	// datosCifrados, err := encryption.EncryptAndSignStr(textoEnClaro, cipherKey)
// 	// fmt.Println(textoEnClaro, " ----> ", datosCifrados)
// 	// if err != nil {
// 	// 	fmt.Println("Error al cifrar Datos:", err)
// 	// 	return nil //Si algo falla al hacer PUT en la base de datos va a a devolver valor nulo
// 	// }
// 	// return s.db.Update(func(tx *bbolt.Tx) error {
// 	// 	b, err := tx.CreateBucketIfNotExists([]byte(namespace))
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("error al crear/abrir bucket '%s': %v", namespace, err)
// 	// 	}
// 	// 	return b.Put(key, []byte(datosCifrados))
// 	// })
//  }

func putAuthData(s *BboltStore, value []byte) ([]byte, error) {
	// Separar hash y salt
	// fmt.Println("Las putas datas son: Value AuthData ", string(value))
	// var parts [4]string //tamaño 4 por: hash, salt, role y authData
	var authData map[string]string

	if err := json.Unmarshal(value, &authData); err != nil {
		return nil, fmt.Errorf("error al deserializar expedientes: %v", err)
	}

	// fmt.Println("Probando el unmarshal: ", authData)

	if _, ok := authData["hash"]; !ok {
		return nil, fmt.Errorf("falta 'hash' en los datos de autenticación")
	}
	if _, ok := authData["salt"]; !ok {
		return nil, fmt.Errorf("falta 'salt' en los datos de autenticación")
	}
	if _, ok := authData["role"]; !ok {
		return nil, fmt.Errorf("falta 'role' en los datos de autenticación")
	}
	if _, ok := authData["data"]; !ok {
		return nil, fmt.Errorf("falta 'data' en los datos de autenticación")
	}

	// parts := strings.Split(string(value), ":")
	// fmt.Println("Parts (servidor): ", parts, " tamaño: ", len(parts))
	hash, _ := authData["hash"]
	salt, _ := authData["salt"]
	data := authData["role"] + authData["data"] //parts[2] = role y parts[3] = authData

	fmt.Println("Hash: ", string(hash), " dalt: ", string(salt))
	// Generamos una clave de archivo aleatoria para cifrar este valor
	fileKey, err := encryption.GenerateFileKey()
	if err != nil {
		return nil, fmt.Errorf("error al generar fileKey: %v", err)
	}
	fmt.Println("Tamaño clave descifrada:", len(fileKey), " Clave de archivo descifrada: ", fileKey) // Debe ser 32

	// Ciframos la clave de archivo usando la clave maestra
	encryptedFileKey, fileKeyNonce, err := encryption.EncryptFileKey(fileKey, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar fileKey: %v", err)
	}

	// Ciframos el contenido con la fileKey
	datosCifrados, err := encryption.EncryptAndSignStr(data, fileKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar los datos: %v", err)
	}

	// Empaquetamos todo como JSON (puedes usar otra estructura si prefieres)
	todo := map[string]string{
		"hash":          string(hash),
		"salt":          string(salt),
		"encryptedData": datosCifrados,
		"fileKey":       base64.StdEncoding.EncodeToString(encryptedFileKey),
		"nonce":         base64.StdEncoding.EncodeToString(fileKeyNonce),
	}
	jsonBytes, err := json.Marshal(todo)
	if err != nil {
		return nil, fmt.Errorf("error al serializar datos cifrados: %v", err)
	}
	return jsonBytes, nil
}

func putUserData(s *BboltStore, value []byte) ([]byte, error) {
	data := string(value) //Array de Expedientes en JSON

	// Generamos una clave de archivo aleatoria para cifrar este valor
	fileKey, err := encryption.GenerateFileKey()
	if err != nil {
		return nil, fmt.Errorf("error al generar fileKey: %v", err)
	}

	// Ciframos la clave de archivo usando la clave maestra
	encryptedFileKey, fileKeyNonce, err := encryption.EncryptFileKey(fileKey, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar fileKey: %v", err)
	}

	// Ciframos el contenido con la fileKey
	datosCifrados, err := encryption.EncryptAndSignStr(data, fileKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar los datos: %v", err)
	}

	todo := map[string]string{
		"encryptedData": datosCifrados,
		"fileKey":       base64.StdEncoding.EncodeToString(encryptedFileKey),
		"nonce":         base64.StdEncoding.EncodeToString(fileKeyNonce),
	}
	jsonBytes, err := json.Marshal(todo)
	if err != nil {
		return nil, fmt.Errorf("error al serializar datos cifrados: %v", err)
	}
	return jsonBytes, nil
}

func putSessionsData(s *BboltStore, value []byte) ([]byte, error) {
	data := string(value) //Array de Expedientes en JSON

	// Generamos una clave de archivo aleatoria para cifrar este valor
	fileKey, err := encryption.GenerateFileKey()
	if err != nil {
		return nil, fmt.Errorf("error al generar fileKey: %v", err)
	}

	// Ciframos la clave de archivo usando la clave maestra
	encryptedFileKey, fileKeyNonce, err := encryption.EncryptFileKey(fileKey, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar fileKey: %v", err)
	}

	// Ciframos el contenido con la fileKey
	datosCifrados, err := encryption.EncryptAndSignStr(data, fileKey)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar los datos: %v", err)
	}

	todo := map[string]string{
		"encryptedData": datosCifrados, //Contendrá la token y la fecha de expiración
		"fileKey":       base64.StdEncoding.EncodeToString(encryptedFileKey),
		"nonce":         base64.StdEncoding.EncodeToString(fileKeyNonce),
	}
	jsonBytes, err := json.Marshal(todo)
	if err != nil {
		return nil, fmt.Errorf("error al serializar datos cifrados: %v", err)
	}
	return jsonBytes, nil
}

// Put almacena o actualiza (key, value) dentro de un bucket = namespace.
// No se soportan sub-buckets.
func (s *BboltStore) Put(namespace string, key, value []byte) error { //antes de hacer el value cufamos el value. Igual con el get
	if s.masterKey == nil {
		return fmt.Errorf("clave maestra no configurada")
	}

	var jsonBytes []byte
	var err error
	switch namespace {
	case "auth":
		jsonBytes, err = putAuthData(s, value)
		if err != nil {
			return err
		}
	case "userdata":
		jsonBytes, err = putUserData(s, value)
		if err != nil {
			return err
		}
	case "sessions": //De ser posible arreglar la forma en la que se guardan los datos encriptados (formato "token:expiracy" a JSON)
		jsonBytes, err = putSessionsData(s, value)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Namespace no definido para operación PUT")
	}

	// 6. Guardamos el JSON en el bucket
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return fmt.Errorf("error al crear/abrir bucket '%s': %v", namespace, err)
		}
		return b.Put(key, jsonBytes)
	})
} // almcenar el value del put y lo encripto

// Get recupera el valor de (key) en el bucket = namespace.
func (s *BboltStore) Get(namespace string, key []byte) ([]byte, error) {
	var val []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("bucket no encontrado: %s", namespace)
		}
		val = b.Get(key)
		if val == nil {
			return fmt.Errorf("clave no encontrada: %s", string(key))
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	// fmt.Println("Data: ", string(val))
	// Parseamos el JSON
	var data struct {
		Hash          string `json:"hash,omitempty"`
		Salt          string `json:"salt,omitempty"`
		EncryptedData string `json:"encryptedData"`
		FileKey       string `json:"fileKey"`
		Nonce         string `json:"nonce"`
	}
	if err := json.Unmarshal(val, &data); err != nil {
		return nil, fmt.Errorf("error al parsear datos cifrados: %v", err)
	}

	// Derivamos la clave maestra
	// masterKey := encryption.DeriveMasterKey(userPassword, salt)

	// Decodificamos clave de archivo cifrada y nonce
	encryptedFileKey, _ := base64.StdEncoding.DecodeString(data.FileKey)
	nonce, _ := base64.StdEncoding.DecodeString(data.Nonce)

	// Si no hay clave maestra, devolver el valor cifrado sin descifrar ---> Permite registrar e iniciar sesión sin clave maestra pero sin perder seguridad
	if s.masterKey == nil {
		if namespace != "auth" {
			return nil, fmt.Errorf("clave maestra no configurada y no se permite acceso a este namespace")
		}
		return val, nil
	}

	// Desciframos la fileKey
	fileKey, err := encryption.DecryptFileKey(encryptedFileKey, nonce, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar fileKey: %v", err)
	}

	// Desciframos el contenido
	plaintext, err := encryption.VerifyAndDecryptStr(data.EncryptedData, fileKey)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar el historial médico: %v", err)
	}

	return []byte(plaintext), nil
	// var val []byte
	// err := s.db.View(func(tx *bbolt.Tx) error {
	// 	b := tx.Bucket([]byte(namespace))
	// 	if b == nil {
	// 		return fmt.Errorf("bucket no encontrado: %s", namespace)
	// 	}
	// 	val = b.Get(key)
	// 	if val == nil {
	// 		return fmt.Errorf("clave no encontrada: %s", string(key))
	// 	}
	// 	return nil
	// }) // se desencripta antes de hacer el return

	// if string(val) == "" {
	// 	fmt.Println("Los datos leídos en ", namespace, " están vacíos")
	// } else {
	// 	// Decodificar el string base64 recibido
	// 	// datosCifrados, err := base64.StdEncoding.DecodeString(string(val))
	// 	// Definir la clave y el vector de inicialización (IV) que usaste en el cliente
	// 	cipherKey := encryption.ObtenerSHA256("Clave")
	// 	// iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize] // aes.BlockSize es de 16 bytes

	// 	// Descifrar el contenido cifrado
	// 	textoEnClaroDescifrado, err := encryption.VerifyAndDecryptStr(string(val), cipherKey)
	// 	if err != nil {
	// 		fmt.Println("Error al descifrar los datos en el cliente: ", err)
	// 	}
	// 	val = []byte(textoEnClaroDescifrado)
	// }

	// // fmt.Println(datosCifrados, " ---> ", textoEnClaroDescifrado)
	// return val, err
}

// Delete elimina la clave 'key' del bucket = namespace.
func (s *BboltStore) Delete(namespace string, key []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("bucket no encontrado: %s", namespace)
		}
		return b.Delete(key)
	})
}

// ListKeys devuelve todas las claves del bucket = namespace.
func (s *BboltStore) ListKeys(namespace string) ([][]byte, error) {
	var keys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("bucket no encontrado: %s", namespace)
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			keys = append(keys, kCopy)
		}
		return nil
	})
	return keys, err
}

// KeysByPrefix devuelve las claves que inicien con 'prefix' en el bucket = namespace.
func (s *BboltStore) KeysByPrefix(namespace string, prefix []byte) ([][]byte, error) {
	var matchedKeys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("bucket no encontrado: %s", namespace)
		}
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			matchedKeys = append(matchedKeys, kCopy)
		}
		return nil
	})
	return matchedKeys, err
}

// Close cierra la base de datos bbolt.
func (s *BboltStore) Close() error {
	return s.db.Close()
}

// Dump imprime todo el contenido de la base de datos bbolt para propósitos de depuración.
func (s *BboltStore) Dump() error {
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, b *bbolt.Bucket) error {
			fmt.Printf("Bucket: %s\n", string(bucketName))
			return b.ForEach(func(k, v []byte) error {
				fmt.Printf("  Key: %s, Value: %s\n", string(k), string(v))
				return nil
			})
		})
	})
	if err != nil {
		return fmt.Errorf("error al hacer el volcado de depuración: %v", err)
	}
	return nil
}
