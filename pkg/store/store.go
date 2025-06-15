// El paquete store provee una interfaz genérica de almacenamiento.
// Cada motor (en nuestro caso bbolt) se implementa en un archivo separado
// que debe cumplir la interfaz Store.
package store

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// boltStore es una implementación de Store usando BoltDB.
type boltStore struct {
	db *bolt.DB
}

// ForEach itera sobre todas las claves y valores en un namespace (bucket).
func (s *BboltStore) ForEach(namespace string, fn func(key, value []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return fmt.Errorf("bucket not found: %s", namespace)
		}
		return bucket.ForEach(fn)
	})
}

// Store define los métodos comunes que deben implementar
// los diferentes motores de almacenamiento.
type Store interface {
	// Put almacena (o actualiza) el valor 'value' bajo la clave 'key'
	// dentro del 'namespace' indicado.
	Put(namespace string, key, value []byte) error

	// Get recupera el valor asociado a la clave 'key'
	// dentro del 'namespace' especificado.
	Get(namespace string, key []byte) ([]byte, error)

	// Delete elimina la clave 'key' dentro del 'namespace' especificado.
	Delete(namespace string, key []byte) error

	// ListKeys devuelve todas las claves existentes en el namespace.
	ListKeys(namespace string) ([][]byte, error)

	// KeysByPrefix devuelve las claves que empiecen con 'prefix' dentro
	// del namespace especificado.
	KeysByPrefix(namespace string, prefix []byte) ([][]byte, error)

	ForEach(namespace string, fn func(key, value []byte) error) error // Asegúrate de incluir esto

	//Métodos para gestionar clave maestra
	SetMasterKey(key []byte) error
	GetMasterKey() ([]byte, error)
	SetFileKey(key []byte) error
	GetFileKey() ([]byte, error)

	// Close cierra cualquier recurso abierto (por ej. cerrar la base de datos).
	Close() error

	// Dump imprime todo el contenido de la base de datos para depuración de errores.
	Dump() error

	CreateBucketIfNotExists(bucket string) error
}

// NewStore permite instanciar diferentes tipos de Store
// dependiendo del motor solicitado (sólo se soporta "bbolt").
func NewStore(engine, path string) (Store, error) {
	switch engine {
	case "bbolt":
		return NewBboltStore(path)
	default:
		return nil, fmt.Errorf("motor de almacenamiento desconocido: %s", engine)
	}
}
