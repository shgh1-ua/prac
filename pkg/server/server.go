// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"prac/pkg/api"
	"prac/pkg/encryption"
	"prac/pkg/store"

	"crypto/aes"
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db           store.Store // base de datos
	log          *log.Logger // logger para mensajes de error e información
	tokenCounter int64       // contador para generar tokens
}

// Definimos una estructura para serializar los datos
type Paciente struct {
	IdPac     int    `json:"idpac"`
	Nombre    string `json:"nombre"`
	Apellidos string `json:"apellidos"`
	Edad      int    `json:"edad"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type Medico struct {
	IdMed     int    `json:"idmed"`
	Nombre    string `json:"nombre"`
	Apellidos string `json:"apellidos"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type Historial struct {
	ID          string `json:"id"`
	Nombre      string `json:"nombre"`
	Edad        int    `json:"edad"`
	Diagnostico string `json:"diagnostico"`
	Tratamiento string `json:"tratamiento"`
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {
	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	err = http.ListenAndServe(":8080", mux)

	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateToken crea un token único incrementando un contador interno (inseguro)
func (s *server) generateToken() string {
	tokenBytes := make([]byte, 32) // Genera un token de 32 bytes
	_, err := rand.Read(tokenBytes)
	if err != nil {
		s.log.Println("Error generando token aleatorio:", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(tokenBytes) // Codifica el token en base64 URL-safe
}

// Para que sea mejor le metem,os jwt y echa de expiracion
// hashPassword genera un hash seguro de la contraseña usando scrypt.
func hashPassword(password string) (hash, salt []byte, err error) {
	salt = make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	hash, err = scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	return hash, salt, err
}

// verifyPassword compara una contraseña con su hash y salt.
func verifyPassword(password string, hash, salt []byte) bool {
	newHash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return false
	}
	return string(newHash) == string(hash)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
// Modificamos registerUser para almacenar contraseñas cifradas.
func (s *server) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificar si el usuario ya existe
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Generar hash y salt para la contraseña
	hash, salt, err := hashPassword(req.Password)
	if err != nil {
		return api.Response{Success: false, Message: "Error al procesar contraseña"}
	}

	// Almacenar hash y salt en el namespace 'auth'
	authData := base64.StdEncoding.EncodeToString(hash) + ":" + base64.StdEncoding.EncodeToString(salt)
	if err := s.db.Put("auth", []byte(req.Username), []byte(authData)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Crear entrada vacía en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// Modificamos loginUser para validar contraseñas cifradas.
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recuperar hash y salt del usuario
	authData, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Separar hash y salt
	parts := strings.Split(string(authData), ":")
	if len(parts) != 2 {
		return api.Response{Success: false, Message: "Datos de autenticación corruptos"}
	}
	hash, _ := base64.StdEncoding.DecodeString(parts[0])
	salt, _ := base64.StdEncoding.DecodeString(parts[1])

	// Verificar contraseña
	if !verifyPassword(req.Password, hash, salt) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generar token y guardar en 'sessions'
	token := s.generateToken()
	if err := s.db.Put("sessions", []byte(req.Username), []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	// // Comprobar si el cliente está enviando datos cifrados
	// if string(rawData) == "" {
	// 	return api.Response{Success: false, Message: "No se recibieron datos"}
	// }

	// // Decodificar el string base64 recibido
	// datosCifrados, err := base64.StdEncoding.DecodeString(string(rawData))
	// if err != nil {
	// 	return api.Response{Success: false, Message: "Error al decodificar los datos cifrados"}
	// }

	// // Definir la clave y el vector de inicialización (IV) que usaste en el cliente
	// key := encryption.ObtenerSHA256("Clave")
	// iv := encryption.ObtenerSHA256("<inicializar>")
	// iv = iv[:aes.BlockSize] // aes.BlockSize es de 16 bytes

	// // Descifrar el contenido cifrado
	// textoEnClaroDescifrado, err := encryption.DescifrarBytes(datosCifrados, key)
	// // if err != nil {
	// // 	return api.Response{Success: false, Message: "Error al descifrar los datos"}
	// // }

	// // // Procesar el historial médico que llega descifrado
	// // var historial Medico
	// // if err := json.Unmarshal([]byte(textoEnClaroDescifrado), &historial); err != nil {
	// // 	return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
	// // }
	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(rawData), //Modificar para que se vean mejor los datos
	}
}

// func getNextId(expedientes []string) int {

// }

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos nuevo dato del cliente
	// Comprobar si el cliente está enviando datos cifrados
	if req.Data == "" {
		return api.Response{Success: false, Message: "No se recibieron datos"}
	}
	// Decodificar el string base64 recibido
	datosCifrados, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return api.Response{Success: false, Message: "Error al decodificar los datos cifrados"}
	}
	// Definir la clave y el vector de inicialización (IV) que usamos en el cliente
	key := encryption.ObtenerSHA256("Clave")
	iv := encryption.ObtenerSHA256("<inicializar>")
	iv = iv[:aes.BlockSize] // aes.BlockSize es de 16 bytes
	// Descifrar el contenido cifrado
	textoEnClaroDescifrado, err := encryption.DescifrarBytes(datosCifrados, key, iv)
	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar los datos"}
	}

	// Procesar el historial médico que llega descifrado --------> se hace para agregar el id del historial -----> perdemos un poco de seguridad porque el admin del servidor lo podrà ver, pero se puede modificar el contenido
	var historial Historial
	if err := json.Unmarshal([]byte(textoEnClaroDescifrado), &historial); err != nil {
		return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
	}
	//-----------------------------------
	var expedientesNew []Historial //Donde guardaremos todos los expedientes a serializar y cifrar

	// Obtenemos los datos asociados al usuario desde 'userdata' en la base de datos
	data, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	if data != nil && len(data) != 0 {
		// Si existe, deserializar
		// var expedientes []string
		fmt.Println("Data: ", data)
		fmt.Println("len(data): ", len(data))
		// Decodificar el string base64 recibido
		datosCifrados, err := base64.StdEncoding.DecodeString(string(data))
		fmt.Println("datosCifrados: ", datosCifrados)
		// Definir la clave y el vector de inicialización (IV) que usaste en el cliente
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize] // aes.BlockSize es de 16 bytes

		// Descifrar el contenido cifrado
		expedientesRaw, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		fmt.Println("expedientes: ", expedientesRaw)
		if err != nil {
			fmt.Println("Error al descifrar los datos en el cliente: ", err)
		}
		//---------------------
		// Escribimos el nuevo dato en 'userdata'
		errN := json.Unmarshal([]byte(expedientesRaw), &expedientesNew)
		if errN != nil {
			return api.Response{Success: false, Message: "Error al deserializar los expedientes guardados del paciente"}
		}
		fmt.Println("expedientes+nuevo: ", expedientesNew)
		// Agregar el nuevo expediente al slice
		expedientesNew = append(expedientesNew, historial)
	} else {
		expedientesNew = append(expedientesNew, historial)
	}

	// Serializar el array actualizado
	dataActualizada, err := json.Marshal(expedientesNew)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar los expedientes del paciente más el nuevo"}
	}
	//Ciframos todo de nuevo
	expedientesCifrados, err := encryption.CifrarString(string(dataActualizada), key, iv)
	if err != nil {
		fmt.Println("Error al cifrar Datos:", err)
		return api.Response{Success: false, Message: "Error al cifrar el array de expedientes"}
	}
	if err := s.db.Put("userdata", []byte(req.Username), []byte(expedientesCifrados)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}
	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username, token string) bool {
	storedToken, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	return string(storedToken) == token
}
