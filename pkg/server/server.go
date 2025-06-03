// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"prac/pkg/api"
	"prac/pkg/encryption"
	"prac/pkg/store"

	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/scrypt"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db           store.Store // base de datos
	log          *log.Logger // logger para mensajes de error e información
	tokenCounter int64       // contador para generar tokens
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
	err = http.ListenAndServeTLS(":10443", "login/cert.pem", "login/key.pem", mux)

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
		res = s.registerUserCambiado(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateDataSinCifrar(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionViewAllRecords:
		res = s.viewAllRecords(req)
	case api.ActionDeleteUser:
		res = s.deleteUser(req)
	case api.ActionManageAccounts:
		res = s.manageAccounts(req)
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

// GenerateJWT genera un token JWT firmado con jwtSecret que expira en 30 minutos
func GenerateJWT(username, role string) (string, error) {
	// Obtener el secreto desde la variable de entorno
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", fmt.Errorf("Error al generar token") // puedes definir este error personalizado si quieres
	}

	// Crear las claims (datos dentro del token)
	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(30 * time.Minute).Unix(),
		"iat":      time.Now().Unix(),
	}

	// Crear token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Firmar token con la clave secreta
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Claims personalizadas (opcional, pero aquí usamos MapClaims por flexibilidad)
type Claims struct {
	Username string
	Role     string
	jwt.RegisteredClaims
}

// ValidateJWT valida el token JWT y devuelve el username y role si es válido
func ValidateJWT(tokenStr string) (string, string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", "", errors.New("JWT_SECRET no está configurado")
	}

	// Parsear el token y validar firma y expiración
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Verificar que se use el método de firma esperado
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inválido")
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return "", "", errors.New("token inválido o expirado")
	}

	// Extraer claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		username, _ := claims["username"].(string)
		role, _ := claims["role"].(string)
		return username, role, nil
	}

	return "", "", errors.New("no se pudieron leer las claims")
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

// // verifyPassword compara una contraseña con su hash y salt.
// func verifyPassword(password string, hash, salt []byte) bool {
// 	newHash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
// 	if err != nil {
// 		return false
// 	}
// 	return string(newHash) == string(hash)
// }

func verifyPassword(password string, hash, salt []byte) bool {
	newHash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return false
	}
	return hmac.Equal(newHash, hash)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
// Modificamos registerUser para almacenar contraseñas cifradas.

// Modificamos registerUser para incluir roles.
func (s *server) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" || req.Role == "" {
		return api.Response{Success: false, Message: "Faltan credenciales o rol"}
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

	// Almacenar hash, salt y rol en el namespace 'auth'
	authData := base64.StdEncoding.EncodeToString(hash) + ":" + base64.StdEncoding.EncodeToString(salt) + ":" + req.Role
	if err := s.db.Put("auth", []byte(req.Username), []byte(authData)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Crear entrada vacía en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	token := s.generateToken()
	expiry := time.Now().Add(30 * time.Minute).Unix() // 30 minutos de validez
	sessionData := fmt.Sprintf("%s:%d", token, expiry)
	if err := s.db.Put("sessions", []byte(req.Username), []byte(sessionData)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	// Si el usuario es administrador, retornamos una respuesta indicando que debe mostrarse el menú de admin
	if req.Role == "admin" {
		return api.Response{
			Success: true,
			Message: "Usuario registrado y logueado como administrador",
			Token:   token,
			Data:    "admin", // Indicamos que es un administrador
		}
	}

	// Para otros roles, simplemente retornamos el éxito del registro y login
	return api.Response{
		Success: true,
		Message: "Usuario registrado y logueado",
		Token:   token,
	}
	// return api.Response{Success: true, Message: "Usuario registrado"}
}

// Modificamos registerUser para incluir roles.
func (s *server) registerUserCambiado(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" || req.Role == "" {
		return api.Response{Success: false, Message: "Faltan credenciales o rol"}
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
	fmt.Println("La contraseña es: ", req.Password)
	hash, salt, err := hashPassword(req.Password)
	fmt.Println("hash: ", hash, " salt: ", salt)
	if err != nil {
		return api.Response{Success: false, Message: "Error al procesar contraseña"}
	}

	//Derivar y establecer clave maestra a partir de contraseña y salt
	masterKey := encryption.DeriveMasterKey([]byte(req.Password), []byte(salt))
	s.db.(*store.BboltStore).SetMasterKey(masterKey)

	// Almacenar hash, salt y rol en el namespace 'auth'
	authData := map[string]string{
		"hash": base64.StdEncoding.EncodeToString(hash),
		"salt": base64.StdEncoding.EncodeToString(salt),
		"role": req.Role,
		"data": req.Data,
	}
	// authData := +":" + +":" + +":" + req.Data
	authDataBytes, err := json.Marshal(authData)
	fmt.Println("authData server: ", authData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar datos del usuario"}
	}
	if err := s.db.Put("auth", []byte(req.Username), authDataBytes); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Crear entrada vacía en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	token := s.generateToken()
	expiry := time.Now().Add(30 * time.Minute).Unix() // 30 minutos de validez
	sessionData := fmt.Sprintf("%s:%d", token, expiry)
	fmt.Println("sessionData: ", sessionData)
	fmt.Println("username: ", req.Username)
	if err := s.db.Put("sessions", []byte(req.Username), []byte(sessionData)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	// Si el usuario es administrador, retornamos una respuesta indicando que debe mostrarse el menú de admin
	if req.Role == "admin" {
		return api.Response{
			Success: true,
			Message: "Usuario registrado y logueado como administrador",
			Token:   token,
			Data:    "admin", // Indicamos que es un administrador
		}
	}

	// Para otros roles, simplemente retornamos el éxito del registro y login
	return api.Response{
		Success: true,
		Message: "Usuario registrado y logueado",
		Token:   token,
	}
	// return api.Response{Success: true, Message: "Usuario registrado"}
}

func extractRole(data string) (string, error) {
	idx := strings.Index(data, "{")
	if idx == -1 {
		return "", errors.New("formato inválido: no se encontró '{'")
	}

	rol := data[:idx]

	switch rol {
	case "admin", "medic", "patient":
		return rol, nil
	default:
		return "", errors.New("rol inválido detectado")
	}
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
	var data map[string]string

	if err := json.Unmarshal(authData, &data); err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos de autenticación"}
	}

	fmt.Println("AuthData: ", data)
	// fmt.Println("Tamaño: ", len(data))
	if len(data) != 5 {
		return api.Response{Success: false, Message: "Datos de autenticación corruptos"}
	}
	hash, _ := base64.StdEncoding.DecodeString(data["hash"])
	salt, _ := base64.StdEncoding.DecodeString(data["salt"])
	fileKey := data["fileKey"]
	nonce, _ := base64.StdEncoding.DecodeString(data["nonce"])
	encryptedData := data["encryptedData"]

	// Verificar contraseña
	if !verifyPassword(req.Password, []byte(hash), []byte(salt)) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Derivar y establecer clave maestra
	masterKey := encryption.DeriveMasterKey([]byte(req.Password), []byte(salt))
	s.db.(*store.BboltStore).SetMasterKey(masterKey)

	fileKeyDecoded, err := base64.StdEncoding.DecodeString(fileKey)
	if err != nil {
		return api.Response{Success: false, Message: "Clave de archivo corrupta (base64)"}
	}
	decryptedFileKey, err := encryption.DecryptFileKey(fileKeyDecoded, nonce, masterKey)

	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar clave de archivo"}
	}
	fmt.Println("Tamaño clave descifrada:", len(decryptedFileKey), " Clave de archivo descifrada: ", decryptedFileKey) // Debe ser 32

	// Usar directamente la clave descifrada
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return api.Response{Success: false, Message: "Datos cifrados corruptos"}
	}

	decryptedData, err := encryption.VerifyAndDecryptBytes(encryptedBytes, decryptedFileKey)
	fmt.Println("Decrypted data = ", decryptedData)

	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar datos del usuario"}
	}

	// Generar token y guardar en 'sessions'
	token := s.generateToken()
	expiry := time.Now().Add(30 * time.Minute).Unix() // 30 minutos de validez
	sessionData := fmt.Sprintf("%s:%d", token, expiry)
	if err := s.db.Put("sessions", []byte(req.Username), []byte(sessionData)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	// Para otros roles, simplemente retornamos el éxito del registro y login
	role, err := extractRole(decryptedData)
	fmt.Println("reqrole = ", role)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener rol del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Usuario logueado",
		Token:   token,
		Data:    role,
	}
}

// Añadimos funciones para las acciones del administrador.
func (s *server) viewAllRecords(req api.Request) api.Response {
	// Verificar credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener todos los expedientes médicos
	var allRecords []api.Historial
	err := s.db.ForEach("userdata", func(key, value []byte) error {
		var userRecords []api.Historial
		if len(value) > 0 {
			// Decodificar y descifrar los datos
			datosCifrados, err := base64.StdEncoding.DecodeString(string(value))
			if err != nil {
				return fmt.Errorf("error al decodificar datos cifrados: %v", err)
			}
			key := encryption.ObtenerSHA256("Clave")
			iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
			datosDescifrados, err := encryption.DescifrarBytes(datosCifrados, key, iv)
			if err != nil {
				return fmt.Errorf("error al descifrar datos: %v", err)
			}

			// Deserializar los expedientes
			if err := json.Unmarshal([]byte(datosDescifrados), &userRecords); err != nil {
				return fmt.Errorf("error al deserializar expedientes: %v", err)
			}
			allRecords = append(allRecords, userRecords...)
		}
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener expedientes médicos: " + err.Error()}
	}

	// Serializar los expedientes para enviarlos al cliente
	data, _ := json.Marshal(allRecords)
	return api.Response{Success: true, Message: "Expedientes médicos obtenidos", Data: string(data)}
}

func (s *server) manageRecords(req api.Request) api.Response {
	// Verificar credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Procesar la solicitud (crear, editar o eliminar)
	var record api.Historial
	if err := json.Unmarshal([]byte(req.Data), &record); err != nil {
		return api.Response{Success: false, Message: "Error al procesar los datos del expediente"}
	}

	// Obtener los expedientes del usuario
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener expedientes del usuario"}
	}

	var records []api.Historial
	if len(rawData) > 0 {
		// Decodificar y descifrar los datos
		datosCifrados, err := base64.StdEncoding.DecodeString(string(rawData))
		if err != nil {
			return api.Response{Success: false, Message: "Error al decodificar datos cifrados"}
		}
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
		datosDescifrados, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		if err != nil {
			return api.Response{Success: false, Message: "Error al descifrar datos"}
		}

		// Deserializar los expedientes
		if err := json.Unmarshal([]byte(datosDescifrados), &records); err != nil {
			return api.Response{Success: false, Message: "Error al deserializar expedientes"}
		}
	}

	// Crear, editar o eliminar según el ID
	switch req.Action {
	case api.ActionCreateRecord:
		// Crear nuevo expediente
		record.ID = fmt.Sprintf("%d", len(records)+1)
		records = append(records, record)
	case api.ActionEditRecord:
		// Editar expediente existente
		updated := false
		for i, r := range records {
			if r.ID == record.ID {
				records[i] = record
				updated = true
				break
			}
		}
		if !updated {
			return api.Response{Success: false, Message: "Expediente no encontrado"}
		}
	case api.ActionDeleteRecord:
		// Eliminar expediente
		deleted := false
		for i, r := range records {
			if r.ID == record.ID {
				records = append(records[:i], records[i+1:]...)
				deleted = true
				break
			}
		}
		if !deleted {
			return api.Response{Success: false, Message: "Expediente no encontrado"}
		}
	default:
		return api.Response{Success: false, Message: "Acción no válida"}
	}

	// Serializar y cifrar los expedientes actualizados
	dataActualizada, err := json.Marshal(records)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar los expedientes"}
	}
	key := encryption.ObtenerSHA256("Clave")
	iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
	expedientesCifrados, err := encryption.CifrarString(string(dataActualizada), key, iv)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar los expedientes"}
	}

	// Guardar los expedientes actualizados
	if err := s.db.Put("userdata", []byte(req.Username), []byte(expedientesCifrados)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar los expedientes"}
	}

	return api.Response{Success: true, Message: "Expedientes actualizados correctamente"}
}

func (s *server) deleteUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Eliminar usuario de la base de datos
	if err := s.db.Delete("auth", []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al eliminar usuario"}
	}
	if err := s.db.Delete("userdata", []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al eliminar datos del usuario"}
	}
	if err := s.db.Delete("sessions", []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al eliminar sesión del usuario"}
	}

	return api.Response{Success: true, Message: "Usuario eliminado correctamente"}
}

func (s *server) manageAccounts(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener datos del usuario
	authData, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Retornar los datos al cliente
	return api.Response{Success: true, Message: "Datos de la cuenta obtenidos", Data: string(authData)}
}

func (s *server) assignRoles(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener datos del usuario
	authData, err := s.db.Get("auth", []byte(req.Data))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Actualizar el rol
	parts := strings.Split(string(authData), ":")
	if len(parts) != 3 {
		return api.Response{Success: false, Message: "Datos de autenticación corruptos"}
	}
	parts[2] = req.Role // Cambiar el rol
	newAuthData := strings.Join(parts, ":")
	if err := s.db.Put("auth", []byte(req.Data), []byte(newAuthData)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar el rol"}
	}

	return api.Response{Success: true, Message: "Rol actualizado correctamente"}
}

func (s *server) viewStatsAndLogs(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Generar estadísticas (ejemplo: número de usuarios y expedientes)
	var userCount, recordCount int
	_ = s.db.ForEach("auth", func(key, value []byte) error {
		userCount++
		return nil
	})
	_ = s.db.ForEach("userdata", func(key, value []byte) error {
		var records []api.Historial
		if err := json.Unmarshal(value, &records); err == nil {
			recordCount += len(records)
		}
		return nil
	})

	// Retornar estadísticas
	stats := fmt.Sprintf("Usuarios registrados: %d\nExpedientes médicos: %d", userCount, recordCount)
	return api.Response{Success: true, Message: "Estadísticas obtenidas", Data: stats}
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
	var historial api.Historial
	if err := json.Unmarshal([]byte(textoEnClaroDescifrado), &historial); err != nil {
		return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
	}
	//-----------------------------------
	var expedientesNew []api.Historial //Donde guardaremos todos los expedientes a serializar y cifrar

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

func (s *server) updateDataSinCifrar(req api.Request) api.Response {
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
		return api.Response{Success: false, Message: "El usuario no tiene ningún dato guardado"}
	}

	// Procesar el historial médico que llega descifrado --------> se hace para agregar el id del historial -----> perdemos un poco de seguridad porque el admin del servidor lo podrà ver, pero se puede modificar el contenido
	var historial api.Historial
	if err := json.Unmarshal([]byte(req.Data), &historial); err != nil {
		return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
	}
	//-----------------------------------
	var expedientesNew []api.Historial //Donde guardaremos todos los expedientes a serializar y cifrar

	// Obtenemos los datos asociados al usuario desde 'userdata' en la base de datos
	data, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	if data != nil && len(data) != 0 { // Si existe, deserializar
		// var expedientes []string
		// fmt.Println("Data: ", data)
		// fmt.Println("len(data): ", len(data))
		// Decodificar el string base64 recibido
		expedientesRaw := data
		fmt.Println("expedientes: ", expedientesRaw)
		//---------------------
		// Escribimos el nuevo dato en 'userdata'
		err := json.Unmarshal([]byte(expedientesRaw), &expedientesNew)
		if err != nil {
			return api.Response{Success: false, Message: "Error al deserializar los expedientes guardados del paciente"}
		}
		// Agregar el nuevo expediente al slice
		expedientesNew = append(expedientesNew, historial)
		fmt.Println("expedientes+nuevo: ", expedientesNew)
	} else { //Si no hay ningun expediente simplemente lo añade
		expedientesNew = append(expedientesNew, historial)
	}

	// Serializar el array actualizado
	dataActualizada, err := json.Marshal(expedientesNew)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar los expedientes del paciente más el nuevo"}
	}
	if err := s.db.Put("userdata", []byte(req.Username), []byte(dataActualizada)); err != nil {
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

	//Eliminar clave maestra y clave de archivo
	s.db.(*store.BboltStore).SetMasterKey(nil)
	// s.db.(*store.BboltStore).SetFileKey(nil)

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
	stored, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	parts := strings.Split(string(stored), ":")
	if len(parts) != 2 {
		return false
	}
	storedToken := parts[0]
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	if storedToken != token {
		return false
	}
	if time.Now().Unix() > expiry {
		// Token expirado, eliminar sesión
		_ = s.db.Delete("sessions", []byte(username))
		return false
	}
	return true
}

func (s *server) enumerateRecords(req api.Request) api.Response {
	// Verificar credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener los expedientes del usuario
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener expedientes del usuario"}
	}

	var records []api.Historial
	if len(rawData) > 0 {
		// Decodificar y descifrar los datos
		datosCifrados, err := base64.StdEncoding.DecodeString(string(rawData))
		if err != nil {
			return api.Response{Success: false, Message: "Error al decodificar datos cifrados"}
		}
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
		datosDescifrados, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		if err != nil {
			return api.Response{Success: false, Message: "Error al descifrar datos"}
		}

		// Deserializar los expedientes
		if err := json.Unmarshal([]byte(datosDescifrados), &records); err != nil {
			return api.Response{Success: false, Message: "Error al deserializar expedientes"}
		}
	}

	// Enumerar los expedientes y asignar IDs si no tienen
	updated := false
	for i := range records {
		if records[i].ID == "" {
			records[i].ID = fmt.Sprintf("%d", i+1) // Asignar un ID basado en el índice
			updated = true
		}
	}

	// Si se actualizaron los IDs, guardar los cambios
	if updated {
		dataActualizada, err := json.Marshal(records)
		if err != nil {
			return api.Response{Success: false, Message: "Error al serializar los expedientes"}
		}
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
		expedientesCifrados, err := encryption.CifrarString(string(dataActualizada), key, iv)
		if err != nil {
			return api.Response{Success: false, Message: "Error al cifrar los expedientes"}
		}
		if err := s.db.Put("userdata", []byte(req.Username), []byte(expedientesCifrados)); err != nil {
			return api.Response{Success: false, Message: "Error al guardar los expedientes actualizados"}
		}
	}

	return api.Response{Success: true, Message: "Expedientes enumerados correctamente", Data: fmt.Sprintf("%d expedientes procesados", len(records))}
}

func (s *server) listRecordIDs(req api.Request) api.Response {
	// Verificar credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener los expedientes del usuario
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener expedientes del usuario"}
	}

	var records []api.Historial
	if len(rawData) > 0 {
		// Decodificar y descifrar los datos
		datosCifrados, err := base64.StdEncoding.DecodeString(string(rawData))
		if err != nil {
			return api.Response{Success: false, Message: "Error al decodificar datos cifrados"}
		}
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]
		datosDescifrados, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		if err != nil {
			return api.Response{Success: false, Message: "Error al descifrar datos"}
		}

		// Deserializar los expedientes
		if err := json.Unmarshal([]byte(datosDescifrados), &records); err != nil {
			return api.Response{Success: false, Message: "Error al deserializar expedientes"}
		}
	}

	// Crear un array con los IDs de los expedientes
	var ids []string
	for _, record := range records {
		ids = append(ids, record.ID)
	}

	// Formatear los IDs como un string
	idList := strings.Join(ids, " ")

	return api.Response{Success: true, Message: "Lista de IDs obtenida", Data: "expedientes: " + idList}
}

// ...existing code...

// listUsers devuelve la lista de usuarios registrados (solo nombre de usuario).
func (s *server) listUsers(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}

	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Solo permitir a administradores
	authData, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "No se pudo verificar el rol"}
	}
	parts := strings.Split(string(authData), ":")
	if len(parts) != 3 || parts[2] != "admin" {
		return api.Response{Success: false, Message: "Solo el administrador puede ver la lista de usuarios"}
	}

	// Listar usuarios
	var users []string
	err = s.db.ForEach("auth", func(key, value []byte) error {
		users = append(users, string(key))
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener la lista de usuarios"}
	}

	return api.Response{
		Success: true,
		Message: "Lista de usuarios obtenida",
		Data:    strings.Join(users, ", "),
	}
}

// ...existing code...
