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

	// Crear el bucket "global" si no existe
	if _, err := srv.db.Get("global", []byte("expediente_counter")); err != nil {
		_ = srv.db.Put("global", []byte("expediente_counter"), []byte("0"))
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
		res = s.updatePersonalData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionViewAllRecords:
		res = s.viewAllRecords(req)
	case api.ActionDeleteUser:
		res = s.deleteUser(req)
	case api.ActionManageAccounts:
		res = s.manageAccounts(req)
	case api.ActionViewStatsAndLogs:
		res = s.viewStatsAndLogs(req)
	case api.ActionDeleteAllUsersAndData:
		res = s.deleteAllUsersAndData(req)
	case api.ActionListUsers:
		res = s.listUsers(req)
	case api.ActionAssignRole:
		res = s.assignRoles(req)
	case api.ActionViewLogs:
		res = s.viewLogs(req)
	case api.ActionCreateRecord, api.ActionEditRecord, api.ActionDeleteRecord:
		res = s.manageRecords(req)

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
func (s *server) registerUserCambiado(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" || req.Role == "" {
		fmt.Println("DEBUG registro: Faltan credenciales o rol")
		return api.Response{Success: false, Message: "Faltan credenciales o rol"}
	}

	// Verificar si el usuario ya existe
	exists, err := s.userExists(req.Username)
	fmt.Printf("DEBUG registro: userExists(%s) = %v, err = %v\n", req.Username, exists, err)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		fmt.Println("DEBUG registro: El usuario ya existe")
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Generar hash y salt para la contraseña
	fmt.Println("DEBUG registro: Contraseña recibida =", req.Password)
	hash, salt, err := hashPassword(req.Password)
	fmt.Printf("DEBUG registro: hash = %v, salt = %v, err = %v\n", hash, salt, err)
	if err != nil {
		return api.Response{Success: false, Message: "Error al procesar contraseña"}
	}

	//Derivar y establecer clave maestra a partir de contraseña y salt
	masterKey := encryption.DeriveMasterKey([]byte(req.Password), []byte(salt))
	s.db.(*store.BboltStore).SetMasterKey(masterKey)

	// Generar una clave de archivo real y cifrar datos vacíos
	fileKey, err := encryption.GenerateFileKey()
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar fileKey"}
	}
	encryptedFileKey, fileKeyNonce, err := encryption.EncryptFileKey(fileKey, masterKey)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar fileKey"}
	}

	// Cifra datos vacíos (o los datos iniciales del usuario si tienes)
	// Cifra datos vacíos (o los datos iniciales del usuario si tienes)
	fmt.Println("DEBUG registro: req.Data =", req.Data)
	datosCifrados, err := encryption.EncryptAndSignStr(req.Data, fileKey)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar datos iniciales"}
	}
	fmt.Println("DEBUG registro: datosCifrados =", datosCifrados)

	// Almacenar hash, salt y rol en el namespace 'auth'
	authData := map[string]string{
		"hash":          base64.StdEncoding.EncodeToString(hash),
		"salt":          base64.StdEncoding.EncodeToString(salt),
		"role":          req.Role,
		"data":          req.Data,
		"fileKey":       base64.StdEncoding.EncodeToString(encryptedFileKey),
		"nonce":         base64.StdEncoding.EncodeToString(fileKeyNonce),
		"encryptedData": datosCifrados,
	}
	fmt.Println("DEBUG registro: authData a guardar =", authData)

	authDataBytes, err := json.Marshal(authData)
	if err != nil {
		fmt.Println("DEBUG registro: Error al serializar datos del usuario:", err)
		return api.Response{Success: false, Message: "Error al serializar datos del usuario"}
	}
	if err := s.db.Put("auth", []byte(req.Username), authDataBytes); err != nil {
		fmt.Println("DEBUG registro: Error al guardar credenciales:", err)
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Crear entrada vacía en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		fmt.Println("DEBUG registro: Error al inicializar datos de usuario:", err)
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	token := s.generateToken()
	expiry := time.Now().Add(30 * time.Minute).Unix()
	sessionData := fmt.Sprintf("%s:%d", token, expiry)
	fmt.Printf("DEBUG registro: sessionData = %s, username = %s\n", sessionData, req.Username)
	if err := s.db.Put("sessions", []byte(req.Username), []byte(sessionData)); err != nil {
		fmt.Println("DEBUG registro: Error al crear sesión:", err)
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	if req.Role == "admin" {
		addLogEntry(fmt.Sprintf("Usuario %s se registró como administrador", req.Username))
		fmt.Println("DEBUG registro: Usuario registrado como admin")
		return api.Response{
			Success: true,
			Message: "Usuario registrado y logueado como administrador",
			Token:   token,
			Data:    "admin",
		}
	} else {
		addLogEntry(fmt.Sprintf("Usuario %s se registró con rol %s", req.Username, req.Role))
	}

	fmt.Println("DEBUG registro: Usuario registrado con rol =", req.Role)
	return api.Response{
		Success: true,
		Message: "Usuario registrado y logueado",
		Token:   token,
	}
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
	if len(data) < 5 {
		return api.Response{Success: false, Message: "Datos de autenticación corruptos"}
	}
	hash, _ := base64.StdEncoding.DecodeString(data["hash"])
	salt, _ := base64.StdEncoding.DecodeString(data["salt"])
	fileKey := data["fileKey"]
	nonce, _ := base64.StdEncoding.DecodeString(data["nonce"])
	encryptedData := data["encryptedData"]
	role := data["role"]
	if role == "" {
		return api.Response{Success: false, Message: "Error al obtener rol del usuario"}
	}

	// Verificar contraseña
	if !verifyPassword(req.Password, []byte(hash), []byte(salt)) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}
	addLogEntry(fmt.Sprintf("Usuario %s inició sesión", req.Username))

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
	// Procesar la solicitud (crear, editar o eliminar)
	var record struct {
		Diagnostico   string `json:"diagnostico"`
		Tratamiento   string `json:"tratamiento"`
		Observaciones string `json:"observaciones"`
		ID            string `json:"id,omitempty"`
	}
	if err := json.Unmarshal([]byte(req.Data), &record); err != nil {
		return api.Response{Success: false, Message: "error al procesar los datos del expediente"}
	}

	// Obtener expedientes actuales del usuario destino
	var records []map[string]string
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err == nil && len(rawData) > 0 {
		// Decodificar y descifrar si es necesario, aquí suponemos JSON plano
		if err := json.Unmarshal(rawData, &records); err != nil {
			records = []map[string]string{}
		}
	} else {
		records = []map[string]string{}
	}

	switch req.Action {
	case api.ActionCreateRecord:
		// Obtener el siguiente ID global
		id, err := s.getNextGlobalExpedienteID()
		if err != nil {
			return api.Response{Success: false, Message: "error al obtener el ID global de expediente"}
		}
		// Añadir el ID al expediente
		record.ID = id

		// Convertir a map para mantener compatibilidad con el slice
		recMap := map[string]string{
			"id":            record.ID,
			"diagnostico":   record.Diagnostico,
			"tratamiento":   record.Tratamiento,
			"observaciones": record.Observaciones,
		}
		records = append(records, recMap)

		// Guardar el slice actualizado
		dataActualizada, _ := json.Marshal(records)
		if err := s.db.Put("userdata", []byte(req.Username), dataActualizada); err != nil {
			return api.Response{Success: false, Message: "error al guardar el expediente"}
		}
		return api.Response{Success: true, Message: "Expediente creado correctamente"}
		// ...otros casos para editar/eliminar...
	}
	return api.Response{Success: false, Message: "acción no soportada"}
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
	addLogEntry(fmt.Sprintf("Usuario %s eliminó al usuario %s", req.Username, req.Data))

	return api.Response{Success: true, Message: "Usuario eliminado correctamente"}
}

func (s *server) manageAccounts(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		fmt.Println("DEBUG manageAccounts: Faltan credenciales")
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		fmt.Println("DEBUG manageAccounts: Token inválido")
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Determinar el usuario objetivo (para admin)
	targetUser := req.Username
	if req.Data != "" {
		targetUser = req.Data
	}
	fmt.Println("DEBUG manageAccounts: Buscando usuario:", targetUser)

	// Mostrar todas las claves del bucket auth
	fmt.Println("DEBUG manageAccounts: Claves en bucket 'auth':")
	_ = s.db.ForEach("auth", func(key, _ []byte) error {
		fmt.Println(" -", string(key))
		return nil
	})

	// Obtener datos del usuario
	authData, err := s.db.Get("auth", []byte(targetUser))
	if err != nil {
		fmt.Printf("DEBUG manageAccounts: No se encontró el usuario '%s'. Error: %v\n", targetUser, err)
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}
	fmt.Printf("DEBUG manageAccounts: authData para '%s': %s\n", targetUser, string(authData))

	// Retornar los datos al cliente
	return api.Response{Success: true, Message: "Datos de la cuenta obtenidos", Data: string(authData)}
}

func (s *server) assignRoles(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	var payload struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal([]byte(req.Data), &payload); err != nil {
		fmt.Println("DEBUG assignRoles: Error al parsear payload:", err)
		return api.Response{Success: false, Message: "Datos de entrada inválidos"}
	}
	if payload.Username == "" || payload.Role == "" {
		return api.Response{Success: false, Message: "Faltan campos obligatorios"}
	}

	fmt.Println("DEBUG assignRoles: Cambio de rol solicitado para", payload.Username, "->", payload.Role)

	// Obtener datos del usuario
	authData, err := s.db.Get("auth", []byte(payload.Username))
	if err != nil {
		fmt.Println("DEBUG assignRoles: Usuario no encontrado en auth:", payload.Username)
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	var auth map[string]string
	if err := json.Unmarshal(authData, &auth); err != nil {
		fmt.Println("DEBUG assignRoles: authData corrupto:", err)
		return api.Response{Success: false, Message: "Datos de autenticación corruptos"}
	}

	oldRole := auth["role"]
	fmt.Println("DEBUG assignRoles: Rol actual:", oldRole)

	oldKey := deriveKey(payload.Username, oldRole)
	newKey := deriveKey(payload.Username, payload.Role)

	// Descifrar encryptedData con la clave antigua
	encrypted := auth["encryptedData"]
	decrypted := encryption.DescifrarString(encrypted, oldKey, oldKey[:16])
	if err != nil {
		fmt.Println("DEBUG assignRoles: No se pudo descifrar encryptedData con la clave antigua:", err)
		return api.Response{Success: false, Message: "Error al descifrar los datos del usuario"}
	}
	fmt.Println("DEBUG assignRoles: Datos descifrados:", decrypted)

	// Recifrar con la nueva clave
	encryptedNew, err := encryption.CifrarString(decrypted, newKey, newKey[:16])
	if err != nil {
		fmt.Println("DEBUG assignRoles: Error al recifrar con la nueva clave:", err)
		return api.Response{Success: false, Message: "Error al recifrar los datos del usuario"}
	}

	// Actualizar auth
	auth["role"] = payload.Role
	auth["encryptedData"] = encryptedNew

	updatedAuth, _ := json.Marshal(auth)
	if err := s.db.Put("auth", []byte(payload.Username), updatedAuth); err != nil {
		fmt.Println("DEBUG assignRoles: Error al guardar auth actualizado:", err)
		return api.Response{Success: false, Message: "Error al actualizar los datos del usuario"}
	}

	addLogEntry(fmt.Sprintf("Usuario %s cambió el rol de %s a %s", req.Username, payload.Username, payload.Role))

	fmt.Println("DEBUG assignRoles: Rol y datos cifrados actualizados correctamente")
	return api.Response{Success: true, Message: "Rol actualizado correctamente"}

}

// deriveKey genera una clave a partir del username y role usando SHA-256.
func deriveKey(username, role string) []byte {
	return encryption.ObtenerSHA256(username + ":" + role)
}

func (s *server) viewStatsAndLogs(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	var totalUsers, adminCount, medicCount, patientCount, recordCount int
	var rawUsers strings.Builder

	// Contar usuarios y roles y mostrar cómo están guardados
	err := s.db.ForEach("auth", func(key, value []byte) error {
		totalUsers++
		// Mostrar el usuario y su valor crudo
		rawUsers.WriteString(fmt.Sprintf("Usuario: %s\nValor guardado: %s\n\n", string(key), string(value)))
		// Si los datos están en formato JSON (nuevo sistema)
		var auth map[string]interface{}
		if err := json.Unmarshal(value, &auth); err == nil {
			role, _ := auth["role"].(string)
			switch role {
			case "admin":
				adminCount++
			case "medic":
				medicCount++
			case "patient":
				patientCount++
			}
		} else {
			authStr := string(value)
			// Soportar formato admin{...}
			idx := strings.Index(authStr, "{")
			if idx > 0 {
				role := strings.TrimSpace(authStr[:idx])
				switch role {
				case "admin":
					adminCount++
				case "medic":
					medicCount++
				case "patient":
					patientCount++
				}
			} else {
				// Soportar formato hash:salt:role
				parts := strings.Split(authStr, ":")
				if len(parts) == 3 {
					role := parts[2]
					switch role {
					case "admin":
						adminCount++
					case "medic":
						medicCount++
					case "patient":
						patientCount++
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al contar usuarios"}
	}

	// Contar expedientes médicos
	err = s.db.ForEach("userdata", func(key, value []byte) error {
		var records []api.Historial
		if err := json.Unmarshal(value, &records); err == nil {
			recordCount += len(records)
		}
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al contar expedientes"}
	}

	stats := fmt.Sprintf(
		"Usuarios registrados: %d\nAdmins: %d\nMédicos: %d\nPacientes: %d\nExpedientes médicos: %d\n\n--- Usuarios en base de datos ---\n%s",
		totalUsers, adminCount, medicCount, patientCount, recordCount, rawUsers.String(),
	)

	return api.Response{
		Success: true,
		Message: "Estadísticas y logs del sistema",
		Data:    stats,
	}
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

func (s *server) deleteAllUsersAndData(req api.Request) api.Response {
	// Solo permitir a administradores
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	authData, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "No se pudo verificar el rol"}
	}

	fmt.Println("DEBUG deleteAllUsersAndData: authData =", string(authData))
	var role string
	var data map[string]interface{}
	jsonErr := json.Unmarshal(authData, &data)
	fmt.Println("DEBUG deleteAllUsersAndData: json.Unmarshal err =", jsonErr)
	fmt.Println("DEBUG deleteAllUsersAndData: data =", data)
	if jsonErr == nil {
		role, _ = data["role"].(string)
		fmt.Println("DEBUG deleteAllUsersAndData: role (json) =", role)
	} else {
		authStr := string(authData)
		// Soportar formato admin{...}
		idx := strings.Index(authStr, "{")
		if idx > 0 {
			role = strings.TrimSpace(authStr[:idx])
			fmt.Println("DEBUG deleteAllUsersAndData: formato especial, role =", role)
		} else {
			// Soportar formato hash:salt:role
			parts := strings.Split(authStr, ":")
			fmt.Println("DEBUG deleteAllUsersAndData: parts =", parts)
			if len(parts) == 3 {
				role = parts[2]
				fmt.Println("DEBUG deleteAllUsersAndData: role (legacy) =", role)
			} else {
				return api.Response{Success: false, Message: "Error al leer datos de autenticación"}
			}
		}
	}
	if role != "admin" {
		return api.Response{Success: false, Message: "Solo el administrador puede borrar todos los usuarios"}
	}

	// Borrar todos los usuarios y datos de los buckets conocidos
	buckets := []string{"auth", "userdata", "sessions"}
	for _, bucket := range buckets {
		_ = s.db.ForEach(bucket, func(key, _ []byte) error {
			fmt.Printf("DEBUG deleteAllUsersAndData: borrando key=%s del bucket=%s\n", string(key), bucket)
			_ = s.db.Delete(bucket, key)
			return nil
		})
	}
	addLogEntry(fmt.Sprintf("Usuario %s borró TODOS los usuarios y datos", req.Username))

	fmt.Println("DEBUG deleteAllUsersAndData: ¡Todos los usuarios y datos han sido eliminados!")
	return api.Response{Success: true, Message: "¡Todos los usuarios y datos han sido eliminados!"}
}

// Estructura para almacenar logs en memoria (puedes moverla a nivel de servidor si quieres persistencia)
var actionLogs []string

// Función para agregar una entrada al log
func addLogEntry(entry string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	actionLogs = append(actionLogs, fmt.Sprintf("[%s] %s", timestamp, entry))
	// Limita el tamaño del log en memoria (por ejemplo, 100 entradas)
	if len(actionLogs) > 100 {
		actionLogs = actionLogs[len(actionLogs)-100:]
	}
}

// Llama a addLogEntry en los puntos clave de tu código, por ejemplo:
// addLogEntry(fmt.Sprintf("Usuario %s se registró con rol %s", req.Username, req.Role))
// addLogEntry(fmt.Sprintf("Usuario %s inició sesión", req.Username))
// addLogEntry(fmt.Sprintf("Usuario %s cambió el rol de %s a %s", req.Username, payload.Username, payload.Role))
// addLogEntry(fmt.Sprintf("Usuario %s actualizó sus datos", req.Username))

// Acción: Mostrar logs recientes
func (s *server) viewLogs(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	// Solo admin puede ver logs
	authData, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "No se pudo verificar el rol"}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(authData, &data); err != nil {
		return api.Response{Success: false, Message: "Error al leer datos de autenticación"}
	}
	role, _ := data["role"].(string)
	if role != "admin" {
		return api.Response{Success: false, Message: "Solo el administrador puede ver los logs"}
	}

	// Devuelve los logs más recientes
	logs := strings.Join(actionLogs, "\n")
	return api.Response{
		Success: true,
		Message: "Logs recientes del sistema",
		Data:    logs,
	}
}

func (s *server) updatePersonalData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Data == "" {
		return api.Response{Success: false, Message: "No se recibieron datos"}
	}

	// Guardar los datos personales actualizados en el bucket 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos personales"}
	}
	addLogEntry(fmt.Sprintf("Usuario %s actualizó sus datos personales", req.Username))
	return api.Response{Success: true, Message: "Datos personales actualizados correctamente"}
}

func (s *server) listUsers(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	type userInfo struct {
		Username  string `json:"username"`
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}

	var users []userInfo

	// Recorrer todos los usuarios en el bucket "auth"
	err := s.db.ForEach("auth", func(key, value []byte) error {
		username := string(key)
		var auth map[string]interface{}
		if err := json.Unmarshal(value, &auth); err == nil {
			role, _ := auth["role"].(string)
			// Obtener datos personales del bucket userdata
			var nombre, apellidos string
			if raw, err := s.db.Get("userdata", key); err == nil && len(raw) > 0 {
				fmt.Printf("DEBUG userdata raw para %s: %s\n", username, string(raw)) // <-- Añade esta línea
				var datos map[string]interface{}
				if err := json.Unmarshal(raw, &datos); err == nil {
					fmt.Printf("DEBUG json.Unmarshal ok para %s: %+v\n", username, datos) // <-- Y esta
					nombre, _ = datos["nombre"].(string)
					apellidos, _ = datos["apellidos"].(string)
				} else {
					fmt.Printf("DEBUG json.Unmarshal ERROR para %s: %v\n", username, err) // <-- Y esta
				}
			} else {
				fmt.Printf("DEBUG NO userdata para %s o vacío\n", username) // <-- Y esta
			}
			fmt.Printf("DEBUG listUsers: username=%s, nombre=%s, apellidos=%s, role=%s\n", username, nombre, apellidos, role)

			users = append(users, userInfo{
				Username:  username,
				Nombre:    nombre,
				Apellidos: apellidos,
				Role:      role,
			})
		}
		return nil
	})
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener la lista de usuarios"}
	}

	// Serializar y devolver
	data, _ := json.Marshal(users)
	return api.Response{
		Success: true,
		Message: "Lista de usuarios obtenida",
		Data:    string(data),
	}
}

// Obtiene y actualiza el contador global de expedientes
func (s *server) getNextGlobalExpedienteID() (string, error) {
	const counterKey = "expediente_counter"

	val, err := s.db.Get("global", []byte(counterKey))
	var nextID int
	if err == nil && len(val) > 0 {
		nextID, _ = strconv.Atoi(string(val))
	}
	nextID++ // Siguiente ID

	// Guardar el nuevo valor (esto creará el bucket si tu store lo soporta)
	if err := s.db.Put("global", []byte(counterKey), []byte(strconv.Itoa(nextID))); err != nil {
		return "", fmt.Errorf("no se pudo guardar el contador global de expedientes: %v", err)
	}
	return strconv.Itoa(nextID), nil
}
