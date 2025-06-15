// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister              = "register"              // Registrar un usuario
	ActionLogin                 = "login"                 // Iniciar sesión
	ActionFetchData             = "fetchData"             // Obtener datos privados
	ActionUpdateData            = "updateData"            // Actualizar datos privados
	ActionLogout                = "logout"                // Cerrar sesión
	ActionViewAllRecords        = "viewAllRecords"        // Ver todos los expedientes médicos
	ActionCreateRecord          = "createRecord"          // Crear expedientes médicos
	ActionEditRecord            = "editRecord"            // Editar expedientes médicos
	ActionDeleteRecord          = "deleteRecord"          // Eliminar expedientes médicos
	ActionDeleteUser            = "deleteUser"            // Eliminar cualquier usuario
	ActionManageAccounts        = "manageAccounts"        // Ver, editar o eliminar cuentas
	ActionEditAccount           = "editAccount"           // Editar cuentas de usuario
	ActionDeleteAccount         = "deleteAccount"         // Eliminar cuentas de usuario
	ActionAssignRole            = "assignRoles"           // Asignar o cambiar roles de usuario
	ActionViewStatsAndLogs      = "viewStatsAndLogs"      // Acceder a estadísticas y logs del sistema
	ActionViewAccount           = "viewAccount"           // Ver cuentas de usuario
	ActionManageRecords         = "manageRecords"         // Ver, editar o eliminar expedientes médicos
	ActionListRecordIDs         = "listRecordIDs"         // Listar IDs de expedientes médicos
	ActionListUsers             = "listUsers"             // Listar usuarios
	ActionDeleteAllUsersAndData = "deleteAllUsersAndData" // Eliminar todos los usuarios y datos
	ActionViewLogs              = "viewLogs"              // Ver logs del sistema
	ActionGetAuthData           = "getAuthData"           // obtiene los datos de autenticación de usuario
	ActionGetMasterKey          = "getMasterKey"          //Obtiene la masterKey
)

type Request struct {
	Action    string `json:"action"`              // Acción a realizar
	Username  string `json:"username"`            // Nombre de usuario
	Password  string `json:"password,omitempty"`  // Contraseña (opcional)
	Token     string `json:"token,omitempty"`     // Token de autenticación (opcional)
	Data      string `json:"data,omitempty"`      // Datos adicionales (opcional)
	Role      string `json:"role,omitempty"`      // Rol del usuario (opcional)
	Email     string `json:"email,omitempty"`     //Email del usuario (opcional)
	OTP       string `json:"otp,omitempty"`       //OTP generado para la autentificación ------> cifrarlo si da tiempo usando las funciones de encrypt.go
	DataBytes []byte `json:"databytes,omitempty"` // Datos adicionales de tipo []byte (opcional)
}

type Response struct {
	Success   bool   `json:"success"`             // Indica si la operación fue exitosa
	Message   string `json:"message"`             // Mensaje de respuesta
	Token     string `json:"token,omitempty"`     // Token de autenticación (opcional)
	Data      string `json:"data,omitempty"`      // Datos adicionales (opcional)
	DataBytes []byte `json:"databytes,omitempty"` // Datos adicionales de tipo []byte (opcional)
}

// Los structs a partir de aquí tendrán en su mayoría omitempty para poder construir la aplicación
type User struct {
	IdPac     int    `json:"idpac,omitempty"`
	Nombre    string `json:"nombre,omitempty"`
	Apellidos string `json:"apellidos,omitempty"`
	Edad      int    `json:"edad,omitempty"`
	Email     string `json:"email,omitempty"`
	Username  string `json:"username,omitempty"`
	Role      string `json:"role,omitempty"` // Rol del usuario (opcional)
}

type Historial struct {
	ID     string `json:"id,omitempty"`
	Nombre string `json:"nombre,omitempty"`
	// Edad        int    `json:"edad,omitempty"`
	Diagnostico   string `json:"diagnostico,omitempty"`
	Tratamiento   string `json:"tratamiento,omitempty"`
	Observaciones string `json:"observaciones,omitempty"`
}

type UserAuth struct {
	Username string            `json:"username"`
	Data     map[string]string `json:"data"`
}
