// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister         = "register"         // Registrar un usuario
	ActionLogin            = "login"            // Iniciar sesión
	ActionFetchData        = "fetchData"        // Obtener datos privados
	ActionUpdateData       = "updateData"       // Actualizar datos privados
	ActionLogout           = "logout"           // Cerrar sesión
	ActionViewAllRecords   = "viewAllRecords"   // Ver todos los expedientes médicos
	ActionCreateRecord     = "createRecord"     // Crear expedientes médicos
	ActionEditRecord       = "editRecord"       // Editar expedientes médicos
	ActionDeleteRecord     = "deleteRecord"     // Eliminar expedientes médicos
	ActionDeleteUser       = "deleteUser"       // Eliminar cualquier usuario
	ActionManageAccounts   = "manageAccounts"   // Ver, editar o eliminar cuentas
	ActionEditAccount      = "editAccount"      // Editar cuentas de usuario
	ActionDeleteAccount    = "deleteAccount"    // Eliminar cuentas de usuario
	ActionAssignRole       = "assignRoles"      // Asignar o cambiar roles de usuario
	ActionViewStatsAndLogs = "viewStatsAndLogs" // Acceder a estadísticas y logs del sistema
	ActionViewAccount      = "viewAccount"      // Ver cuentas de usuario
	ActionManageRecords    = "manageRecords"    // Ver, editar o eliminar expedientes médicos
	ActionListRecordIDs    = "listRecordIDs"    // Listar IDs de expedientes médicos
	ActionListUsers        = "listUsers"        // Listar usuarios

)

type Request struct {
	Action   string `json:"action"`             // Acción a realizar
	Username string `json:"username"`           // Nombre de usuario
	Password string `json:"password,omitempty"` // Contraseña (opcional)
	Token    string `json:"token,omitempty"`    // Token de autenticación (opcional)
	Data     string `json:"data,omitempty"`     // Datos adicionales (opcional)
	Role     string `json:"role,omitempty"`     // Rol del usuario (opcional)
}

type Response struct {
	Success bool   `json:"success"`         // Indica si la operación fue exitosa
	Message string `json:"message"`         // Mensaje de respuesta
	Token   string `json:"token,omitempty"` // Token de autenticación (opcional)
	Data    string `json:"data,omitempty"`  // Datos adicionales (opcional)
}
