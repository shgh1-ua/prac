// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"prac/pkg/api"
	"prac/pkg/encryption"
	"prac/pkg/ui"

	"crypto/aes"
	"crypto/tls"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Si NO hay usuario logueado, se muestran ciertas opciones;
// si SÍ hay usuario logueado, se muestran otras.
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario logueado, si lo hubiera.
		var title string
		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		fmt.Println("Debugging en runLoop :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)
		if c.currentUser == "" { // Hay que mapear la opción elegida según si está logueado o no.
			fmt.Println("Debugging en runLoop(if) :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)
			title = "Menú"
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
			// Mostramos el menú y obtenemos la elección del usuario.
			choice := ui.PrintMenu(title, options)
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else { //Hay que ver el rol del usuario para saber qué opciones se les va a mostrar
			// adminMenu se declara de nuevo antes o despues no recuerdo cuando  -----> recordar quitarlo que con ponerlo en runLoop basta
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
			res := c.sendRequest(api.Request{ //ManageAccounts obtiene los datos de currentUser
				Action:   api.ActionManageAccounts,
				Username: c.currentUser,
				Token:    c.authToken,
			})
			fmt.Println("Datos que hay del usuario: c.authToken: ", c.authToken, " c.currentUser ", c.currentUser, " c.log ", c.log)
			// fmt.Println("Datos obtenidos del servidor: ", res)

			////Esta serie if-else se puede hacer con un for iterando sobre array de roles---->(eficiencia de codigo?)
			if strings.Contains(res.Data, "admin") {
				c.adminMenu()
			} else if strings.Contains(res.Data, "medic") {
				c.medicMenu()
			} else if strings.Contains(res.Data, "patient") {
				c.patientMenu()
			}
		}
		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) patientMenu() {
	var title string
	var options []string //No sé si es meterlo como parámetro en la funcion en vez de declararla otra vez (PREGUNTAR AL PROFESOR)
	// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
	title = fmt.Sprintf("Menú de paciente (%s)", c.currentUser)
	options = []string{
		"Ver expedientes asociados",
		"Actualizar datos personales",
		"Cerrar sesión",
	}

	choice := ui.PrintMenu(title, options)
	fmt.Println("Debugging en runLoop(else) :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)
	// Caso logueado
	switch choice {
	case 1:
		c.fetchData()
	case 2:
		c.updatePersonalData()
	case 3:
		c.logoutUser()
	default:
		fmt.Println("Opción no válida, Intente de nuevo")
	}
}

func (c *client) medicMenu() {
	var title string
	var options []string //No sé si es meterlo como parámetro en la funcion en vez de declararla otra vez (PREGUNTAR AL PROFESOR)
	// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
	title = fmt.Sprintf("Menú de médico (%s)", c.currentUser)
	options = []string{
		"Ver lista de pacientes",    //1
		"Ver todos los expedientes", //2
		"Modificar expedientes",     //3
		"Cerrar sesión",             //4
	}

	choice := ui.PrintMenu(title, options)
	fmt.Println("Debugging en runLoop(else) :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)
	// Caso logueado
	switch choice {
	case 1:
		c.listPatients()
	case 2:
		c.viewAllRecords()
	case 3:
		c.manageRecords()
	case 4:
		c.logoutUser()
	default:
		fmt.Println("Opción no válida, intente de nuevo")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
// ...existing code...

// Añadimos un nuevo menú para el administrador.
func (c *client) adminMenu() {
	ui.ClearScreen()
	title := fmt.Sprintf("Menú de Administrador (%s)", c.currentUser)
	options := []string{
		"Ver lista de usuarios",                            //1                  //2
		"Eliminar cualquier usuario",                       //2                  //3
		"Asignar o cambiar roles de usuario",               //3
		"Acceder a estadísticas",                           //4
		"Acceder a logs del sistema",                       //5
		"Borrar TODOS los usuarios y datos (solo pruebas)", //6
		"Cerrar sesión",                                    //7
	}

	choice := ui.PrintMenu(title, options)

	switch choice {
	case 1:
		c.listUsers()
	case 2:
		c.deleteUser()
	case 3:
		c.assignRoles()
	case 4:
		c.viewStatsAndLogs()
	case 5:
		c.viewLogs()
	case 6:
		c.deleteAllUsersAndData()
	case 7:
		c.logoutUser()
	default:
		fmt.Println("Opción no existente, Intente de nuevo")
	}
}

// Modificamos el registro para incluir el rol.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	//Pedimos datos personales (son los que se van a cifrar y los que debemos mantener resguardados)
	name := ui.ReadInput("Nombre")
	surnames := ui.ReadInput("Apellidos")
	email := ui.ReadInput("E-mail") //Importante añadir comprobación de datos introducidos
	age := ui.ReadInt("Edad")
	usuario := api.User{
		Nombre:    name,
		Apellidos: surnames,
		Email:     email,
		Edad:      age,
	}
	data, _ := json.Marshal(usuario)

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadPassword("Contraseña")
	role := ui.ReadInput("Rol (admin, doctor, paciente)")

	//Normalizamos el rol del usuario para que se guarde de forma uniforme en la base de datos
	if strings.Contains(role, "admin") {
		role = "admin"
	} else if strings.Contains(role, "medic") || strings.Contains(role, "doc") {
		role = "medic"
	} else if strings.Contains(role, "pac") || strings.Contains(role, "pat") {
		role = "patient"
	} else {
		fmt.Println("El rol introducido no pudo ser identificado correctamente, pruebe evitando introducir tildes o cambiando de rol")
		return
	}

	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
		Data:     string(data),
		Role:     role,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		// Guardamos el token y el usuario actual
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Debugging en registerUser :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)

		// Si el rol es admin, mostramos el menú de administrador
		// if res.Data == "admin" {
		// 	fmt.Println("Iniciando sesión como administrador...")
		// 	ui.Pause("Pulsa [Enter] para continuar...")
		// 	c.adminMenu()
		// }
	}
}

// Ver todos los expedientes médicos
func (c *client) viewAllRecords() {
	ui.ClearScreen()
	fmt.Println("** Ver todos los expedientes médicos **")

	res := c.sendRequest(api.Request{
		Action:   api.ActionViewAllRecords,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("Expedientes médicos:")
		fmt.Println(res.Data)
	}
}

func (c *client) createRecord() {
	// Crear expediente
	username := ui.ReadInput("¿A qué usuario (paciente) quieres añadirle un expediente médico? (Introduce el nombre de usuario)")

	// Consultar nombre y apellidos del usuario
	res := c.sendRequest(api.Request{
		Action:   api.ActionManageAccounts,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})

	if !res.Success {
		fmt.Println("No se pudo obtener la cuenta:", res.Message)
		return
	}

	var user struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal([]byte(res.Data), &user); err != nil {
		fmt.Println("Error al procesar los datos del usuario:", err)
		return
	}
	if user.Role != "patient" {
		fmt.Println("Solo se pueden añadir expedientes a usuarios con rol 'patient'.")
		return
	}

	fmt.Printf("Añadir expediente para usuario %s (%s %s)\n", username, user.Nombre, user.Apellidos)
	diagnostico := ui.ReadInput("Añada un diagnóstico")
	tratamiento := ui.ReadInput("Añada un tratamiento")
	observaciones := ui.ReadInput("Añada observaciones")

	record := map[string]string{
		"diagnostico":   diagnostico,
		"tratamiento":   tratamiento,
		"observaciones": observaciones,
	}
	data, _ := json.Marshal(record)

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionCreateRecord,
		Username: username,
		Token:    c.authToken,
		Data:     string(data),
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}

func (c *client) editRecord() {
	// Modificar expediente
	username := ui.ReadInput("¿De qué usuario quieres modificar un expediente? (Introduce el nombre de usuario)")

	// Consultar nombre, apellidos y expedientes del usuario
	res := c.sendRequest(api.Request{
		Action:   api.ActionManageAccounts,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})
	if !res.Success {
		fmt.Println("No se pudo obtener la cuenta:", res.Message)
		return
	}
	var user struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal([]byte(res.Data), &user); err != nil {
		fmt.Println("Error al procesar los datos del usuario:", err)
		return
	}

	// Obtener expedientes del usuario
	resExp := c.sendRequest(api.Request{
		Action:   api.ActionListRecordIDs,
		Username: username,
		Token:    c.authToken,
	})
	if !resExp.Success {
		fmt.Println("No se pudieron obtener los expedientes:", resExp.Message)
		return
	}
	var ids []string
	if err := json.Unmarshal([]byte(resExp.Data), &ids); err != nil {
		fmt.Println("Error al procesar los IDs de expedientes:", err)
		return
	}
	if len(ids) == 0 {
		fmt.Println("Este usuario no tiene expedientes.")
		return
	}
	fmt.Printf("El usuario %s (%s %s) tiene estos expedientes: %v\n", username, user.Nombre, user.Apellidos, ids)
	id := ui.ReadInput("¿Cuál deseas modificar? Introduce el número de expediente")

	// Pedir nuevos datos
	diagnostico := ui.ReadInput("Nuevo diagnóstico")
	tratamiento := ui.ReadInput("Nuevo tratamiento")
	observaciones := ui.ReadInput("Nuevas observaciones")

	record := map[string]string{
		"id":            id,
		"diagnostico":   diagnostico,
		"tratamiento":   tratamiento,
		"observaciones": observaciones,
	}
	data, _ := json.Marshal(record)

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionEditRecord,
		Username: username,
		Token:    c.authToken,
		Data:     string(data),
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}

func (c *client) deleteRecord() {
	// Eliminar expediente
	username := ui.ReadInput("¿De qué usuario quieres eliminar un expediente? (Introduce el nombre de usuario)")

	// Consultar nombre, apellidos y expedientes del usuario
	res := c.sendRequest(api.Request{
		Action:   api.ActionManageAccounts,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})
	if !res.Success {
		fmt.Println("No se pudo obtener la cuenta:", res.Message)
		return
	}
	var user struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal([]byte(res.Data), &user); err != nil {
		fmt.Println("Error al procesar los datos del usuario:", err)
		return
	}

	// Obtener expedientes del usuario
	resExp := c.sendRequest(api.Request{
		Action:   api.ActionListRecordIDs,
		Username: username,
		Token:    c.authToken,
	})
	if !resExp.Success {
		fmt.Println("No se pudieron obtener los expedientes:", resExp.Message)
		return
	}
	var ids []string
	if err := json.Unmarshal([]byte(resExp.Data), &ids); err != nil {
		fmt.Println("Error al procesar los IDs de expedientes:", err)
		return
	}
	if len(ids) == 0 {
		fmt.Println("Este usuario no tiene expedientes.")
		return
	}
	fmt.Printf("El usuario %s (%s %s) tiene estos expedientes: %v\n", username, user.Nombre, user.Apellidos, ids)
	id := ui.ReadInput("¿Qué expediente deseas eliminar? Introduce el número de expediente")

	confirm := ui.Confirm(fmt.Sprintf("¿Estás seguro de que deseas eliminar el expediente %s de %s (%s %s)?", id, username, user.Nombre, user.Apellidos))
	if !confirm {
		fmt.Println("Operación cancelada.")
		return
	}

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionDeleteRecord,
		Username: username,
		Token:    c.authToken,
		Data:     id,
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}

// Crear, editar o eliminar expedientes
func (c *client) manageRecords() {
	ui.ClearScreen()
	fmt.Println("** Crear, editar o eliminar expedientes **")

	options := []string{"Crear expediente", "Editar expediente", "Eliminar expediente", "Volver"}
	choice := ui.PrintMenu("Gestión de expedientes", options)

	switch choice {
	case 1:
		c.createRecord()
	case 2:
		c.editRecord()
	case 3:
		c.deleteRecord()
	}
}

// Eliminar cualquier usuario
func (c *client) deleteUser() {
	ui.ClearScreen()
	fmt.Println("** Eliminar usuario **")

	username := ui.ReadInput("Nombre de usuario a eliminar")
	res := c.sendRequest(api.Request{
		Action:   api.ActionDeleteUser,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// Ver, editar o eliminar cualquier cuenta
func (c *client) manageAccounts() {
	ui.ClearScreen()
	fmt.Println("** Ver, editar o eliminar cuentas **")

	options := []string{"Ver cuenta", "Editar cuenta", "Eliminar cuenta", "Volver"}
	choice := ui.PrintMenu("Gestión de cuentas", options)

	switch choice {
	case 1:
		// Ver cuenta
		username := ui.ReadInput("Nombre de usuario a consultar")
		res := c.sendRequest(api.Request{
			Action:   api.ActionManageAccounts,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     username,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)
		if res.Success {
			fmt.Println("Datos de la cuenta:")
			fmt.Println(res.Data)
		}

	case 2:
		// Editar cuenta
		username := ui.ReadInput("Nombre de usuario a editar")
		newRole := ui.ReadInput("Nuevo rol (admin, doctor, paciente)")

		data := map[string]string{
			"username": username,
			"role":     newRole,
		}
		dataJSON, _ := json.Marshal(data)

		res := c.sendRequest(api.Request{
			Action:   api.ActionEditAccount,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     string(dataJSON),
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)

	case 3:
		// Eliminar cuenta
		username := ui.ReadInput("Nombre de usuario a eliminar")
		res := c.sendRequest(api.Request{
			Action:   api.ActionDeleteAccount,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     username,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)
	}
}

func (c *client) getRole() {
	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		// Comprobar si el cliente está enviando datos cifrados
		if string(res.Data) == "" {
			fmt.Println("No se recibieron datos en el cliente")
		}
		fmt.Println("Datos crudos recibidos: ", res.Data)
		// Decodificar el string base64 recibido
		datosCifrados, err := base64.StdEncoding.DecodeString(string(res.Data))
		fmt.Println("Datos cifrados: ", datosCifrados)
		// Definir la clave y el vector de inicialización (IV) que usaste en el cliente
		key := encryption.ObtenerSHA256("Clave")
		iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize] // aes.BlockSize es de 16 bytes

		// Descifrar el contenido cifrado
		textoEnClaroDescifrado, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		if err != nil {
			fmt.Println("Error al descifrar los datos en el cliente: ", err)
		}
		fmt.Println("Datos descifrados: ", textoEnClaroDescifrado)

		// // Procesar el historial médico que llega descifrado -------------------- IMPLEMENTAR - IMPORTANTE PARA EL WAILS
		// var historial Medico
		// if err := json.Unmarshal([]byte(textoEnClaroDescifrado), &historial); err != nil {
		// 	return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
		// }

		//Por ahora usaremos "Clave" como key y <inicializar> como vector de inicialización (similar a la sal) para facilitar las cosas.
		//En casos reales debe ser diferente para cada usuario y debe ser el mismo al cifrar y descifrar ----> tomar en cuenta luego al modificar

		//-------------------------------
		fmt.Println("Tus datos:", textoEnClaroDescifrado) //Por ahora sale en formato JSON mientras no se implemente una función de procesamiento
	}
}

// Asignar o cambiar roles de usuario
func (c *client) assignRoles() {
	ui.ClearScreen()
	fmt.Println("** Asignar o cambiar roles de usuario **")

	username := ui.ReadInput("Nombre de usuario a modificar")

	// 1. Consultar el rol actual
	res := c.sendRequest(api.Request{
		Action:   api.ActionManageAccounts,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})

	if !res.Success {
		fmt.Println("No se pudo obtener la cuenta:", res.Message)
		return
	}

	// Intentar extraer el rol actual del JSON recibido
	var user map[string]interface{}
	rolActual := ""
	if err := json.Unmarshal([]byte(res.Data), &user); err == nil {
		if r, ok := user["role"].(string); ok {
			rolActual = r
		}
	}
	fmt.Printf("El rol actual de %s es: %s\n", username, rolActual)

	// 2. Preguntar si quiere cambiar el rol
	if !ui.Confirm("¿Quieres cambiar el rol de este usuario?") {
		fmt.Println("Operación cancelada.")
		return
	}

	// 3. Pedir el nuevo rol
	newRole := ui.ReadInput("Nuevo rol (admin, medic, patient)")

	// 4. Enviar la petición al servidor
	data := map[string]string{
		"username": username,
		"role":     newRole,
	}
	dataJSON, _ := json.Marshal(data)

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionAssignRole,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     string(dataJSON),
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}

// Acceder a estadísticas y logs del sistema
func (c *client) viewStatsAndLogs() {
	ui.ClearScreen()
	fmt.Println("** Acceder a estadísticas y logs del sistema **")

	res := c.sendRequest(api.Request{
		Action:   api.ActionViewStatsAndLogs,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("Estadísticas y logs:")
		fmt.Println(res.Data)
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadPassword("Contraseña")

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		// Guardamos el token y el usuario actual
		c.currentUser = username
		c.authToken = res.Token
		// fmt.Println("Debugging en loginUser :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)

		println("Res.Data: ", res.Data)
		// Si el rol es admin, mostramos el menú de administrador
		switch res.Data {
		case "admin":
			fmt.Println("Iniciando sesión como administrador...")
			ui.Pause("Pulsa [Enter] para continuar...")
			c.adminMenu()
		case "medic":
			fmt.Println("Iniciando sesión como médico...")
			ui.Pause("Pulsa [Enter] para continuar...")
			c.medicMenu()
		case "patient":
			fmt.Println("Iniciando sesión como paciente...")
			ui.Pause("Pulsa [Enter] para continuar...")
			c.patientMenu()
		default:
			fmt.Println("Hubo un problema iniciando sesión")
		}
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	fmt.Println("Debugging en fetchData :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		// Comprobar si el cliente está enviando datos cifrados
		if string(res.Data) == "" {
			fmt.Println("No se recibieron datos en el cliente")
		}
		fmt.Println("Datos crudos recibidos: ", res.Data)
		// // Decodificar el string base64 recibido
		// datosCifrados, err := base64.StdEncoding.DecodeString(string(res.Data))
		// fmt.Println("Datos cifrados: ", datosCifrados)
		// // Definir la clave y el vector de inicialización (IV) que usaste en el cliente
		// key := encryption.ObtenerSHA256("Clave")
		// iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize] // aes.BlockSize es de 16 bytes

		// // Descifrar el contenido cifrado
		// textoEnClaroDescifrado, err := encryption.DescifrarBytes(datosCifrados, key, iv)
		// if err != nil {
		// 	fmt.Println("Error al descifrar los datos en el cliente: ", err)
		// }
		// fmt.Println("Datos descifrados: ", textoEnClaroDescifrado)

		// // Procesar el historial médico que llega descifrado -------------------- IMPLEMENTAR - IMPORTANTE PARA EL WAILS
		// var historial Medico
		// if err := json.Unmarshal([]byte(textoEnClaroDescifrado), &historial); err != nil {
		// 	return api.Response{Success: false, Message: "Error al procesar los datos del historial"}
		// }

		//Por ahora usaremos "Clave" como key y <inicializar> como vector de inicialización (similar a la sal) para facilitar las cosas.
		//En casos reales debe ser diferente para cada usuario y debe ser el mismo al cifrar y descifrar ----> tomar en cuenta luego al modificar

		//-------------------------------
		// fmt.Println("Tus datos:", textoEnClaroDescifrado) //Por ahora sale en formato JSON mientras no se implemente una función de procesamiento
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// //Leeremos el archivo JSON serializado
	// p := Persona{
	// 	Nombre: "Sebastián",
	// 	Edad:   25,
	// 	Email:  "sebastian@example.com",
	// }

	// // Imprimir JSON como string
	// fmt.Println(string(jsonData))

	// Leemos la nueva Data
	// newData := ui.ReadInput("Introduce el contenido del historial que desees almacenar")
	fmt.Println("Introduce el contenido del nuevo historial médico que desees almacenar:")
	nombre := ui.ReadInput("Nombre")
	// edad := ui.ReadInt("Edad")
	diagnostico := ui.ReadInput("Diagnostico")
	tratamiento := ui.ReadInput("Tratamiento")

	historial := api.Historial{
		Nombre:      nombre,
		Diagnostico: diagnostico,
		Tratamiento: tratamiento,
	}

	newData, err := json.Marshal(historial)
	if err != nil { // manejar error
		fmt.Println("Error al serializar los datos", err)
		return
	}

	//Ciframos antes de mandar al servidor. Lo hacemos suponiendo que el servidor no es de confiar por sea cual fuere la razón (administrador poco confiable, datos comprometidos, uso de http, etc.)
	key := encryption.ObtenerSHA256("Clave")
	iv := encryption.ObtenerSHA256("<inicializar>")[:aes.BlockSize]

	textoEnClaro := string(newData)
	/*Meteremos los datos cifrados en un archivo .enc porque:
	✅ Ventajas:
		- Modularidad: puedes inspeccionar, mover, hacer backup o gestionar esos archivos fácilmente.
		- Escalabilidad: ideal si cada usuario tiene su propio archivo cifrado (ej: historial_usuario123.zip.enc).
		- Interoperabilidad: otros procesos (scripts, servicios) pueden usar los archivos sin tocar el código del programa.
		- Manejo eficiente de grandes volúmenes de datos: archivos son más fáciles de manejar que strings gigantes.
	❌ Desventajas:
		- Es más lento (I/O con disco).
		- Requiere limpieza de archivos temporales para evitar residuos.
		- En sistemas distribuidos (como web APIs), debes transmitirlos con cuidado (base64, MIME types, etc.).
	*/
	//----------CIFRADO--------------
	datosCifrados, err := encryption.CifrarString(textoEnClaro, key, iv)
	if err != nil {
		fmt.Println("Error al cifrar Datos:", err)
		return
	}

	//----------DESCIFRADO-----------
	// textoEnClaroDescifrado := encryption.DescifrarArchivoEnString(nombreArchivoDatos, key, iv)
	// //----------Comprobación-----------
	// if textoEnClaroDescifrado == textoEnClaro {
	// 	fmt.Println("Cifrado realizado correctamente")
	// } else {
	// 	fmt.Println("Algo ha fallado con el cifrado")
	// }

	// Enviar el contenido cifrado
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     datosCifrados,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) updateDataSinCifrar() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	// newData := ui.ReadInput("Introduce el contenido del historial que desees almacenar")
	fmt.Println("Introduce el contenido del nuevo historial médico que desees almacenar:")
	nombre := ui.ReadInput("Nombre")
	// edad := ui.ReadInt("Edad")
	diagnostico := ui.ReadInput("Diagnostico")
	tratamiento := ui.ReadInput("Tratamiento")

	historial := api.Historial{
		Nombre:      nombre,
		Diagnostico: diagnostico,
		Tratamiento: tratamiento,
	}

	newData, err := json.Marshal(historial)
	if err != nil { // manejar error
		fmt.Println("Error al serializar los datos", err)
		return
	}

	// Enviar el contenido cifrado
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     string(newData),
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
	}
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)

	// Configurar cliente HTTPS que ignora certificados autofirmados
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Post("https://localhost:10443/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}

func (c *client) listRecordIDs() {
	ui.ClearScreen()
	fmt.Println("** Ver IDs de expedientes médicos **")

	// Enviar solicitud al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionListRecordIDs,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	// Mostrar la respuesta
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("Expedientes:", res.Data)
	}
}

func (c *client) listUsers() {
	ui.ClearScreen()
	fmt.Println("** Lista de usuarios existentes **")

	res := c.sendRequest(api.Request{
		Action:   api.ActionListUsers,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		// Esperamos un array de objetos con Username y Role
		var users []struct {
			Username  string `json:"username"`
			Role      string `json:"role"`
			Nombre    string `json:"nombre,omitempty"`
			Apellidos string `json:"apellidos,omitempty"`
		}
		decoded, err := base64.StdEncoding.DecodeString(res.Data)
		if err != nil {
			fmt.Println("Error al decodificar la lista de usuarios:", err)
			return
		}
		if err := json.Unmarshal(decoded, &users); err != nil {
			fmt.Println("Error al procesar la lista de usuarios:", err)
			fmt.Println("DEBUG: res.Data =", res.Data)
			return
		}
		if len(users) == 0 {
			fmt.Println("No hay usuarios registrados.")
			return
		}
		fmt.Printf("%-15s %-10s %-15s %-15s\n", "Usuario", "Rol", "Nombre", "Apellidos")
		fmt.Println(strings.Repeat("-", 66))
		for _, u := range users {
			fmt.Printf("%-15s %-10s %-15s %-15s\n", u.Username, u.Role, u.Nombre, u.Apellidos)
		}
	}
}

func (c *client) deleteAllUsersAndData() {
	ui.ClearScreen()
	fmt.Println("** Borrar TODOS los usuarios y datos (solo para pruebas) **")
	confirm := ui.Confirm("¿Estás seguro de que quieres borrar TODOS los usuarios y datos? (Esta acción es irreversible)")
	if !confirm {
		fmt.Println("Operación cancelada.")
		return
	}

	res := c.sendRequest(api.Request{
		Action:   "deleteAllUsersAndData",
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// Acceder a estadísticas y logs del sistema
func (c *client) viewLogs() {
	ui.ClearScreen()
	fmt.Println("** Acceder a logs del sistema **")

	res := c.sendRequest(api.Request{
		Action:   api.ActionViewLogs,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("=== LOGS DEL SISTEMA ===")
		fmt.Println(res.Data)
	}
}

// updatePersonalData permite al usuario actualizar sus datos personales.
func (c *client) updatePersonalData() {
	ui.ClearScreen()
	fmt.Println("--- Actualizar Datos Personales ---")

	// 1. Obtener datos actuales del usuario
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	if !res.Success {
		fmt.Println("No se pudieron obtener los datos:", res.Message)
		return
	}

	// 2. Mostrar datos actuales
	var datos struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Edad      int    `json:"edad"`
		Email     string `json:"email"`
		Direccion string `json:"direccion,omitempty"`
		Telefono  string `json:"telefono,omitempty"`
	}
	if err := json.Unmarshal([]byte(res.Data), &datos); err != nil {
		fmt.Println("Error al procesar los datos actuales:", err)
		return
	}

	fmt.Println("Tus datos actuales:")
	fmt.Printf("Nombre: %s\n", datos.Nombre)
	fmt.Printf("Apellidos: %s\n", datos.Apellidos)
	fmt.Printf("Edad: %d\n", datos.Edad)
	fmt.Printf("Email: %s\n", datos.Email)
	fmt.Printf("Dirección: %s\n", datos.Direccion)
	fmt.Printf("Teléfono: %s\n", datos.Telefono)

	// 3. Preguntar si desea modificar algo
	if !ui.Confirm("¿Deseas modificar algún dato?") {
		fmt.Println("No se ha realizado ningún cambio.")
		return
	}

	// 4. Preguntar qué campo desea modificar
	fmt.Println("¿Qué campo deseas modificar?")
	fmt.Println("(1) Nombre")
	fmt.Println("(2) Apellidos")
	fmt.Println("(3) Edad")
	fmt.Println("(4) Email")
	fmt.Println("(5) Dirección")
	fmt.Println("(6) Teléfono")
	fmt.Println("(0) Cancelar")

	opcion := ui.ReadInput("Introduce el número de la opción que deseas modificar")
	switch opcion {
	case "1":
		datos.Nombre = ui.ReadInput("Introduce el nuevo nombre")
	case "2":
		datos.Apellidos = ui.ReadInput("Introduce los nuevos apellidos")
	case "3":
		datos.Edad = ui.ReadInt("Introduce la nueva edad")
	case "4":
		datos.Email = ui.ReadInput("Introduce el nuevo email")
	case "5":
		datos.Direccion = ui.ReadInput("Introduce la nueva dirección")
	case "6":
		datos.Telefono = ui.ReadInput("Introduce el nuevo teléfono")
	case "0":
		fmt.Println("Operación cancelada.")
		return
	default:
		fmt.Println("Opción no válida.")
		return
	}

	// 5. Enviar los datos actualizados al servidor
	newData, err := json.Marshal(datos)
	if err != nil {
		fmt.Println("Error al serializar los datos actualizados:", err)
		return
	}

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     string(newData),
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}

func (c *client) listPatients() {
	ui.ClearScreen()
	fmt.Println("** Lista de pacientes **")

	res := c.sendRequest(api.Request{
		Action:   api.ActionListUsers,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	if !res.Success {
		fmt.Println("No se pudo obtener la lista de pacientes:", res.Message)
		return
	}

	// Esperamos un array de objetos con Username, Nombre y Apellidos
	var pacientes []struct {
		Username  string `json:"username"`
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}

	if err := json.Unmarshal([]byte(res.Data), &pacientes); err != nil {
		fmt.Println("Error al procesar la lista de pacientes:", err)
		fmt.Println("DEBUG: res.Data =", res.Data)
		return
	}
	fmt.Println("DEBUG: pacientes =", pacientes)

	// Filtrar solo pacientes y ordenar por nombre de usuario
	var lista []struct {
		Username  string
		Nombre    string
		Apellidos string
	}
	for _, p := range pacientes {
		if p.Role == "patient" {
			lista = append(lista, struct {
				Username  string
				Nombre    string
				Apellidos string
			}{p.Username, p.Nombre, p.Apellidos})
		}
	}
	// Ordenar por Username
	sort.Slice(lista, func(i, j int) bool {
		return lista[i].Username < lista[j].Username
	})

	if len(lista) == 0 {
		fmt.Println("No hay pacientes registrados.")
		return
	}

	fmt.Println("Pacientes registrados:")
	for _, p := range lista {
		fmt.Printf("- Usuario: %s | Nombre: %s | Apellidos: %s\n", p.Username, p.Nombre, p.Apellidos)
	}
}

func (c *client) createMedicalRecord() {
	ui.ClearScreen()
	fmt.Println("** Crear expediente médico **")

	// 1. Preguntar a qué usuario (paciente) se le va a añadir el expediente
	username := ui.ReadInput("¿A qué usuario (paciente) quieres añadirle un expediente médico? (Introduce el nombre de usuario)")

	// 2. Consultar nombre y apellidos del usuario
	res := c.sendRequest(api.Request{
		Action:   api.ActionManageAccounts,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     username,
	})

	if !res.Success {
		fmt.Println("No se pudo obtener la cuenta:", res.Message)
		return
	}

	var user struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal([]byte(res.Data), &user); err != nil {
		fmt.Println("Error al procesar los datos del usuario:", err)
		return
	}
	if user.Role != "patient" {
		fmt.Println("Solo se pueden añadir expedientes a usuarios con rol 'patient'.")
		return
	}

	fmt.Printf("Añadir expediente para usuario %s (%s %s)\n", username, user.Nombre, user.Apellidos)

	// 3. Pedir los datos del expediente
	diagnostico := ui.ReadInput("Añada un diagnóstico")
	tratamiento := ui.ReadInput("Añada un tratamiento")
	observaciones := ui.ReadInput("Añada observaciones")

	// 4. Crear el expediente y enviarlo al servidor
	record := map[string]string{
		"diagnostico":   diagnostico,
		"tratamiento":   tratamiento,
		"observaciones": observaciones,
	}
	data, _ := json.Marshal(record)

	res2 := c.sendRequest(api.Request{
		Action:   api.ActionCreateRecord,
		Username: username, // El usuario al que se le añade el expediente
		Token:    c.authToken,
		Data:     string(data),
	})

	fmt.Println("Éxito:", res2.Success)
	fmt.Println("Mensaje:", res2.Message)
}
