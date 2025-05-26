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
			} else {
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
		c.updateDataSinCifrar()
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
		"Ver lista de pacientes",      //1
		"Ver todos los expedientes",   //2
		"Modificar expedientes",       //3
		"Añadir Expediente",           //4
		"Eliminar Expediente",         //5
		"Actualizar datos personales", //6
		"Cerrar sesión",               //7
	}

	choice := ui.PrintMenu(title, options)
	fmt.Println("Debugging en runLoop(else) :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)
	// Caso logueado
	switch choice {
	case 1:
		c.logoutUser()
	case 2:
		c.viewAllRecords()
	case 3:
		c.manageRecords()
	case 4:
		c.updateDataSinCifrar()
	case 5:
		c.logoutUser()
	case 6:
		c.logoutUser()
	case 7:
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
		"Registrar usuarios (médicos, pacientes, administradores)", //1
		"Eliminar cualquier usuario",                               //2
		"Ver, editar o eliminar cualquier cuenta",                  //3
		"Asignar o cambiar roles de usuario",                       //4
		"Acceder a estadísticas y logs del sistema",                //5
		"Cerrar sesión", //6
	}

	choice := ui.PrintMenu(title, options)

	switch choice {
	case 1:
		c.registerUser()
	case 2:
		c.deleteUser()
	case 3:
		c.manageAccounts()
	case 4:
		c.assignRoles()
	case 5:
		c.viewStatsAndLogs()
	case 6:
		c.logoutUser() //Quité un return aquí
	default:
		fmt.Println("Opción no existente, Intente de nuevo")
	}
	ui.Pause("Pulsa [Enter] para continuar...")

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
		if res.Data == "admin" {
			fmt.Println("Iniciando sesión como administrador...")
			ui.Pause("Pulsa [Enter] para continuar...")
			c.adminMenu()
		}
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

// Crear, editar o eliminar expedientes
func (c *client) manageRecords() {
	ui.ClearScreen()
	fmt.Println("** Crear, editar o eliminar expedientes **")

	options := []string{"Crear expediente", "Editar expediente", "Eliminar expediente", "Volver"}
	choice := ui.PrintMenu("Gestión de expedientes", options)

	switch choice {
	case 1:
		// Crear expediente
		nombre := ui.ReadInput("Nombre del paciente")
		// edad := ui.ReadInt("Edad del paciente")
		diagnostico := ui.ReadInput("Diagnóstico")
		tratamiento := ui.ReadInput("Tratamiento")

		historial := api.Historial{
			Nombre:      nombre,
			Diagnostico: diagnostico,
			Tratamiento: tratamiento,
		}

		data, _ := json.Marshal(historial)
		res := c.sendRequest(api.Request{
			Action:   api.ActionCreateRecord,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     string(data),
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)

	case 2:
		// Editar expediente
		id := ui.ReadInput("ID del expediente a editar")
		nombre := ui.ReadInput("Nuevo nombre del paciente")
		diagnostico := ui.ReadInput("Nuevo diagnóstico")
		tratamiento := ui.ReadInput("Nuevo tratamiento")

		historial := api.Historial{
			ID:          id,
			Nombre:      nombre,
			Diagnostico: diagnostico,
			Tratamiento: tratamiento,
		}

		data, _ := json.Marshal(historial)
		res := c.sendRequest(api.Request{
			Action:   api.ActionEditRecord,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     string(data),
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)

	case 3:
		// Eliminar expediente
		id := ui.ReadInput("ID del expediente a eliminar")
		res := c.sendRequest(api.Request{
			Action:   api.ActionDeleteRecord,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     id,
		})

		fmt.Println("Éxito:", res.Success)
		fmt.Println("Mensaje:", res.Message)
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
			Action:   api.ActionViewAccount,
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

	username := ui.ReadInput("Nombre de usuario")
	newRole := ui.ReadInput("Nuevo rol (admin, doctor, paciente)")

	data := map[string]string{
		"username": username,
		"role":     newRole,
	}
	dataJSON, _ := json.Marshal(data)

	res := c.sendRequest(api.Request{
		Action:   api.ActionAssignRole,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     string(dataJSON),
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
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
		fmt.Println("Debugging en loginUser :) ::: c.currentUser = ", c.currentUser, " c.authToken = ", c.authToken)

		// Si el rol es admin, mostramos el menú de administrador
		if res.Data == "admin" {
			fmt.Println("Iniciando sesión como administrador...")
			ui.Pause("Pulsa [Enter] para continuar...")
			c.adminMenu()
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
		fmt.Println("Usuarios registrados:")
		fmt.Println(res.Data)
	}
}
