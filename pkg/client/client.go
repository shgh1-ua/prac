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

	"prac/pkg/api"
	"prac/pkg/encryption"
	"prac/pkg/ui"

	"crypto/aes"
	"crypto/tls"
)

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

type HistorialMedico struct {
	ID          string `json:"id"`
	Nombre      string `json:"nombre"`
	Edad        int    `json:"edad"`
	Diagnostico string `json:"diagnostico"`
	Tratamiento string `json:"tratamiento"`
}

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
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Ver datos",
				"Actualizar datos",
				"Cerrar sesión",
				"Salir",
			}
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
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
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.logoutUser()
			case 4:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
// ...existing code...

// Añadimos un nuevo menú para el administrador.
func (c *client) adminMenu() {
	for {
		ui.ClearScreen()
		title := fmt.Sprintf("Menú de Administrador (%s)", c.currentUser)
		options := []string{
			"Ver todos los expedientes médicos",
			"Crear, editar o eliminar expedientes",
			"Registrar usuarios (médicos, pacientes, administradores)",
			"Eliminar cualquier usuario",
			"Ver, editar o eliminar cualquier cuenta",
			"Asignar o cambiar roles de usuario",
			"Acceder a estadísticas y logs del sistema",
			"Volver al menú principal",
		}

		choice := ui.PrintMenu(title, options)

		switch choice {
		case 1:
			c.viewAllRecords()
		case 2:
			c.manageRecords()
		case 3:
			c.registerUser()
		case 4:
			c.deleteUser()
		case 5:
			c.manageAccounts()
		case 6:
			c.assignRoles()
		case 7:
			c.viewStatsAndLogs()
		case 8:
			return
		}

		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// Modificamos el registro para incluir el rol.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")
	role := ui.ReadInput("Rol (admin, doctor, paciente)")

	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
		Role:     role,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		// Guardamos el token y el usuario actual
		c.currentUser = username
		c.authToken = res.Token

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
		edad := ui.ReadInt("Edad del paciente")
		diagnostico := ui.ReadInput("Diagnóstico")
		tratamiento := ui.ReadInput("Tratamiento")

		historial := HistorialMedico{
			Nombre:      nombre,
			Edad:        edad,
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
		edad := ui.ReadInt("Nueva edad del paciente")
		diagnostico := ui.ReadInput("Nuevo diagnóstico")
		tratamiento := ui.ReadInput("Nuevo tratamiento")

		historial := HistorialMedico{
			ID:          id,
			Nombre:      nombre,
			Edad:        edad,
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

// Registrar usuarios (médicos, pacientes, administradores)
func (c *client) registerUser1() {
	ui.ClearScreen()
	fmt.Println("** Registrar usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")
	role := ui.ReadInput("Rol (admin, doctor, paciente)")

	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
		Role:     role,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
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
	password := ui.ReadInput("Contraseña")

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
	edad := ui.ReadInt("Edad")
	diagnostico := ui.ReadInput("Diagnostico")
	tratamiento := ui.ReadInput("Tratamiento")

	historial := HistorialMedico{
		Nombre:      nombre,
		Edad:        edad,
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

	resp, err := client.Post("http://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
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
