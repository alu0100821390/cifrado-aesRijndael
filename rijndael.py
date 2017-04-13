##########################################################################################
## Universidad de La Laguna								##
## Escuela Superior de Ingeniería y Tecnología	 					##
## Grado en Ingeniería Informática				 			##
## Seguridad en Sistemas Informáticos			 				##
## Fecha: 28/03/2017									##
## Autor: Kevin Estévez Expósito (alu0100821390) 					##
## 											##
## Práctica 5: Cifrado AES/Rijndael				 			##
## Descripción: Cifrado y descifrado de mensajes mediante el cifrado AES/Rijndael.	##
##											##
## Ejecución: py rijndael.py								##
## Ejemplo de clave: 000102030405060708090a0b0c0d0e0f					##
## Ejemplo de bloque de texto original: 00112233445566778899aabbccddeeff		##
##########################################################################################


import sys

# Inicialización de la Caja S
caja_s = []
caja_s.append([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
caja_s.append([0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0])
caja_s.append([0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15])
caja_s.append([0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75])
caja_s.append([0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84])
caja_s.append([0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf])
caja_s.append([0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8])
caja_s.append([0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2])
caja_s.append([0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73])
caja_s.append([0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb])
caja_s.append([0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79])
caja_s.append([0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08])
caja_s.append([0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a])
caja_s.append([0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e])
caja_s.append([0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf])
caja_s.append([0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16])

rc = []
rc.append([0x01, 0x00, 0x00, 0x00])
rc.append([0x02, 0x00, 0x00, 0x00])
rc.append([0x04, 0x00, 0x00, 0x00])
rc.append([0x08, 0x00, 0x00, 0x00])
rc.append([0x10, 0x00, 0x00, 0x00])
rc.append([0x20, 0x00, 0x00, 0x00])
rc.append([0x40, 0x00, 0x00, 0x00])
rc.append([0x80, 0x00, 0x00, 0x00])
rc.append([0x1b, 0x00, 0x00, 0x00])
rc.append([0x36, 0x00, 0x00, 0x00])

# Clave introducida manualmente
# clave = []
# clave.append([0x00, 0x01, 0x02, 0x03])  # Columna 0
# clave.append([0x04, 0x05, 0x06, 0x07])  # Columna 1
# clave.append([0x08, 0x09, 0x0a, 0x0b])  # Columna 2
# clave.append([0x0c, 0x0d, 0x0e, 0x0f])  # Columna 3

# Bloque de texto original introducido manualmente
# texto_original = []
# texto_original.append([0x00, 0x11, 0x22, 0x33])  # Columna 0
# texto_original.append([0x44, 0x55, 0x66, 0x77])  # Columna 1
# texto_original.append([0x88, 0x99, 0xaa, 0xbb])  # Columna 2
# texto_original.append([0xcc, 0xdd, 0xee, 0xff])  # Columna 3

##### Funciones globales #####

# Función SubBytes (para columnas): Sustitución no lineal de los bytes del vector
# basada en una S-Caja que, para cada byte, genera un nuevo byte
def sub_bytes_col(columna):
	for i in range(4):
		if len(hex(columna[i])[2:]) == 1:  # Si el número hexadecimal tiene una sola cifra...
			coord1 = 0
			coord2 = columna[i]
		else:
			coord1 = int(hex(columna[i])[-2], 16)  # -2 indica la penúltima posición
			coord2 = int(hex(columna[i])[-1], 16)  # -1 indica la última posición
		columna[i] = caja_s[coord1][coord2]

# Función SubBytes: Sustitución no lineal de los bytes de la matriz de estado 
# basada en una S-Caja que, para cada byte, genera un nuevo byte
def sub_bytes(estado):
	for i in range(4):
		for j in range(4):
			if len(hex(estado[i][j])[2:]) == 1:  # Si el número hexadecimal tiene una sola cifra...
				coord1 = 0
				coord2 = estado[i][j]
			else:
				coord1 = int(hex(estado[i][j])[-2], 16)  # -2 indica la penúltima posición
				coord2 = int(hex(estado[i][j])[-1], 16)  # -1 indica la última posición
			estado[i][j] = caja_s[coord1][coord2]

# Función ShiftRow: Desplaza a la izquierda los bytes tantas veces como
# indique su posición en la matriz de las filas que conforman
# la matriz del estado pasado por parámetros
def shift_rows(estado):
	for i in range(4):
		for j in range(i):
			aux1 = estado[0].pop(i)
			aux2 = estado[1].pop(i)
			aux3 = estado[2].pop(i)
			aux4 = estado[3].pop(i)
			estado[0].insert(i, aux2)
			estado[1].insert(i, aux3)
			estado[2].insert(i, aux4)
			estado[3].insert(i, aux1)

# Función MixColumn
def mix_column(r):
	a = []
	b = []
	for c in range(4):
		a.append(r[c])
		h = r[c] & 0x80
		b.append((r[c] << 1) % 256)
		if h == 0x80:
			b[c] = b[c] ^ 0x1b
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]

# Función AddRoundKey: Consiste en una XOR entre
# el estado intermedio y la subclave correspondientes
def add_round_key(entrada, clave):
	for i in range(4):
		columna_intermedia = []
		for j in range(4):
			columna_intermedia.append(entrada[i][j] ^ clave[i][j])
		entrada[i] = columna_intermedia


##### PROGRAMA PRINCIPAL #####

# Se pide la clave por teclado
clave_ = str(input("Introduzca una clave de 16 bytes en hexadecimal: "))
while len(clave_) != 32:
	clave_ = str(input("Introduzca una clave de 16 bytes en hexadecimal: "))

clave = []  # Lista en la que se guardará la clave
# Se divide la clave introducida y se guarda en forma de matriz
for i in range(4):
	clave.append([])
	for j in range(4):
		pos = (i * 8) + (2 * j)
		clave[i].append(int(clave_[pos:pos+2], 16))


# Se pide el bloque de texto original por teclado
texto_original_ = str(input("Introduzca el bloque de texto original de 16 bytes en hexadecimal: "))
while len(texto_original_) != 32:
	texto_original_ = str(input("Introduzca el bloque de texto original de 16 bytes en hexadecimal: "))

texto_original = []  # Lista en la que se guardará el bloque de texto original
# Se divide el bloque de texto original introducido y se guarda en forma de matriz
for i in range(4):
	texto_original.append([])
	for j in range(4):
		pos = (i * 8) + (2 * j)
		texto_original[i].append(int(texto_original_[pos:pos+2], 16))


# EXPANSIÓN DE CLAVE

subclave = []  # Lista en la que se irán guardando las subclaves
subclave.append(clave)  # Se añade la clave original como primera subclave

# 10 iteraciones de generación de subclaves
for n in range(0, 10):
	clave_aux = []
	columna_aux = []
	columna1 = []
	columna2 = []
	columna3 = []
	columna4 = []
	
	for i in range(4):
		columna_aux.append(subclave[n][3][i])
	
	#RotWord
	aux = columna_aux.pop(0)
	columna_aux.append(aux)
	
	#SubBytes
	sub_bytes_col(columna_aux)
	
	#XOR
	for i in range(4):
		columna1.append(subclave[n][0][i] ^ columna_aux[i] ^ rc[n][i])
		columna2.append(subclave[n][1][i] ^ columna1[i])
		columna3.append(subclave[n][2][i] ^ columna2[i])
		columna4.append(subclave[n][3][i] ^ columna3[i])
	clave_aux.append(columna1)
	clave_aux.append(columna2)
	clave_aux.append(columna3)
	clave_aux.append(columna4)
	subclave.append(clave_aux)  # Se añade la subclave generada a la lista de claves


intermedio = []  # Lista en la que se irán guardando los estados intermedios

# Primera iteración (solo AddRoundKey)
estado_aux = texto_original  # Estado auxiliar que se transformará hasta obtener el primer estado intermedio
add_round_key(estado_aux, clave)  # AddRoundKey entre el bloque de entrada y la clave original
intermedio.append(estado_aux)  # Se guarda el primer estado intermedio generado

# Se muestra por pantalla la primera iteración
print ("R0 (Subclave = ", end = '')
for i in range(len(subclave[0])):
	for j in range(len(subclave[0][i])):
		print (hex(subclave[0][i][j])[2:].zfill(2), end = '')
print (") = ", end = '')
for i in range(len(intermedio[0])):
	for j in range(len(intermedio[0][i])):
		print (hex(intermedio[0][i][j])[2:].zfill(2), end = '')
print ()


# 9 iteraciones (1.SubBytes, 2.ShiftRow, 3.MixColumn y 4.AddRoundKey)
for a in range(1, 10):
	estado_aux = intermedio[a-1]  # Estado auxiliar que se transformará hasta obtener el estado intermedio correspondiente
	sub_bytes(estado_aux)  # 1.SubBytes
	shift_rows(estado_aux)  # 2.ShiftRows
	for i in range(4):
		mix_column(estado_aux[i])  # 3.MixColumn con cada una de las columnas del estado
	add_round_key(estado_aux, subclave[a])  # 4.AddRoundKey con la subclave correspondiente
	intermedio.append(estado_aux)  # Se guarda el estado intermedio generado
	
	# Se muestra por pantalla
	print ("R" + str(a) + " (Subclave = ", end = '')
	for i in range(4):
		for j in range(4):
			print (hex(subclave[a][i][j])[2:].zfill(2), end = '')
	print (") = ", end = '')
	for i in range(4):
		for j in range(4):
			print (hex(intermedio[a][i][j])[2:].zfill(2), end = '')
	print ()


# Última iteración (1.SubBytes, 2.ShiftRows, 3.AddRoundKey)
estado_aux = intermedio[-1]  # Estado auxiliar que se transformará hasta obtener el último estado intermedio
sub_bytes(estado_aux)  # 1.SubBytes
shift_rows(estado_aux)  # 2.ShiftRows
add_round_key(estado_aux, subclave[-1])  # AddRoundKey con la última subclave
intermedio.append(estado_aux)  # Se guarda el último estado intermedio generado

# Se muestra por pantalla la última iteración
print ("R10" + " (Subclave = ", end = '')
for i in range(4):
	for j in range(4):
		print (hex(subclave[-1][i][j])[2:].zfill(2), end = '')
print (") = ", end = '')
for i in range(4):
	for j in range(4):
		print (hex(intermedio[-1][i][j])[2:].zfill(2), end = '')
print ()

# Se muestra por pantalla el bloque de texto cifrado
print ()
print ("Bloque de Texto Cifrado: ", end = '')
for i in range(4):
		for j in range(4):
			print (hex(intermedio[-1][i][j])[2:].zfill(2), end = '')


print ()
sys.exit(0)
