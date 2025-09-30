#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
from optparse import OptionParser
from scapy.all import sniff

# Variables globales
imsis_detectados = []
tmsis_asociados = {}
contador_imsi = 0
mcc_actual = ""
mnc_actual = ""
lac_actual = ""
celda_actual = ""
pais_actual = ""
marca_actual = ""
operador_actual = ""
imsi_a_seguir = ""
longitud_imsi_seguir = 0
mostrar_todos_tmsi = False

# Cargar códigos MCC-MNC al inicio
with open('mcc-mnc/mcc_codes.json', 'r') as archivo:
    codigos_mcc_mnc = json.load(archivo)

def formatear_tmsi(tmsi):
    """Convierte un TMSI a formato hexadecimal legible"""
    if not tmsi:
        return ""
    
    tmsi_hex = "0x"
    for byte in tmsi:
        hex_byte = hex(ord(byte))
        if len(hex_byte) == 4:
            tmsi_hex += hex_byte[2] + hex_byte[3]
        else:
            tmsi_hex += "0" + hex_byte[2]
    return tmsi_hex

def formatear_imsi(imsi, paquete_original=""):
    """Formatea y decodifica un IMSI con información del operador"""
    if not imsi:
        return ""
    
    imsi_formateado = ''
    for byte in imsi:
        hex_byte = hex(ord(byte))
        if len(hex_byte) == 4:
            imsi_formateado += hex_byte[3] + hex_byte[2]
        else:
            imsi_formateado += hex_byte[2] + "0"
    
    mcc = imsi_formateado[1:4]
    mnc = imsi_formateado[4:6]
    pais = ""
    marca = ""
    operador = ""
    
    if mcc in codigos_mcc_mnc:
        if mnc in codigos_mcc_mnc[mcc]['MNC']:
            pais = codigos_mcc_mnc[mcc]['c'][0]
            marca = codigos_mcc_mnc[mcc]['MNC'][mnc][0]
            operador = codigos_mcc_mnc[mcc]['MNC'][mnc][1]
            imsi_formateado = f"{mcc} {mnc} {imsi_formateado[6:]}"
        elif mnc + imsi_formateado[6:7] in codigos_mcc_mnc[mcc]['MNC']:
            mnc += imsi_formateado[6:7]
            pais = codigos_mcc_mnc[mcc]['c'][0]
            marca = codigos_mcc_mnc[mcc]['MNC'][mnc][0]
            operador = codigos_mcc_mnc[mcc]['MNC'][mnc][1]
            imsi_formateado = f"{mcc} {mnc} {imsi_formateado[7:]}"
        else:
            pais = codigos_mcc_mnc[mcc]['c'][0]
            marca = f"MNC {mnc} Desconocido"
            operador = f"MNC {mnc} Desconocido"
            imsi_formateado = f"{mcc} {mnc} {imsi_formateado[6:]}"
    else:
        pais = f"MCC {mcc} Desconocido"
        marca = f"MNC {mnc} Desconocido"
        operador = f"MNC {mnc} Desconocido"
    
    try:
        linea_formateada = f"{imsi_formateado:17s} ; {pais:12s} ; {marca:10s} ; {operador:21s}"
    except Exception as e:
        print(f"Error al formatear IMSI: {e}", paquete_original, imsi_formateado, pais, marca, operador)
        linea_formateada = ""
    
    return linea_formateada

def mostrar_imsi(imsi1="", imsi2="", tmsi1="", tmsi2="", paquete_original=""):
    """Procesa y muestra información de IMSI/TMSI detectados"""
    global imsis_detectados, tmsis_asociados, contador_imsi
    global mcc_actual, mnc_actual, lac_actual, celda_actual
    
    debe_imprimir = False
    numero_imsi = ''
    
    # Procesar IMSI 1
    if imsi1 and (not imsi_a_seguir or imsi1[:longitud_imsi_seguir] == imsi_a_seguir):
        if imsi1 not in imsis_detectados:
            debe_imprimir = True
            imsis_detectados.append(imsi1)
            contador_imsi += 1
            numero_imsi = contador_imsi
        
        # Asociar TMSIs con IMSI
        for tmsi in [tmsi1, tmsi2]:
            if tmsi and (tmsi not in tmsis_asociados or tmsis_asociados[tmsi] != imsi1):
                debe_imprimir = True
                tmsis_asociados[tmsi] = imsi1
    
    # Procesar IMSI 2
    if imsi2 and (not imsi_a_seguir or imsi2[:longitud_imsi_seguir] == imsi_a_seguir):
        if imsi2 not in imsis_detectados:
            debe_imprimir = True
            imsis_detectados.append(imsi2)
            contador_imsi += 1
            numero_imsi = contador_imsi
        
        for tmsi in [tmsi1, tmsi2]:
            if tmsi and (tmsi not in tmsis_asociados or tmsis_asociados[tmsi] != imsi2):
                debe_imprimir = True
                tmsis_asociados[tmsi] = imsi2
    
    # Manejar reasignación de TMSI
    if not imsi1 and not imsi2 and tmsi1 and tmsi2:
        if tmsi2 in tmsis_asociados:
            debe_imprimir = True
            imsi1 = tmsis_asociados[tmsi2]
            tmsis_asociados[tmsi1] = imsi1
            del tmsis_asociados[tmsi2]
    
    # Mostrar resultados
    if debe_imprimir:
        for imsi in [imsi1, imsi2]:
            if imsi:
                linea = f"{str(numero_imsi):7s} ; {formatear_tmsi(tmsi1):10s} ; {formatear_tmsi(tmsi2):10s} ; {formatear_imsi(imsi, paquete_original)} ; {mcc_actual:4s} ; {mnc_actual:5s} ; {lac_actual:6s} ; {celda_actual:6s}"
                print(linea)
                sys.stdout.flush()
    
    # Mostrar TMSIs sin IMSI asociado (si está habilitado)
    if not imsi1 and not imsi2 and mostrar_todos_tmsi:
        for tmsi in [tmsi1, tmsi2]:
            if tmsi and tmsi not in tmsis_asociados:
                tmsis_asociados[tmsi] = ""

def decodificar_info_celda(paquete):
    """Decodifica información de la celda (MCC, MNC, LAC, Cell ID)"""
    global mcc_actual, mnc_actual, lac_actual, celda_actual
    global pais_actual, marca_actual, operador_actual
    
    datos = str(paquete)
    
    # Verificar si es mensaje de información del sistema tipo 3
    if ord(datos[0x36]) == 0x01 and ord(datos[0x3c]) == 0x1b:
        # Decodificar MCC
        byte_mcc = hex(ord(datos[0x3f]))
        mcc_actual = byte_mcc[2] + '0' if len(byte_mcc) < 4 else byte_mcc[3] + byte_mcc[2]
        mcc_actual += str(ord(datos[0x40]) & 0x0f)
        
        # Decodificar MNC
        byte_mnc = hex(ord(datos[0x41]))
        mnc_actual = byte_mnc[2] + '0' if len(byte_mnc) < 4 else byte_mnc[3] + byte_mnc[2]
        
        # Decodificar LAC y Cell ID
        lac_actual = str(ord(datos[0x42]) * 256 + ord(datos[0x43]))
        celda_actual = str(ord(datos[0x3d]) * 256 + ord(datos[0x3e]))
        
        # Buscar información del operador
        if mcc_actual in codigos_mcc_mnc:
            if mnc_actual in codigos_mcc_mnc[mcc_actual]['MNC']:
                pais_actual = codigos_mcc_mnc[mcc_actual]['c'][0]
                marca_actual = codigos_mcc_mnc[mcc_actual]['MNC'][mnc_actual][0]
                operador_actual = codigos_mcc_mnc[mcc_actual]['MNC'][mnc_actual][1]
            else:
                pais_actual = codigos_mcc_mnc[mcc_actual]['c'][0]
                marca_actual = f"MNC {mnc_actual} Desconocido"
                operador_actual = f"MNC {mnc_actual} Desconocido"
        else:
            pais_actual = f"MCC {mcc_actual} Desconocido"
            marca_actual = f"MNC {mnc_actual} Desconocido"
            operador_actual = f"MNC {mnc_actual} Desconocido"
        
        return True
    
    return False

def buscar_imsi(paquete):
    """Función principal que analiza paquetes en busca de IMSI/TMSI"""
    decodificar_info_celda(paquete)
    datos = str(paquete)
    
    # Solo procesar si no es canal BCCH
    if ord(datos[0x36]) != 0x1:
        tmsi1, tmsi2, imsi1, imsi2 = "", "", "", ""
        
        # Mensaje de identidad móvil
        if ord(datos[0x3c]) == 0x21:
            # IMSI en solicitud de identidad
            if ord(datos[0x3e]) == 0x08 and (ord(datos[0x3f]) & 0x1) == 0x1:
                imsi1 = datos[0x3f:][:8]
                
                # Segundo IMSI posible
                if ord(datos[0x3a]) == 0x59 and ord(datos[0x48]) == 0x08 and (ord(datos[0x49]) & 0x1) == 0x1:
                    imsi2 = datos[0x49:][:8]
                # TMSI en lugar de segundo IMSI
                elif ord(datos[0x3a]) == 0x59 and ord(datos[0x48]) == 0x08 and (ord(datos[0x49]) & 0x1) == 0x1:
                    tmsi1 = datos[0x4a:][:4]
                
                mostrar_imsi(imsi1, imsi2, tmsi1, tmsi2, datos)
            
            # IMSI con TMSI previo
            elif ord(datos[0x45]) == 0x08 and (ord(datos[0x46]) & 0x1) == 0x1:
                tmsi1 = datos[0x40:][:4]
                imsi2 = datos[0x46:][:8]
                mostrar_imsi(imsi1, imsi2, tmsi1, tmsi2, datos)
            
            # Intercambio de TMSI
            elif ord(datos[0x3e]) == 0x05 and (ord(datos[0x3f]) & 0x07) == 4:
                tmsi1 = datos[0x40:][:4]
                if ord(datos[0x45]) == 0x05 and (ord(datos[0x46]) & 0x07) == 4:
                    tmsi2 = datos[0x47:][:4]
                
                mostrar_imsi(imsi1, imsi2, tmsi1, tmsi2, datos)
        
        # Mensaje de reasignación de TMSI
        elif ord(datos[0x3c]) == 0x22:
            if ord(datos[0x47]) == 0x08 and (ord(datos[0x48]) & 0x1) == 0x1:
                tmsi1 = datos[0x3e:][:4]
                tmsi2 = datos[0x42:][:4]
                imsi2 = datos[0x48:][:8]
                mostrar_imsi(imsi1, imsi2, tmsi1, tmsi2, datos)

def main():
    """Función principal"""
    global mostrar_todos_tmsi, imsi_a_seguir, longitud_imsi_seguir
    
    parser = OptionParser(usage="%prog: [opciones]")
    parser.add_option("-a", "--todos-tmsi", action="store_true", dest="mostrar_todos_tmsi", 
                     help="Mostrar TMSI que no tienen IMSI asociado (por defecto: false)")
    parser.add_option("-i", "--interfaz", dest="interfaz", default="lo", 
                     help="Interfaz de red (por defecto: lo)")
    parser.add_option("-m", "--imsi", dest="imsi", default="", type="string",
                     help='IMSI a rastrear (por defecto: ninguno, Ejemplo: 123456789101112 o "123 45 6789101112")')
    parser.add_option("-p", "--puerto", dest="puerto", default="4729", type="int",
                     help="Puerto (por defecto: 4729)")
    
    (opciones, args) = parser.parse_args()
    
    mostrar_todos_tmsi = opciones.mostrar_todos_tmsi
    
    # Procesar IMSI a rastrear
    if opciones.imsi:
        imsi = "9" + opciones.imsi.replace(" ", "")
        longitud_imsi = len(imsi)
        
        if longitud_imsi % 2 == 0 and 0 < longitud_imsi < 17:
            for i in range(0, longitud_imsi - 1, 2):
                imsi_a_seguir += chr(int(imsi[i + 1]) * 16 + int(imsi[i]))
            longitud_imsi_seguir = len(imsi_a_seguir)
        else:
            print("¡Tamaño incorrecto para el IMSI a rastrear!")
            print("Tamaños válidos:")
            for longitud in [15, 13, 11, 9, 7, 5, 3]:
                print(f"- {longitud} dígitos")
            sys.exit(1)
    
    # Encabezado de la tabla de resultados
    print(f"{'Nº IMSI':7s} ; {'T-IMSI1':10s} ; {'T-IMSI2':10s} ; {'IMSI':17s} ; {'País':12s} ; {'Marca':10s} ; {'Operador':21s} ; {'MCC':5s} ; {'MNC':4s} ; {'LAC':5s} ; {'Celda':6s}")
    
    # Iniciar captura de paquetes
    filtro = f"port {opciones.puerto} and not icmp and udp"
    sniff(iface=opciones.interfaz, filter=filtro, prn=buscar_imsi, store=0)

if __name__ == '__main__':
    main()
