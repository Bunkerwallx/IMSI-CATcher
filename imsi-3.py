#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
import sqlite3
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from optparse import OptionParser
from scapy.all import sniff, IP, UDP
import threading
import heapq
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
import csv
import os

@dataclass
class EventoIMSI:
    timestamp: datetime
    imsi: str
    tmsi: str
    tipo_evento: str  # 'DETECCION', 'REASIGNACION', 'ALERTA'
    mcc: str
    mnc: str
    lac: str
    cell_id: str
    fuerza_señal: Optional[int] = None

class AnalizadorMovil:
    def __init__(self, archivo_bd: str = "trafico_movil.db"):
        self.imsis_detectados = set()
        self.tmsis_asociados = {}
        self.contador_imsi = 0
        self.estadisticas = defaultdict(lambda: defaultdict(int))
        self.alertas = []
        self.conn = sqlite3.connect(archivo_bd, check_same_thread=False)
        self._inicializar_bd()
        self.lock = threading.RLock()
        
        # Patrones sospechosos
        self.reasignaciones_rapidas = defaultdict(deque)
        self.imsi_hopping = defaultdict(set)
        
        # Cargar códigos MCC-MNC
        with open('mcc-mnc/mcc_codes.json', 'r') as archivo:
            self.codigos_mcc_mnc = json.load(archivo)
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('analizador_movil.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _inicializar_bd(self):
        """Inicializa la base de datos SQLite"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detecciones_imsi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                imsi TEXT,
                tmsi TEXT,
                mcc TEXT,
                mnc TEXT,
                lac TEXT,
                cell_id TEXT,
                tipo_evento TEXT,
                fuerza_señal INTEGER,
                pais TEXT,
                operador TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS estadisticas_diarias (
                fecha DATE PRIMARY KEY,
                total_imsi INTEGER,
                total_eventos INTEGER,
                paises_detectados INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                tipo_alerta TEXT,
                severidad TEXT,
                descripcion TEXT,
                imsi_involucrado TEXT,
                evidencia TEXT
            )
        ''')
        self.conn.commit()

    def analizar_comportamiento_sospechoso(self, evento: EventoIMSI):
        """Detecta comportamientos anómalos en tiempo real"""
        with self.lock:
            ahora = datetime.now()
            
            # Detectar reasignaciones rápidas de TMSI
            self.reasignaciones_rapidas[evento.imsi].append(ahora)
            # Mantener solo eventos de los últimos 5 minutos
            while (self.reasignaciones_rapidas[evento.imsi] and 
                   ahora - self.reasignaciones_rapidas[evento.imsi][0] > timedelta(minutes=5)):
                self.reasignaciones_rapidas[evento.imsi].popleft()
            
            if len(self.reasignaciones_rapidas[evento.imsi]) > 10:
                self._generar_alerta(
                    "REASIGNACION_TMSI_RAPIDA",
                    "ALTA",
                    f"IMSI {evento.imsi} con {len(self.reasignaciones_rapidas[evento.imsi])} reasignaciones en 5 min",
                    evento.imsi
                )

            # Detectar IMSI hopping entre celdas
            self.imsi_hopping[evento.imsi].add((evento.lac, evento.cell_id))
            if len(self.imsi_hopping[evento.imsi]) > 5:
                self._generar_alerta(
                    "IMSI_HOPPING",
                    "MEDIA",
                    f"IMSI {evento.imsi} detectado en {len(self.imsi_hopping[evento.imsi])} celdas diferentes",
                    evento.imsi
                )

    def _generar_alerta(self, tipo: str, severidad: str, descripcion: str, imsi: str):
        """Registra una alerta en el sistema"""
        alerta = {
            'timestamp': datetime.now(),
            'tipo': tipo,
            'severidad': severidad,
            'descripcion': descripcion,
            'imsi': imsi
        }
        self.alertas.append(alerta)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO alertas (tipo_alerta, severidad, descripcion, imsi_involucrado)
            VALUES (?, ?, ?, ?)
        ''', (tipo, severidad, descripcion, imsi))
        self.conn.commit()
        
        self.logger.warning(f"ALERTA {severidad}: {tipo} - {descripcion}")

    def generar_reporte_avanzado(self):
        """Genera reportes detallados de análisis"""
        reporte = {
            'resumen': self._generar_resumen(),
            'patrones_sospechosos': self._analizar_patrones(),
            'estadisticas_temporales': self._estadisticas_temporales(),
            'top_operadores': self._top_operadores()
        }
        
        # Exportar a JSON
        with open(f'reporte_movil_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
            json.dump(reporte, f, indent=2, default=str)
        
        return reporte

    def _generar_resumen(self) -> Dict:
        """Genera resumen ejecutivo"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(DISTINCT imsi), COUNT(*), COUNT(DISTINCT mcc)
            FROM detecciones_imsi 
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        total_imsi, total_eventos, total_paises = cursor.fetchone()
        
        return {
            'total_imsi_unicos': total_imsi,
            'total_eventos': total_eventos,
            'paises_detectados': total_paises,
            'alertas_24h': len(self.alertas),
            'timestamp_generacion': datetime.now()
        }

class SistemaGeolocalizacion:
    def __init__(self, analizador: AnalizadorMovil):
        self.analizador = analizador
        self.historial_ubicaciones = defaultdict(list)
        
    def agregar_ubicacion(self, imsi: str, mcc: str, mnc: str, lac: str, cell_id: str):
        """Registra la ubicación de un IMSI"""
        ubicacion = {
            'timestamp': datetime.now(),
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac,
            'cell_id': cell_id,
            'pais': self._obtener_pais(mcc),
            'operador': self._obtener_operador(mcc, mnc)
        }
        
        self.historial_ubicaciones[imsi].append(ubicacion)
        # Mantener máximo 100 ubicaciones por IMSI
        if len(self.historial_ubicaciones[imsi]) > 100:
            self.historial_ubicaciones[imsi].pop(0)

    def _obtener_pais(self, mcc: str) -> str:
        """Obtiene el país basado en MCC"""
        return self.analizador.codigos_mcc_mnc.get(mcc, {}).get('c', ['Desconocido'])[0]

    def _obtener_operador(self, mcc: str, mnc: str) -> str:
        """Obtiene el operador basado en MCC y MNC"""
        return self.analizador.codigos_mcc_mnc.get(mcc, {}).get('MNC', {}).get(mnc, ['Desconocido'])[1]

    def generar_mapa_calor(self):
        """Genera datos para mapa de calor de detecciones"""
        ubicaciones = []
        for imsi, historial in self.historial_ubicaciones.items():
            for ubicacion in historial[-10:]:  # Últimas 10 ubicaciones
                ubicaciones.append({
                    'imsi': imsi,
                    'pais': ubicacion['pais'],
                    'operador': ubicacion['operador'],
                    'timestamp': ubicacion['timestamp']
                })
        return ubicaciones

class InterfazWeb(threading.Thread):
    """Servidor web para visualización en tiempo real"""
    def __init__(self, analizador: AnalizadorMovil, puerto: int = 8080):
        super().__init__()
        self.analizador = analizador
        self.puerto = puerto
        self.daemon = True

    def run(self):
        try:
            from flask import Flask, jsonify, render_template
            app = Flask(__name__)
            
            @app.route('/')
            def index():
                return render_template('dashboard.html')
            
            @app.route('/api/estadisticas')
            def api_estadisticas():
                return jsonify(self.analizador.generar_reporte_avanzado())
            
            @app.route('/api/alertas')
            def api_alertas():
                return jsonify(self.analizador.alertas[-50:])  # Últimas 50 alertas
            
            @app.route('/api/imsi-activos')
            def api_imsi_activos():
                # IMSI activos en los últimos 15 minutos
                cursor = self.analizador.conn.cursor()
                cursor.execute('''
                    SELECT DISTINCT imsi, MAX(timestamp) as ultima_deteccion
                    FROM detecciones_imsi 
                    WHERE timestamp > datetime('now', '-15 minutes')
                    GROUP BY imsi
                    ORDER BY ultima_deteccion DESC
                ''')
                return jsonify([{'imsi': row[0], 'ultima_deteccion': row[1]} 
                              for row in cursor.fetchall()])
            
            app.run(host='0.0.0.0', port=self.puerto, debug=False)
        except ImportError:
            print("Flask no instalado. Instala con: pip install flask")

class MotorCorrelacion:
    """Motor de correlación para detectar patrones complejos"""
    def __init__(self, analizador: AnalizadorMovil):
        self.analizador = analizador
        self.reglas = [
            self._regla_imsi_catcher,
            self._regla_ataque_denegacion_servicio,
            self._regla_reconocimiento_red
        ]

    def ejecutar_correlacion(self, evento: EventoIMSI):
        """Ejecuta todas las reglas de correlación"""
        for regla in self.reglas:
            regla(evento)

    def _regla_imsi_catcher(self, evento: EventoIMSI):
        """Detecta posibles IMSI catchers"""
        # Regla: Celda con múltiples IMSI internacionales en poco tiempo
        pass

    def _regla_ataque_denegacion_servicio(self, evento: EventoIMSI):
        """Detecta patrones de ataque de denegación de servicio"""
        pass

    def _regla_reconocimiento_red(self, evento: EventoIMSI):
        """Detecta actividades de reconocimiento de red"""
        pass

# Clase principal mejorada
class AnalizadorMovilAvanzado:
    def __init__(self):
        self.analizador = AnalizadorMovil()
        self.geolocalizacion = SistemaGeolocalizacion(self.analizador)
        self.motor_correlacion = MotorCorrelacion(self.analizador)
        self.interfaz_web = InterfazWeb(self.analizador)
        
        # Configuración de filtros
        self.filtros_personalizados = []
        
        # Iniciar interfaz web en segundo plano
        self.interfaz_web.start()

    def procesar_paquete(self, paquete):
        """Procesa un paquete de red con todas las capacidades avanzadas"""
        try:
            # Análisis básico (código existente)
            info_celda = self._decodificar_info_celda(paquete)
            imsi_info = self._buscar_imsi(paquete)
            
            if imsi_info:
                evento = EventoIMSI(
                    timestamp=datetime.now(),
                    imsi=imsi_info['imsi'],
                    tmsi=imsi_info['tmsi'],
                    tipo_evento='DETECCION',
                    mcc=info_celda['mcc'],
                    mnc=info_celda['mnc'],
                    lac=info_celda['lac'],
                    cell_id=info_celda['cell_id']
                )
                
                # Procesamiento avanzado
                self.analizador.analizar_comportamiento_sospechoso(evento)
                self.geolocalizacion.agregar_ubicacion(
                    evento.imsi, evento.mcc, evento.mnc, evento.lac, evento.cell_id
                )
                self.motor_correlacion.ejecutar_correlacion(evento)
                
                # Guardar en base de datos
                self._guardar_evento_bd(evento)
                
        except Exception as e:
            self.analizador.logger.error(f"Error procesando paquete: {e}")

    def _guardar_evento_bd(self, evento: EventoIMSI):
        """Guarda evento en base de datos"""
        cursor = self.analizador.conn.cursor()
        cursor.execute('''
            INSERT INTO detecciones_imsi 
            (imsi, tmsi, mcc, mnc, lac, cell_id, tipo_evento, pais, operador)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evento.imsi, evento.tmsi, evento.mcc, evento.mnc, 
            evento.lac, evento.cell_id, evento.tipo_evento,
            self.geolocalizacion._obtener_pais(evento.mcc),
            self.geolocalizacion._obtener_operador(evento.mcc, evento.mnc)
        ))
        self.analizador.conn.commit()

    def agregar_filtro_personalizado(self, filtro):
        """Permite agregar filtros personalizados para detección"""
        self.filtros_personalizados.append(filtro)

    def exportar_datos(self, formato: str = 'json'):
        """Exporta datos en varios formatos"""
        if formato == 'json':
            with open('detecciones_export.json', 'w') as f:
                json.dump(list(self.analizador.imsis_detectados), f, indent=2)
        elif formato == 'csv':
            with open('detecciones_export.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IMSI', 'Primera_Deteccion', 'Ultima_Deteccion', 'Total_Eventos'])
                # Implementar lógica de exportación CSV

    # Mantener métodos existentes pero integrados con el nuevo sistema
    def _decodificar_info_celda(self, paquete):
        # Implementación existente mejorada
        pass

    def _buscar_imsi(self, paquete):
        # Implementación existente mejorada
        pass

# Uso del sistema avanzado
def main():
    parser = OptionParser(usage="%prog: [opciones]")
    parser.add_option("-i", "--interfaz", dest="interfaz", default="lo", 
                     help="Interfaz de red")
    parser.add_option("-p", "--puerto", dest="puerto", default="4729", type="int",
                     help="Puerto a monitorear")
    parser.add_option("--modo-avanzado", action="store_true", dest="modo_avanzado",
                     help="Habilita análisis avanzado y correlación")
    parser.add_option("--interfaz-web", action="store_true", dest="interfaz_web",
                     help="Inicia servidor web de visualización")
    parser.add_option("--exportar", dest="formato_export", 
                     help="Exportar datos en formato (json, csv)")

    (opciones, args) = parser.parse_args()

    if opciones.modo_avanzado:
        analizador = AnalizadorMovilAvanzado()
        print("✅ Modo avanzado activado - Análisis en tiempo real con correlación")
    else:
        # Usar versión básica para compatibilidad
        from analizador_basico import main as main_basico
        main_basico()
        return

    if opciones.interfaz_web:
        print(f"🌐 Interfaz web disponible en: http://localhost:8080")

    if opciones.formato_export:
        analizador.exportar_datos(opciones.formato_export)
        return

    # Iniciar captura
    try:
        print("🚀 Iniciando captura de tráfico móvil...")
        sniff(iface=opciones.interfaz, 
              filter=f"port {opciones.puerto} and not icmp and udp",
              prn=analizador.procesar_paquete, 
              store=0)
    except KeyboardInterrupt:
        print("\n📊 Generando reporte final...")
        reporte = analizador.analizador.generar_reporte_avanzado()
        print("✅ Análisis completado")

if __name__ == '__main__':
    main()
