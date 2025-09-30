#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import math
import numpy as np
from scipy.optimize import minimize
import sqlite3
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from optparse import OptionParser
from scapy.all import sniff, IP, UDP
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple, Any
import csv
import os

@dataclass
class CeldaGSM:
    mcc: str
    mnc: str
    lac: str
    cell_id: str
    arfcn: int
    bsic: int
    signal_strength: int
    latitude: float
    longitude: float
    timestamp: datetime
    tipo_celda: str  'BCCH', 'TCH', etc.

@dataclass
class UbicacionEstimada:
    latitude: float
    longitude: float
    precision: float
    metodo: str
    celdas_utilizadas: List[CeldaGSM]
    timestamp: datetime

class TrianguladorGSM:
    def __init__(self):
        self.estaciones_base = self._cargar_base_datos_estaciones()
        self.historial_mediciones = defaultdict(list)
        
    def _cargar_base_datos_estaciones(self) -> Dict[str, Dict]:
        """Carga base de datos de estaciones base conocidas"""
        try:
            with open('gsm_cell_database.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.warning("Base de datos de celdas GSM no encontrada")
            return {}
    
    def agregar_medicion_celda(self, celda: CeldaGSM):
        """Agrega una medición de celda para triangulación"""
        clave = f"{celda.mcc}-{celda.mnc}-{celda.lac}-{celda.cell_id}"
        self.historial_mediciones[clave].append(celda)
        
        # Mantener solo las últimas 50 mediciones por celda
        if len(self.historial_mediciones[clave]) > 50:
            self.historial_mediciones[clave].pop(0)
    
    def triangular_ubicacion(self, mediciones_actuales: List[CeldaGSM]) -> Optional[UbicacionEstimada]:
        """Realiza triangulación usando múltiples métodos"""
        if len(mediciones_actuales) < 3:
            return self._estimar_ubicacion_2_celdas(mediciones_actuales)
        
        # Filtrar celdas con ubicación conocida
        celdas_con_ubicacion = []
        for celda in mediciones_actuales:
            ubicacion = self._obtener_ubicacion_celda(celda)
            if ubicacion:
                celdas_con_ubicacion.append((celda, ubicacion))
        
        if len(celdas_con_ubicacion) < 2:
            return None
        
        # Aplicar múltiples métodos de triangulación
        resultados = []
        
        # 1. Triangulación por fuerza de señal
        resultado_rssi = self._triangulacion_rssi(celdas_con_ubicacion)
        if resultado_rssi:
            resultados.append(resultado_rssi)
        
        # 2. Triangulación por tiempo de llegada (TOA)
        resultado_toa = self._triangulacion_toa(celdas_con_ubicacion)
        if resultado_toa:
            resultados.append(resultado_toa)
        
        # 3. Método de centroide
        resultado_centroide = self._metodo_centroide(celdas_con_ubicacion)
        if resultado_centroide:
            resultados.append(resultado_centroide)
        
        if not resultados:
            return None
        
        # Combinar resultados usando promedio ponderado
        return self._combinar_resultados(resultados)
    
    def _triangulacion_rssi(self, celdas: List[Tuple[CeldaGSM, Dict]]) -> Optional[UbicacionEstimada]:
        """Triangulación basada en fuerza de señal (RSSI)"""
        try:
            def funcion_error(posicion):
                lat, lon = posicion
                error_total = 0
                for celda, ubicacion in celdas:
                    distancia_calculada = self._calcular_distancia(
                        lat, lon, ubicacion['lat'], ubicacion['lon']
                    )
                    # Modelo de propagación de señal
                    rssi_esperado = self._modelo_propagacion_rssi(
                        distancia_calculada, celda.signal_strength
                    )
                    error = abs(rssi_esperado - celda.signal_strength)
                    error_total += error
                return error_total
            
            # Punto inicial (promedio de ubicaciones de celdas)
            lat_inicial = np.mean([ubicacion['lat'] for _, ubicacion in celdas])
            lon_inicial = np.mean([ubicacion['lon'] for _, ubicacion in celdas])
            
            resultado = minimize(
                funcion_error, 
                [lat_inicial, lon_inicial],
                method='L-BFGS-B',
                bounds=[(lat_inicial-0.1, lat_inicial+0.1), 
                       (lon_inicial-0.1, lon_inicial+0.1)]
            )
            
            if resultado.success:
                return UbicacionEstimada(
                    latitude=resultado.x[0],
                    longitude=resultado.x[1],
                    precision=resultado.fun,
                    metodo="RSSI",
                    celdas_utilizadas=[celda for celda, _ in celdas],
                    timestamp=datetime.now()
                )
        except Exception as e:
            logging.error(f"Error en triangulación RSSI: {e}")
        
        return None
    
    def _triangulacion_toa(self, celdas: List[Tuple[CeldaGSM, Dict]]) -> Optional[UbicacionEstimada]:
        """Triangulación basada en tiempo de llegada (Time of Arrival)"""
        try:
            # Simulamos diferencias de tiempo basadas en fuerza de señal
            tiempos = []
            for celda, ubicacion in celdas:
                # Estimación simplificada del tiempo basada en RSSI
                tiempo_estimado = self._rssi_a_tiempo(celda.signal_strength)
                tiempos.append((ubicacion['lat'], ubicacion['lon'], tiempo_estimado))
            
            def funcion_error(posicion):
                lat, lon = posicion
                error_total = 0
                for lat_bs, lon_bs, tiempo in tiempos:
                    distancia = self._calcular_distancia(lat, lon, lat_bs, lon_bs)
                    tiempo_calculado = distancia / 300000  # velocidad de la luz en km/μs
                    error = abs(tiempo_calculado - tiempo)
                    error_total += error
                return error_total
            
            lat_inicial = np.mean([lat for lat, _, _ in tiempos])
            lon_inicial = np.mean([lon for _, lon, _ in tiempos])
            
            resultado = minimize(
                funcion_error,
                [lat_inicial, lon_inicial],
                method='L-BFGS-B'
            )
            
            if resultado.success:
                return UbicacionEstimada(
                    latitude=resultado.x[0],
                    longitude=resultado.x[1],
                    precision=resultado.fun,
                    metodo="TOA",
                    celdas_utilizadas=[celda for celda, _ in celdas],
                    timestamp=datetime.now()
                )
        except Exception as e:
            logging.error(f"Error en triangulación TOA: {e}")
        
        return None
    
    def _metodo_centroide(self, celdas: List[Tuple[CeldaGSM, Dict]]) -> UbicacionEstimada:
        """Método del centroide ponderado por fuerza de señal"""
        lats = []
        lons = []
        pesos = []
        
        for celda, ubicacion in celdas:
            lats.append(ubicacion['lat'])
            lons.append(ubicacion['lon'])
            # Ponderar por fuerza de señal (mayor señal = mayor peso)
            pesos.append(celda.signal_strength)
        
        # Normalizar pesos
        pesos = np.array(pesos)
        if np.sum(pesos) > 0:
            pesos = pesos / np.sum(pesos)
        else:
            pesos = np.ones(len(pesos)) / len(pesos)
        
        lat_centroide = np.average(lats, weights=pesos)
        lon_centroide = np.average(lons, weights=pesos)
        
        # Calcular precisión (desviación estándar ponderada)
        precision = np.sqrt(
            np.average((lats - lat_centroide)**2, weights=pesos) +
            np.average((lons - lon_centroide)**2, weights=pesos)
        )
        
        return UbicacionEstimada(
            latitude=lat_centroide,
            longitude=lon_centroide,
            precision=precision,
            metodo="CENTROIDE",
            celdas_utilizadas=[celda for celda, _ in celdas],
            timestamp=datetime.now()
        )
    
    def _estimar_ubicacion_2_celdas(self, celdas: List[CeldaGSM]) -> Optional[UbicacionEstimada]:
        """Estima ubicación cuando solo hay 2 celdas disponibles"""
        if len(celdas) < 2:
            return None
        
        celdas_con_ubicacion = []
        for celda in celdas:
            ubicacion = self._obtener_ubicacion_celda(celda)
            if ubicacion:
                celdas_con_ubicacion.append((celda, ubicacion))
        
        if len(celdas_con_ubicacion) < 2:
            return None
        
        # Método simplificado para 2 celdas
        celda1, ubic1 = celdas_con_ubicacion[0]
        celda2, ubic2 = celdas_con_ubicacion[1]
        
        # Interpolar basado en fuerza de señal relativa
        rssi_total = celda1.signal_strength + celda2.signal_strength
        if rssi_total > 0:
            peso1 = celda1.signal_strength / rssi_total
            peso2 = celda2.signal_strength / rssi_total
        else:
            peso1 = peso2 = 0.5
        
        lat_estimada = ubic1['lat'] * peso1 + ubic2['lat'] * peso2
        lon_estimada = ubic1['lon'] * peso1 + ubic2['lon'] * peso2
        
        # Estimación de precisión basada en distancia entre celdas
        distancia_celdas = self._calcular_distancia(
            ubic1['lat'], ubic1['lon'], ubic2['lat'], ubic2['lon']
        )
        precision = distancia_celdas * 0.5  # Estimación conservadora
        
        return UbicacionEstimada(
            latitude=lat_estimada,
            longitude=lon_estimada,
            precision=precision,
            metodo="2_CELDAS",
            celdas_utilizadas=celdas,
            timestamp=datetime.now()
        )
    
    def _calcular_distancia(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calcula distancia en kilómetros usando fórmula haversine"""
        R = 6371  # Radio de la Tierra en km
        
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        
        a = (math.sin(dlat/2) * math.sin(dlat/2) +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon/2) * math.sin(dlon/2))
        
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c
    
    def _modelo_propagacion_rssi(self, distancia: float, rssi_referencia: int) -> float:
        """Modelo de propagación de señal para estimar RSSI esperado"""
        # Modelo log-distance path loss
        # Parámetros típicos para entorno urbano
        PL0 = rssi_referencia  # Pérdida de camino a 1m
        n = 3.0  # Exponente de pérdida de camino
        return PL0 - 10 * n * math.log10(max(distancia * 1000, 1))  # Evitar log(0)
    
    def _rssi_a_tiempo(self, rssi: int) -> float:
        """Convierte RSSI a tiempo estimado de llegada"""
        # Conversión simplificada para simulación
        return max(-rssi / 100, 0.001)  # Tiempo en microsegundos
    
    def _obtener_ubicacion_celda(self, celda: CeldaGSM) -> Optional[Dict]:
        """Obtiene ubicación de una celda de la base de datos"""
        clave = f"{celda.mcc}-{celda.mnc}-{celda.lac}-{celda.cell_id}"
        return self.estaciones_base.get(clave)
    
    def _combinar_resultados(self, resultados: List[UbicacionEstimada]) -> UbicacionEstimada:
        """Combina múltiples resultados de triangulación"""
        lats = [r.latitude for r in resultados]
        lons = [r.longitude for r in resultados]
        precisiones = [r.precision for r in resultados]
        
        # Ponderar por precisión (menor precisión = mayor peso)
        pesos = [1/(p + 0.001) for p in precisiones]
        pesos = np.array(pesos) / np.sum(pesos)
        
        lat_combinada = np.average(lats, weights=pesos)
        lon_combinada = np.average(lons, weights=pesos)
        
        precision_combinada = np.average(precisiones, weights=pesos)
        
        # Combinar todas las celdas utilizadas
        todas_celdas = []
        for resultado in resultados:
            todas_celdas.extend(resultado.celdas_utilizadas)
        
        return UbicacionEstimada(
            latitude=lat_combinada,
            longitude=lon_combinada,
            precision=precision_combinada,
            metodo="COMBINADO",
            celdas_utilizadas=todas_celdas,
            timestamp=datetime.now()
        )

class MapeadorGSM:
    """Genera mapas y visualizaciones de la red GSM"""
    
    def __init__(self, triangulador: TrianguladorGSM):
        self.triangulador = triangulador
        self.mapa_celdas = {}
        self.trayectorias = defaultdict(list)
    
    def generar_mapa_heatmap(self, ubicaciones: List[UbicacionEstimada]) -> Dict:
        """Genera datos para mapa de calor de ubicaciones"""
        heatmap_data = {
            'type': 'FeatureCollection',
            'features': []
        }
        
        for ubicacion in ubicaciones:
            feature = {
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [ubicacion.longitude, ubicacion.latitude]
                },
                'properties': {
                    'precision': ubicacion.precision,
                    'metodo': ubicacion.metodo,
                    'timestamp': ubicacion.timestamp.isoformat(),
                    'intensity': max(0, 1 - ubicacion.precision / 10)  # Intensidad basada en precisión
                }
            }
            heatmap_data['features'].append(feature)
        
        return heatmap_data
    
    def generar_mapa_celdas(self) -> Dict:
        """Genera mapa de todas las celdas detectadas"""
        mapa_celdas = {
            'type': 'FeatureCollection',
            'features': []
        }
        
        for clave, mediciones in self.triangulador.historial_mediciones.items():
            if mediciones:
                celda = mediciones[-1]  # Última medición
                ubicacion = self.triangulador._obtener_ubicacion_celda(celda)
                if ubicacion:
                    feature = {
                        'type': 'Feature',
                        'geometry': {
                            'type': 'Point',
                            'coordinates': [ubicacion['lon'], ubicacion['lat']]
                        },
                        'properties': {
                            'mcc': celda.mcc,
                            'mnc': celda.mnc,
                            'lac': celda.lac,
                            'cell_id': celda.cell_id,
                            'signal_strength': celda.signal_strength,
                            'tipo': celda.tipo_celda
                        }
                    }
                    mapa_celdas['features'].append(feature)
        
        return mapa_celdas
    
    def actualizar_trayectoria(self, imsi: str, ubicacion: UbicacionEstimada):
        """Actualiza la trayectoria de un IMSI específico"""
        self.trayectorias[imsi].append(ubicacion)
        
        # Mantener solo las últimas 100 ubicaciones por IMSI
        if len(self.trayectorias[imsi]) > 100:
            self.trayectorias[imsi].pop(0)
    
    def generar_trayectoria_imsi(self, imsi: str) -> Dict:
        """Genera datos de trayectoria para un IMSI específico"""
        if imsi not in self.trayectorias:
            return {}
        
        trayectoria = {
            'type': 'FeatureCollection',
            'features': []
        }
        
        # Puntos de la trayectoria
        for i, ubicacion in enumerate(self.trayectorias[imsi]):
            feature = {
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [ubicacion.longitude, ubicacion.latitude]
                },
                'properties': {
                    'timestamp': ubicacion.timestamp.isoformat(),
                    'precision': ubicacion.precision,
                    'orden': i
                }
            }
            trayectoria['features'].append(feature)
        
        # Línea conectando los puntos
        if len(self.trayectorias[imsi]) > 1:
            coordinates = [
                [ubicacion.longitude, ubicacion.latitude] 
                for ubicacion in self.trayectorias[imsi]
            ]
            line_feature = {
                'type': 'Feature',
                'geometry': {
                    'type': 'LineString',
                    'coordinates': coordinates
                },
                'properties': {
                    'imsi': imsi,
                    'num_puntos': len(coordinates)
                }
            }
            trayectoria['features'].append(line_feature)
        
        return trayectoria

class AnalizadorGSMAvanzado:
    """Sistema completo de análisis GSM con triangulación"""
    
    def __init__(self):
        self.triangulador = TrianguladorGSM()
        self.mapeador = MapeadorGSM(self.triangulador)
        self.mediciones_actuales = defaultdict(list)
        self.ubicaciones_estimadas = []
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [Triangulación] %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def procesar_medicion_celda(self, imsi: str, celda: CeldaGSM):
        """Procesa una nueva medición de celda"""
        self.triangulador.agregar_medicion_celda(celda)
        self.mediciones_actuales[imsi].append(celda)
        
        # Realizar triangulación si tenemos suficientes mediciones
        if len(self.mediciones_actuales[imsi]) >= 2:
            ubicacion = self.triangulador.triangular_ubicacion(
                self.mediciones_actuales[imsi]
            )
            
            if ubicacion:
                self.ubicaciones_estimadas.append(ubicacion)
                self.mapeador.actualizar_trayectoria(imsi, ubicacion)
                
                self.logger.info(
                    f"IMSI {imsi} ubicado en: "
                    f"Lat {ubicacion.latitude:.6f}, Lon {ubicacion.longitude:.6f}, "
                    f"Precisión: {ubicacion.precision:.2f} km"
                )
        
        # Limpiar mediciones antiguas
        self._limpiar_mediciones_antiguas()
    
    def _limpiar_mediciones_antiguas(self):
        """Elimina mediciones más antiguas de 5 minutos"""
        ahora = datetime.now()
        for imsi in self.mediciones_actuales:
            self.mediciones_actuales[imsi] = [
                celda for celda in self.mediciones_actuales[imsi]
                if (ahora - celda.timestamp) < timedelta(minutes=5)
            ]
    
    def generar_reportes_ubicacion(self) -> Dict:
        """Genera reportes completos de ubicación"""
        return {
            'estadisticas_ubicacion': {
                'total_ubicaciones': len(self.ubicaciones_estimadas),
                'ubicaciones_hoy': len([
                    u for u in self.ubicaciones_estimadas
                    if u.timestamp.date() == datetime.now().date()
                ]),
                'precision_promedio': np.mean([
                    u.precision for u in self.ubicaciones_estimadas[-100:]
                ]) if self.ubicaciones_estimadas else 0,
                'metodos_utilizados': defaultdict(int, [
                    (u.metodo, 1) for u in self.ubicaciones_estimadas
                ])
            },
            'mapa_heatmap': self.mapeador.generar_mapa_heatmap(
                self.ubicaciones_estimadas[-1000:]  # Últimas 1000 ubicaciones
            ),
            'mapa_celdas': self.mapeador.generar_mapa_celdas(),
            'imsi_activos': {
                imsi: len(trayectoria) 
                for imsi, trayectoria in self.mapeador.trayectorias.items()
            }
        }

# Integración con el sistema existente
def main():
    parser = OptionParser(usage="%prog: [opciones]")
    parser.add_option("-i", "--interfaz", dest="interfaz", default="lo", 
                     help="Interfaz de red")
    parser.add_option("-p", "--puerto", dest="puerto", default="4729", type="int",
                     help="Puerto a monitorear")
    parser.add_option("--triangulacion", action="store_true", dest="triangulacion",
                     help="Habilita triangulación GSM")
    parser.add_option("--exportar-mapa", dest="archivo_mapa",
                     help="Exporta mapa a archivo JSON")
    parser.add_option("--modo-movil", action="store_true", dest="modo_movil",
                     help="Seguimiento de movilidad en tiempo real")

    (opciones, args) = parser.parse_args()

    if opciones.triangulacion:
        analizador = AnalizadorGSMAvanzado()
        print("🎯 Modo triangulación GSM activado")
        
        # Aquí integrarías con tu código de captura existente
        # Ejemplo de uso:
        def paquete_callback(paquete):
            # Extraer información GSM del paquete
            info_gsm = extraer_info_gsm(paquete)  # Tu función existente
            
            if info_gsm:
                celda = CeldaGSM(
                    mcc=info_gsm['mcc'],
                    mnc=info_gsm['mnc'],
                    lac=info_gsm['lac'],
                    cell_id=info_gsm['cell_id'],
                    arfcn=info_gsm.get('arfcn', 0),
                    bsic=info_gsm.get('bsic', 0),
                    signal_strength=info_gsm.get('rssi', -70),
                    latitude=0,  # Se obtendrá de la base de datos
                    longitude=0,
                    timestamp=datetime.now(),
                    tipo_celda=info_gsm.get('tipo', 'BCCH')
                )
                
                analizador.procesar_medicion_celda(info_gsm['imsi'], celda)
        
        print("📡 Capturando tráfico GSM para triangulación...")
        
        if opciones.exportar_mapa:
            # Exportar mapa periódicamente
            def exportar_periodicamente():
                while True:
                    time.sleep(300)  # Cada 5 minutos
                    reporte = analizador.generar_reportes_ubicacion()
                    with open(opciones.exportar_mapa, 'w') as f:
                        json.dump(reporte, f, indent=2)
                    print("🗺️ Mapa exportado")
            
            threading.Thread(target=exportar_periodicamente, daemon=True).start()
        
        try:
            sniff(iface=opciones.interfaz,
                  filter=f"port {opciones.puerto} and udp",
                  prn=paquete_callback,
                  store=0)
        except KeyboardInterrupt:
            print("\n📊 Generando reporte final de triangulación...")
            reporte_final = analizador.generar_reportes_ubicacion()
            print("✅ Triangulación completada")

if __name__ == '__main__':
    main()
