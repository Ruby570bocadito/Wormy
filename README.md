# 🚀 ML Network Worm v2.0

## Enterprise-Grade Red Team Tool with AI/ML

Un sistema completo de red team con inteligencia artificial para operaciones de seguridad autorizadas.

---

## ⚡ Características Principales

### 🎯 **18 Módulos de Explotación**
- SMB (EternalBlue), SSH, Web, RDP, FTP
- MySQL, PostgreSQL, Redis, MongoDB
- Telnet, VNC, SNMP, Docker
- **Jenkins, Elasticsearch, MSSQL, Kubernetes, Tomcat** ⭐

### 🛡️ **Evasión Avanzada**
- 9 técnicas de bypass de EDR/AV
- Ejecución fileless (memory-only)
- AMSI bypass, Direct syscalls, DLL unhooking
- Process hollowing, Thread hijacking, APC injection

### 📡 **Multi-Protocol C2**
- HTTPS, DNS Tunneling, ICMP Tunneling
- WebSockets, SMB Named Pipes
- Encriptación AES-256, Domain fronting

### 🔓 **Post-Explotación Completa**
- 20+ técnicas de escalación de privilegios
- 9+ fuentes de dumping de credenciales
- 15+ métodos de persistencia
- 9 técnicas de movimiento lateral
- Anti-forensics completo

### 🤖 **Inteligencia Artificial**
- Reinforcement Learning para selección de targets
- Aprendizaje adaptativo de evasión
- Optimización automática de estrategias

---

## 🚀 Inicio Rápido

### Instalación
```bash
pip install -r requirements.txt
```

### Ejecución
```bash
# Modo simulation (seguro)
python worm_core.py --config config_simulation.yaml

# Modo aggressive (máximo)
python worm_core.py --config config_aggressive.yaml

# Solo escaneo
python worm_core.py --scan-only
```

### Monitorización
```bash
# Dashboard en vivo
python start_monitoring.bat
# Abre: http://localhost:8080
```

### Testing
```bash
# Test completo
python test_v2.py
```

---

## 📊 Estructura del Proyecto

```
ML/
├── exploits/          # 18 módulos de explotación
├── evasion/           # EDR bypass, stealth, anti-forensics
├── c2/                # Multi-protocol C2
├── post_exploit/      # Privilege escalation, credentials, persistence
├── scanner/           # Network scanning
├── rl_engine/         # Reinforcement Learning
├── monitoring/        # Dashboard web
└── utils/             # Utilidades
```

---

## 🎯 Capacidades

| Categoría | Cantidad | Detalles |
|-----------|----------|----------|
| **Exploits** | 18 | 16 con RCE |
| **EDR Bypass** | 9 técnicas | >85% evasión |
| **C2 Protocols** | 5 | Con fallback automático |
| **Priv Escalation** | 20+ | Windows + Linux |
| **Credential Sources** | 9+ | LSASS, SAM, browsers, cloud |
| **Persistence** | 15+ | Registry, tasks, services |
| **Lateral Movement** | 9 | PsExec, WMI, Pass-the-Hash |

---

## ⚠️ Seguridad y Uso Responsable

### ⚠️ ADVERTENCIA CRÍTICA
**SOLO PARA USO AUTORIZADO EN:**
- Operaciones de red team autorizadas
- Pentesting con permiso escrito
- Entornos de laboratorio controlados
- Investigación de seguridad ética

**ILEGAL SIN AUTORIZACIÓN EXPLÍCITA**

### Kill Switches
- Código manual de emergencia
- Dead man's switch
- Geofencing
- Runtime limits
- Max infections
- Auto-destruct

---

## 📚 Documentación

- `README.md` - Este archivo
- `SECURITY_GUIDE.md` - Guía de seguridad y uso responsable
- `walkthrough.md` - Documentación completa del sistema (en `.gemini/`)

---

## 🔧 Configuración

### Archivos de Configuración
- `config.yaml` - Configuración por defecto
- `config_simulation.yaml` - Modo simulación (seguro)
- `config_test.yaml` - Modo test (limitado)
- `config_aggressive.yaml` - Modo aggressive (máximo)

### Personalización
Edita los archivos YAML para ajustar:
- Rangos de red a escanear
- Exploits habilitados
- Configuración de C2
- Límites de seguridad
- Parámetros de ML

---

## 🎓 Casos de Uso

### Red Team Operations
- Evaluación de seguridad de red
- Simulación de ataques APT
- Testing de respuesta a incidentes
- Validación de controles de seguridad

### Pentesting
- Evaluación de vulnerabilidades
- Testing de segmentación de red
- Validación de EDR/AV
- Auditoría de configuraciones

### Research
- Desarrollo de técnicas de evasión
- Análisis de comportamiento de malware
- Machine Learning en ciberseguridad
- Detección de amenazas

---

## 📈 Comparación

| Herramienta | Precio | Auto-Propagación | ML/IA | EDR Bypass |
|-------------|--------|------------------|-------|------------|
| **ML Worm v2.0** | **GRATIS** | ✅ | ✅ | ✅ (9) |
| Metasploit | Gratis/Pro | ❌ | ❌ | Limitado |
| Cobalt Strike | $3,500/año | ❌ | ❌ | ✅ |
| Empire | Gratis | ❌ | ❌ | ✅ |

---

## 🤝 Contribuciones

Este es un proyecto de investigación de seguridad. Las contribuciones son bienvenidas para:
- Nuevos módulos de explotación
- Técnicas de evasión mejoradas
- Optimizaciones de ML
- Corrección de bugs
- Documentación

---

## 📄 Licencia

Solo para uso educativo y de investigación de seguridad autorizada.

---

## ⚡ Soporte

Para preguntas sobre uso autorizado y ético de esta herramienta, consulta `SECURITY_GUIDE.md`.

---

**Desarrollado para investigación de seguridad y operaciones de red team autorizadas.**

**⚠️ El uso no autorizado es ilegal y puede resultar en consecuencias legales graves.**
