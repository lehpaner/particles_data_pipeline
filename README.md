# TSI Particle Counter — FastAPI WebApp

Porta Python del progetto C# **TrakProLiteClassLibrary** per strumenti TSI (serie 9xxx).  
Legge i dati via **Modbus TCP**, li salva in **SQLite** e li espone via **FastAPI REST API**.

---

## Struttura

```
ttsipy/
├── main.py          # FastAPI app (endpoints, background sync)
├── tsi_modbus.py    # Client Modbus TCP (porta del C# TSI_IPCommunication + ModbusInterpreter)
├── database.py      # SQLite layer (schema, CRUD)
├── requirements.txt
└── README.md
```

### Schema SQLite (`tsi_data.db`)

| Tabella     | Contenuto                                    |
|-------------|----------------------------------------------|
| `devices`   | Strumenti (ip, modello, seriale, canali...)  |
| `records`   | Campioni (1 riga = 1 misurazione)            |
| `channels`  | Conteggi particelle per canale per campione  |
| `sync_log`  | Storico delle sincronizzazioni               |

---

## Installazione e avvio

```bash
# 1. Crea cartella di destinazione
mkdir C:\Users\Sasa\Desktop\ttsipy
# (o su Linux/Mac: mkdir ~/ttsipy)

# 2. Copia i file in quella cartella

# 3. Installa dipendenze (Python 3.10+)
pip install -r requirements.txt

# 4. Avvia il server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 5. Apri nel browser
#    http://localhost:8000        → pagina home con elenco endpoint
#    http://localhost:8000/docs   → Swagger UI interattivo
```

---

## Utilizzo

### 1. Connetti uno strumento e leggi tutti i dati

```bash
curl -X POST http://localhost:8000/connect \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.50", "port": 502, "max_records": 500}'
```

Risposta:
```json
{
  "message": "Sync avviata in background",
  "device_id": 1,
  "stream_url": "/devices/1/sync/stream"
}
```

### 2. Monitora il progresso (Server-Sent Events)

```javascript
// nel browser
const es = new EventSource('/devices/1/sync/stream');
es.onmessage = e => console.log(JSON.parse(e.data));
```

### 3. Leggi i campioni

```bash
# ultimi 100 campioni
curl http://localhost:8000/devices/1/records

# con filtro data e paginazione
curl "http://localhost:8000/devices/1/records?from_ts=2024-01-01T00:00:00&limit=50&skip=0"
```

### 4. Canali di un campione

```bash
curl http://localhost:8000/devices/1/records/42/channels
```

### 5. Statistiche aggregate

```bash
curl http://localhost:8000/devices/1/stats
```

### 6. Risincronizza (solo nuovi record)

```bash
curl -X POST http://localhost:8000/devices/1/sync \
  -H "Content-Type: application/json" \
  -d '{"max_records": 200}'
```

---

## Come funziona il protocollo TSI Modbus TCP

Lo strumento TSI espone un server Modbus TCP sulla porta **502**.

| Registro (1-based) | Contenuto                    |
|--------------------|------------------------------|
| 40003–40010        | Modello (8 reg, 16 char)     |
| 40011–40018        | Numero di serie              |
| 41003–41062        | Device info (canali, date..) |
| 41078–41079        | Indice record da leggere     |
| 42001–42002        | Numero totale campioni       |
| 42005–42122        | Payload record corrente      |
| 43001–43017        | Location label               |
| 43018–43034        | Recipe label                 |

Ogni record contiene:
- Timestamp, numero record, location
- Flow rate, sample time, count mode
- Conteggi particelle per 16 canali (dimensioni in µm)
- Misure ambientali opzionali: temperatura, umidità, velocità aria, CO₂

---

## Note tecniche

- Il byte order del protocollo TSI è **big-endian** con swap a coppie (come nel codice C# originale).
- La webapp usa **BackgroundTasks** di FastAPI per la sync: risponde subito e legge lo strumento in background.
- Il DB usa `INSERT OR IGNORE` su `(device_id, rec_num)` per evitare duplicati nelle resync.
- Il WAL di SQLite permette letture concorrenti durante la scrittura.
