from fastapi import FastAPI, HTTPException, Depends
import uvicorn
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import db
import logging
import humanize
import qrcode
import io
import base64
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import os
import json
import aiohttp
import pytz

app = FastAPI(title="WireGuard VPN Manager API",
             description="API для управления VPN клиентами WireGuard",
             version="1.0.0")

# Включаем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Модели данных
class ClientCreate(BaseModel):
    username: str
    expiration: Optional[datetime] = None
    traffic_limit: Optional[str] = None
    ipv6: bool = False

class ClientUpdate(BaseModel):
    expiration: Optional[datetime] = None
    traffic_limit: Optional[str] = None

class ClientResponse(BaseModel):
    username: str
    config: str
    qr_code: str
    token: str

class ClientInfo(BaseModel):
    username: str
    public_key: str
    created_at: datetime
    expiration: Optional[datetime] = None
    traffic_limit: Optional[str] = None
    traffic_used: Optional[str] = None
    is_active: bool

class ConnectionInfo(BaseModel):
    ip: str
    timestamp: str
    isp: str

class IPInfo(BaseModel):
    country: str
    countryCode: str
    region: str
    regionName: str
    city: str
    zip: str
    lat: float
    lon: float
    timezone: str
    isp: str
    org: str
    as_: str = None
    hosting: bool

def generate_qr_code(config: str) -> str:
    """Генерирует QR код из конфигурации"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(config)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Конвертируем изображение в base64
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_str = base64.b64encode(img_buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def get_client_token(config: str) -> str:
    """Генерирует токен из конфигурации для Amnezia"""
    # Здесь должна быть логика генерации токена в формате Amnezia
    # Пока возвращаем закодированную конфигурацию как пример
    return base64.b64encode(config.encode()).decode()

# Endpoints
@app.post("/clients/", response_model=ClientResponse)
async def create_client(client: ClientCreate):
    """Создать нового VPN клиента"""
    try:
        # Создаем клиента
        client_id = db.root_add(client.username, client.ipv6)
        
        # Устанавливаем срок действия и лимит трафика если указаны
        if client.expiration or client.traffic_limit:
            db.set_user_expiration(
                client.username,
                client.expiration,
                client.traffic_limit
            )
        
        # Получаем конфигурацию клиента
        config_path = f"users/{client.username}/{client.username}.conf"
        if not os.path.exists(config_path):
            raise HTTPException(status_code=500, detail="Failed to create client configuration")
            
        with open(config_path, 'r') as f:
            config = f.read()
            
        # Генерируем QR код и токен
        qr_code = generate_qr_code(config)
        token = get_client_token(config)
        
        return ClientResponse(
            username=client.username,
            config=config,
            qr_code=qr_code,
            token=token
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/clients/", response_model=List[ClientInfo])
async def list_clients():
    """Получить список всех клиентов"""
    try:
        clients = db.get_active_list()
        result = []
        
        for client in clients:
            username = client['userData']
            expiration = db.get_user_expiration(username)
            traffic_limit = db.get_user_traffic_limit(username)
            traffic = db.read_traffic(username)
            
            result.append(ClientInfo(
                username=username,
                public_key=client['clientId'],
                created_at=datetime.now(),  # В текущей реализации нет сохранения даты создания
                expiration=expiration,
                traffic_limit=traffic_limit,
                traffic_used=humanize.naturalsize(traffic['total']) if traffic else None,
                is_active=True
            ))
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/clients/{username}/config", response_model=ClientResponse)
async def get_client_config(username: str):
    """Получить конфигурационный файл клиента"""
    try:
        config_path = f"users/{username}/{username}.conf"
        if not os.path.exists(config_path):
            raise HTTPException(status_code=404, detail="Client configuration not found")
            
        with open(config_path, 'r') as f:
            config = f.read()
            
        qr_code = generate_qr_code(config)
        token = get_client_token(config)
        
        return ClientResponse(
            username=username,
            config=config,
            qr_code=qr_code,
            token=token
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/clients/{username}")
async def delete_client(username: str):
    """Удалить клиента"""
    try:
        db.deactive_user_db(username)
        return {"message": f"Client {username} successfully deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/clients/{username}", response_model=ClientInfo)
async def update_client(username: str, client_update: ClientUpdate):
    """Обновить параметры клиента (срок действия и лимит трафика)"""
    try:
        # Проверяем существование клиента
        clients = db.get_active_list()
        client_exists = False
        client_info = None
        
        for client in clients:
            if client['userData'] == username:
                client_exists = True
                client_info = client
                break
                
        if not client_exists:
            raise HTTPException(status_code=404, detail="Client not found")
            
        # Обновляем параметры
        db.set_user_expiration(
            username,
            client_update.expiration,
            client_update.traffic_limit
        )
        
        # Получаем обновленную информацию
        traffic = db.read_traffic(username)
        return ClientInfo(
            username=username,
            public_key=client_info['clientId'],
            created_at=datetime.now(),
            expiration=client_update.expiration,
            traffic_limit=client_update.traffic_limit,
            traffic_used=humanize.naturalsize(traffic['total']) if traffic else None,
            is_active=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Новые эндпоинты
@app.get("/client/{username}/connections", response_model=List[ConnectionInfo])
async def get_client_connections(username: str):
    """Получить информацию о последних подключениях клиента"""
    file_path = os.path.join('files', 'connections', f'{username}_ip.json')
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Нет данных о подключениях пользователя")
    
    try:
        with open(file_path, 'r') as f:
            data = json.loads(f.read())
        
        sorted_ips = sorted(data.items(), key=lambda x: datetime.strptime(x[1], '%d.%m.%Y %H:%M'), reverse=True)
        last_connections = sorted_ips[:5]
        
        result = []
        for ip, timestamp in last_connections:
            async with aiohttp.ClientSession() as session:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,isp"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        isp_data = await resp.json()
                        isp = isp_data.get('isp', 'Unknown ISP')
                    else:
                        isp = 'Unknown ISP'
            
            result.append(ConnectionInfo(
                ip=ip,
                timestamp=timestamp,
                isp=isp
            ))
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/client/{username}/ip-info", response_model=IPInfo)
async def get_client_ip_info(username: str):
    """Получить подробную информацию об IP клиента"""
    active_clients = db.get_active_list()
    active_info = next((ac for ac in active_clients if ac[0] == username), None)
    
    if not active_info:
        raise HTTPException(status_code=404, detail="Нет информации о подключении пользователя")
    
    endpoint = active_info[3]
    ip_address = endpoint.split(':')[0]
    
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://ip-api.com/json/{ip_address}?fields=message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting"
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'message' in data:
                        raise HTTPException(status_code=400, detail=data['message'])
                    return IPInfo(**data)
                else:
                    raise HTTPException(status_code=resp.status, detail="Ошибка при запросе к IP API")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/client/{username}/traffic")
async def update_client_traffic(username: str, incoming_bytes: int, outgoing_bytes: int):
    """Обновить информацию о трафике клиента"""
    try:
        await update_traffic(username, incoming_bytes, outgoing_bytes)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/client/{username}/traffic")
async def get_client_traffic(username: str):
    """Получить информацию о трафике клиента"""
    try:
        traffic_info = await read_traffic(username)
        return traffic_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/client/{username}/deactivate")
async def deactivate_client(username: str):
    """Деактивировать клиента"""
    try:
        await deactivate_user(username)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def update_traffic(username: str, incoming_bytes: int, outgoing_bytes: int):
    """Обновляет информацию о трафике пользователя"""
    try:
        traffic_file = os.path.join('files', 'traffic', f'{username}_traffic.json')
        os.makedirs(os.path.dirname(traffic_file), exist_ok=True)
        
        current_data = {}
        if os.path.exists(traffic_file):
            with open(traffic_file, 'r') as f:
                current_data = json.loads(f.read())
        
        current_data['incoming'] = incoming_bytes
        current_data['outgoing'] = outgoing_bytes
        current_data['last_update'] = datetime.now().strftime('%d.%m.%Y %H:%M')
        
        with open(traffic_file, 'w') as f:
            json.dump(current_data, f)
            
    except Exception as e:
        logging.error(f"Ошибка при обновлении трафика для {username}: {e}")
        raise

async def read_traffic(username: str):
    """Читает информацию о трафике пользователя"""
    try:
        traffic_file = os.path.join('files', 'traffic', f'{username}_traffic.json')
        if not os.path.exists(traffic_file):
            return {
                'incoming': 0,
                'outgoing': 0,
                'last_update': None
            }
            
        with open(traffic_file, 'r') as f:
            data = json.loads(f.read())
            return data
            
    except Exception as e:
        logging.error(f"Ошибка при чтении трафика для {username}: {e}")
        raise

async def deactivate_user(username: str):
    """Деактивирует пользователя"""
    try:
        # Получаем текущую конфигурацию
        config = db.get_config()
        docker_container = config['docker_container']
        wg_config_file = config['wg_config_file']
        
        # Удаляем пользователя из WireGuard
        cmd = ["docker", "exec", docker_container, "wg-quick", "down", wg_config_file]
        subprocess.run(cmd, check=True)
        
        # Удаляем из базы данных
        db.deactive_user_db(username)
        
        # Перезапускаем WireGuard
        cmd = ["docker", "exec", docker_container, "wg-quick", "up", wg_config_file]
        subprocess.run(cmd, check=True)
        
    except Exception as e:
        logging.error(f"Ошибка при деактивации пользователя {username}: {e}")
        raise

if __name__ == "__main__":
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)
