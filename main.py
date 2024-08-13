import json
import requests
from datetime import datetime, timedelta
from collections import defaultdict
from pymisp import PyMISP, MISPEvent, MISPAttribute
from tabulate import tabulate

# Global
data_de_hoje = datetime.now().strftime('%Y-%m-%d')
log_data_iso = datetime.now().isoformat()

# API key MISP
misp_url = '' # Troque
misp_key = '' # troque
misp_verifycert = True
misp = PyMISP(misp_url, misp_key, misp_verifycert)

# API KEY TrenMicro Visio One
url_base = 'https://api.xdr.trendmicro.com'
url_path = '/v3.0/threatintel/suspiciousObjects'
token = '' # Troque


# Calcular data e hora há exatamente 24 horas atrás
current_datetime = datetime.utcnow()
start_datetime = current_datetime - timedelta(hours=24) # Troque o valor se necessario, ultiams 24 horas

# Formatar as datas no formato ISO 8601
startDateTime = start_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
endDateTime = current_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
 
query_params = {
    'orderBy': 'lastModifiedDateTime desc',
    'startDateTime': startDateTime,
    'endDateTime': endDateTime,
    'top': '100'
}

headers = {
    'Authorization': 'Bearer ' + token
}

def get_suspiciousObjects():
    data_with_description = defaultdict(list)
    no_description_iocs = []  # Lista para armazenar IOCs sem descrição
    events_created = []  # Lista para armazenar informações sobre eventos criados
    
    # Realizar a requisição na Trend
    response = requests.get(url_base + url_path, params=query_params, headers=headers)
    
    # Checa se a requisição foi feita com sucesso
    if response.status_code == 200 and response.headers.get('Content-Type', '') and len(response.content):
        print(f'{log_data_iso} - [INFO] - Get suspiciousObjects')
        parsed_data = json.loads(response.text)
        
        for item in parsed_data.get('items', []):
            ioc_type = item.get('type')
            value = next(iter(item.values()))  # Pega o primeiro valor
            description = item.get('description')
            riskLevel = item.get('riskLevel')
            scanAction = item.get('scanAction')
            lastModified = item.get('lastModified')
            expiredTime = item.get('expiredTime')
            hitException = item.get('hitException')
            
            # Primeiro IF: Ignorar se a descrição for 'Trend Block' ou 'Trend Sweep'
            if description in ['Trend Block', 'Trend Sweep']:
                print(f'{log_data_iso} - [WARNING] - IOC {value} possui a descrição: {description}, possivelmente já existe no MISP.')
                continue
            
            # Segundo IF: Adicionar IOC à lista correspondente se a descrição possui valor
            if description:
                data_with_description[description].append((ioc_type, value, riskLevel))
            else:
                # Caso contrário, adicionar IOC à lista de IOCs sem descrição
                no_description_iocs.append((ioc_type, value, riskLevel))
        
        # Criar eventos no MISP para IOCs com descrição
        for description, iocs in data_with_description.items():
            if iocs:
                my_event = MISPEvent()
                my_event.info = f'[TrendMicro] - Suspicious Object - {description}'  # INFO DO EVENTO
                my_event.threat_level_id = 1  # Severidade do evento no MISP
                my_event.analysis = 2  # Status da análise no MISP
                my_event.distribution = 1  # Distribuição
                
                # Criar evento no MISP
                created_event = misp.add_event(event=my_event, pythonify=True)
                misp.tag(created_event, 'Trend Send')
                if created_event:
                    event_id = created_event.id
                    num_iocs = len(iocs)
                    events_created.append({'event_id': event_id, 'description': description, 'num_iocs': num_iocs})
                    print(f"{log_data_iso} - [INFO] - Evento {event_id} criado no MISP")
                    for ioc_type, value, riskLevel in iocs:
                        attribute_type = map_ioc_type_to_misp(ioc_type)
                        attribute = MISPAttribute()
                        attribute.type = attribute_type
                        attribute.value = value
                        attribute.comment = f'riskLevel: {riskLevel}\n'
                        misp.add_attribute(event_id, attribute)
                        print(f"{log_data_iso} - [INFO] - [+] Adicionado atributo [{attribute_type}]: {value} ao evento {event_id}")
                else:
                    print(f"{log_data_iso} [ERROR] Falha ao criar evento para descrição: {description}.")
        
        # Criar evento para IOCs sem descrição
        if no_description_iocs:
            no_description_event = MISPEvent()
            no_description_event.info = '[TrendMicro] - Suspicious Object - Sem Descrição'
            no_description_event.threat_level_id = 1
            no_description_event.analysis = 2
            no_description_event.distribution = 1
            
            created_no_description_event = misp.add_event(event=no_description_event, pythonify=True)
            misp.tag(created_no_description_event, 'Trend Send')
            if created_no_description_event:
                event_id = created_no_description_event.id
                num_iocs = len(no_description_iocs)
                events_created.append({'event_id': event_id, 'description': 'Sem Descrição', 'num_iocs': num_iocs})
                print(f"{log_data_iso} - [INFO] - Evento {event_id} criado no MISP para IOCs sem descrição")
                for ioc_type, value, riskLevel in no_description_iocs:
                    attribute_type = map_ioc_type_to_misp(ioc_type)
                    attribute = MISPAttribute()
                    attribute.type = attribute_type
                    attribute.value = value
                    attribute.comment = f'riskLevel: {riskLevel}\n'
                    misp.add_attribute(event_id, attribute)
                    print(f"{log_data_iso} - [INFO] - [+] Adicionado atributo [{attribute_type}]: {value} ao evento {event_id}")
            else:
                print(f"{log_data_iso} - [ERROR] Falha ao criar evento para IOCs sem descrição.")
    else:
        print("erro na requisição")
    
    # Gerar o relatório de iocs importados 
    if events_created:
        print(f"\nRelatório de Eventos Criados: periodo {startDateTime} até: {endDateTime}")
        table = [{'Evento ID': e['event_id'], 'Descrição': e['description'], 'Número de IOCs': e['num_iocs']} for e in events_created]
        print(tabulate(table, headers='keys', tablefmt='pretty'))
    else:
        print("Nenhum evento foi criado.")

def map_ioc_type_to_misp(ioc_type):
    mapping = {
        'url': 'url',
        'domain': 'domain',
        'senderMailAddress': 'email-src',
        'ip': 'ip-src',
        'fileSha1': 'sha1',
        'fileSha256': 'sha256'
    }
    return mapping.get(ioc_type, 'unknown')

get_suspiciousObjects()
