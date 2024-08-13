# Script para Captura e Criação de Eventos de IOCs no MISP
Este script realiza a captura de IOCs (Indicators of Compromise) de uma API da trendmicro `/v3.0/threatintel/suspiciousObjects`, filtra os dados conforme certas condições e cria eventos correspondentes no MISP (Malware Information Sharing Platform).

# Funcionamento básico do script
1) Filtra IOCs que não têm a descrição "Trend Block" ou "Trend Sweep".
2) Cria um evento no MISP e adiciona a tag "Trend Sweep" ao evento.
3) Adiciona os atributos de IOC no evento criado no MISP.

## Requisitos
As bibliotecas utilizadas neste script estão listadas no arquivo `requirements.txt`. Para instalá-las, utilize o comando:
```
pip install -r requirements.txt
```

## Condições logicas 

``` 
linha 68: if description in ['Trend Block', 'Trend Sweep']:
```
Ignora qualquer evento que contém as tags `Trend Block` e `Trend Sweep`


### Nota
Certifique-se de ajustar as variáveis `misp_url`, `misp_key`, e `token` com as informações apropriadas para sua implementação.
 - [ ] URL do MISP
 - [ ] Chave de API MISP
 - [ ] Chave de API TrendMicro


### Referências
Para obter mais informações sobre as integrações utilizadas no projeto, consulte a documentação oficial.
- **[Automation trendmicro](https://automation.trendmicro.com/xdr/api-v3#tag/Suspicious-Object-List)**
- **[PyMISP](https://pymisp.readthedocs.io/en/latest/)**

