# IOC Analyzer - Blue Team Tool

Sistema de análise e gerenciamento de Indicadores de Comprometimento (IOCs) para times de Segurança Cibernética.

## 🛡️ Funcionalidades

- **Análise de Logs**: Upload de arquivos de log com detecção automática de IPs, URLs, domínios e hashes
- **Verificação de Reputação**: Integração com AbuseIPDB e VirusTotal
- **Classificação Automática**: Score de reputação convertido em vereditos (Malicioso, Suspeito, Não Malicioso)
- **CRUD de IOCs**: Gerenciamento completo de indicadores com interface web moderna
- **Salvamento Automático**: IOCs detectados são salvos automaticamente no banco de dados
- **Exportação**: Suporte para exportar IOCs em formato JSON

## 📋 Requisitos

- Python 3.8+
- Flask
- Requests
- python-dotenv
- AbuseIPDB API Key
- VirusTotal API Key

## 🚀 Instalação

1. Clone o repositório:
git clone https://github.com/SEU_USUARIO/ioc_analyzer.git
cd ioc_analyzer

2. Instale as dependências:
pip install -r requirements.txt

3. Configure as variáveis de ambiente:
Crie um arquivo `.env` na raiz do projeto:
ABUSEIPDB_KEY=sua_chave_aqui
VIRUSTOTAL_API_KEY=sua_chave_aqui

4. Execute a aplicação:
python webapp.py

5. Acesse no navegador:
- Upload de Logs: `http://127.0.0.1:5000/`
- Gerenciar IOCs: `http://127.0.0.1:5000/crud`

## 📁 Estrutura do Projeto

ioc_analyzer/
├── ioc/
│ ├── abuseipdb_client.py
│ ├── virustotal_client.py
│ └── url_checker.py
├── parsers/
│ └── log_parser.py
├── templates/
│ └── crud.html
├── utils/
│ └── logger.py
├── data/
├── .env
├── .gitignore
├── requirements.txt
├── webapp.py
└── README.md

## 🔒 Segurança

- **Nunca commit suas API keys!** Use sempre o arquivo `.env` e inclua-o no `.gitignore`
- As chaves de API devem ser obtidas nos sites oficiais:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com/)

## 📝 Licença

Este projeto é de código aberto para fins educacionais e profissionais de Blue Team.

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests.

## 👤 Autor

**Pablo Nuunes de Oliveira**
Analista de Cibersegurança | Blue Team

## 📧 Contato

- LinkedIn: (https://www.linkedin.com/in/pabloliveira/l)
- Email: pabloliveir@gmail.com