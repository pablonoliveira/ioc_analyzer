IOC Analyzer - Blue Team
Sistema profissional para análise e gerenciamento de Indicadores de Comprometimento (IOCs) voltado a times de Segurança Cibernética e Blue Team.

✨ Funcionalidades
Análise automática de logs com detecção de IPs, domínios, URLs e hashes maliciosos

Verificação de reputação automática via AbuseIPDB (IPs) e VirusTotal (domínios, URLs, hashes)

Classificação instantânea dos IOCs (Malicioso, Suspeito, Não Malicioso)

CRUD completo e interface web moderna para gestão dos IOCs

Exportação de IOCs em JSON

Dados e modificações persistentes (não perde dados ao reiniciar)

Suporte à exportação e revisão rápida dos indicadores

📋 Requisitos
Python 3.8+

Flask

Requests

python-dotenv

AbuseIPDB API Key

VirusTotal API Key

🛠 Instalação
Clone o repositório:

bash
git clone https://github.com/pablonoliveira/ioc_analyzer.git
cd ioc_analyzer
Crie e ative um ambiente virtual (opcional e recomendado):

bash
python -m venv env
# Ative no Windows:
.\env\Scripts\activate
# Ou no Linux/Mac:
source env/bin/activate
Instale as dependências:

bash
pip install -r requirements.txt
Configure as chaves de API:

Crie um arquivo .env na raiz do projeto, usando ioc/.env.example como modelo:

text
ABUSEIPDB_KEY=sua_chave_abuseipdb
VIRUSTOTAL_API_KEY=sua_chave_virustotal
Nunca faça commit do seu .env! Ele já está protegido no .gitignore.

🚀 Executando a aplicação
bash
python webapp.py
Upload de Logs: http://127.0.0.1:5000/

Gerenciar IOCs: http://127.0.0.1:5000/crud

📁 Estrutura do Projeto
text
ioc_analyzer/
├── ioc/                 # Integrações com AbuseIPDB/VirusTotal
├── parsers/             # Parser de logs para extração de IOCs
├── templates/           # Templates HTML (painel web CRUD)
├── utils/               # Utilidades e logger
├── data/                # Banco de dados dos IOCs (persistente)
├── requirements.txt     # Dependências do projeto
├── webapp.py            # Servidor Flask principal
└── README.md
🔒 Segurança
Suas chaves de API ficam sempre no .env (excluído do controle de versão).

As chaves devem ser obtidas em:

AbuseIPDB

VirusTotal

📝 Licença
GPL-3.0. Projeto aberto para fins educacionais e profissionais de Blue Team.

🤝 Contribuições
Contribuições são bem-vindas! Abra issues ou pull requests para sugerir melhorias.

👤 Autor
Pablo Nunes de Oliveira
Analista de Segurança da Informação | Blue Team
LinkedIn | Email