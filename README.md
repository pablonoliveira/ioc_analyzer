# 🛡️ IOC Analyzer - Blue Team Platform

[![Version](https://img.shields.io/badge/version-2.1-blue.svg)](https://github.com/pablonoliveira/ioc_analyzer)
[![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![Flask](https://img.shields.io/badge/flask-3.0+-red.svg)](https://flask.palletsprojects.com/)

Plataforma completa de análise e correlação de **Indicadores de Comprometimento (IoCs)** e **Vulnerabilidades (CVEs)** para equipes de **Blue Team** e **Threat Intelligence**.

---

## 🚀 Funcionalidades v2.1

### ✅ **Dashboard Interativo**
- 📊 Visualização consolidada de IoCs e CVEs
- 📈 Gráficos interativos com Chart.js
- 🎯 Estatísticas em tempo real
- 🔢 Contador de ameaças críticas

### ✅ **Gerenciamento de IoCs**
- 🔍 Busca rápida de IPs, Domínios, URLs e Hashes
- 💾 CRUD completo de IoCs
- 🏷️ Classificação por severidade (Critical, High, Medium, Low)
- 🔎 Filtro de busca em tempo real
- 📂 Organização por tipo (IP, Domain, URL, Hash)

### ✅ **Gerenciamento de CVEs**
- 🛡️ Busca em múltiplas fontes (NVD, CIRCL, CISA KEV)
- 📥 Buscar CVEs das últimas 24 horas automaticamente
- 🌐 Tradução automática para português (PT-BR)
- ⚠️ Detecção de CVEs exploradas ativamente (CISA KEV)
- 💾 Banco de dados local de CVEs
- 🔍 Busca e filtro de CVEs

### ✅ **Upload de Logs**
- 📤 Upload com drag-and-drop
- 📂 Suporte a múltiplos arquivos (.log, .txt, .csv)
- 🤖 Extração automática de IoCs
- 💾 Salvamento automático no banco de dados

### ✅ **Navegação e Interface**
- 🎨 Interface moderna com gradientes
- 📱 Totalmente responsiva
- 🔗 Navegação consistente entre páginas
- 🌐 Acesso via rede local (LAN)

---

## 🏗️ Estrutura do Projeto

```
ioc_analyzer/
├── data/
│   ├── ioc_database.json          # Banco de IoCs
│   └── cve_database.json          # Banco de CVEs
├── docs/
│   ├── DOCUMENTACAO.html          # Documentação completa
│   └── img/                       # Screenshots
├── ioc/
│   ├── abuseipdb_client.py        # Cliente AbuseIPDB
│   ├── virustotal_client.py       # Cliente VirusTotal
│   ├── cisa_kev_client.py         # Cliente CISA KEV
│   ├── circl_cve_client.py        # Cliente CIRCL
│   ├── nvd_cve_client.py          # Cliente NVD (novo!)
│   └── url_checker.py             # Checker de URLs
├── parsers/
│   └── log_parser.py              # Parser de logs
├── templates/
│   ├── dashboard.html             # Dashboard principal
│   ├── ioc_panel.html             # Painel de IoCs
│   ├── cve_panel.html             # Painel de CVEs
│   └── upload.html                # Upload de logs
├── uploads/                       # Pasta temporária de uploads
├── webapp.py                      # Aplicação Flask principal
├── .env.example                   # Exemplo de configuração
├── .gitignore                     # Arquivos ignorados
├── LICENSE                        # GNU GPL v3
├── README.md                      # Este arquivo
└── requirements.txt               # Dependências Python
```

---

## ⚙️ Instalação

### 1️⃣ **Clonar o Repositório**

```bash
git clone https://github.com/pablonoliveira/ioc_analyzer.git
cd ioc_analyzer
```

### 2️⃣ **Criar Ambiente Virtual**

```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate
```

### 3️⃣ **Instalar Dependências**

```bash
pip install -r requirements.txt
```

### 4️⃣ **Configurar APIs (Opcional)**

Crie um arquivo `.env` na raiz do projeto:

```env
# APIs de Threat Intelligence
ABUSEIPDB_API_KEY=sua_chave_aqui
VIRUSTOTAL_API_KEY=sua_chave_aqui

# Configurações do Servidor
FLASK_DEBUG=True
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

> **Nota**: As APIs são opcionais. O sistema funciona sem elas, mas com funcionalidades limitadas.

---

## 🚀 Execução

### **Iniciar o Servidor**

```bash
python webapp.py
```

**Saída esperada:**

```
============================================================
🛡️  IOC Analyzer - Blue Team Platform
============================================================
✅ Servidor iniciado
📊 Dashboard: http://localhost:5000
📤 Upload: http://localhost:5000/upload
🔍 IOC Panel: http://localhost:5000/ioc
🛡️  CVE Panel: http://localhost:5000/cve
============================================================
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.X.X:5000
```

### **Acessar via Navegador**

- **Local**: http://localhost:5000
- **Rede Local**: http://SEU_IP_LOCAL:5000

---

## 🌐 Acesso via Rede Local (LAN)

### **Configuração do Firewall (Windows)**

```powershell
# Executar como Administrador:
netsh advfirewall firewall add rule name="IOC Analyzer Port 5000" dir=in action=allow protocol=TCP localport=5000
```

### **Descobrir seu IP Local**

```bash
# Windows:
ipconfig

# Linux/Mac:
ifconfig
```

### **Acessar de Outros Dispositivos**

Conecte-se à mesma rede WiFi e acesse:

```
http://SEU_IP_LOCAL:5000
```

Exemplo: `http://192.168.254.83:5000`

---

## 📚 Dependências Principais

```
flask>=3.0.0
requests>=2.31.0
googletrans==4.0.0-rc1
werkzeug>=3.0.0
python-dotenv>=1.0.0
```

**Instalar todas:**

```bash
pip install -r requirements.txt
```

---

## 🛠️ APIs Suportadas

| API | Descrição | Status | Documentação |
|-----|-----------|--------|--------------|
| **NVD** | National Vulnerability Database | ✅ Integrado | [nvd.nist.gov](https://nvd.nist.gov) |
| **CIRCL CVE** | CVE Search | ✅ Integrado | [cve.circl.lu](https://cve.circl.lu) |
| **CISA KEV** | Known Exploited Vulnerabilities | ✅ Integrado | [cisa.gov/kev](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **AbuseIPDB** | IP Reputation | 🔧 Requer API Key | [abuseipdb.com](https://www.abuseipdb.com) |
| **VirusTotal** | Hash/URL Analysis | 🔧 Requer API Key | [virustotal.com](https://www.virustotal.com) |

---

## 📖 Uso Básico

### **1. Dashboard - Visão Geral**

Acesse `http://localhost:5000/` para visualizar:
- Total de IoCs e CVEs
- Contador de ameaças críticas
- Gráficos de distribuição por severidade
- Gráficos de IoCs por tipo

### **2. Upload de Logs**

1. Acesse `http://localhost:5000/upload`
2. Arraste arquivos `.log`, `.txt` ou `.csv`
3. Clique em "Analisar Logs"
4. IoCs serão extraídos e salvos automaticamente

### **3. Gerenciar IoCs**

1. Acesse `http://localhost:5000/ioc`
2. Adicione IoCs manualmente ou via upload
3. Filtre e busque IoCs
4. Exclua ou atualize IoCs

### **4. Gerenciar CVEs**

1. Acesse `http://localhost:5000/cve`
2. Busque CVEs específicas (ex: CVE-2024-1234)
3. Busque CVEs das últimas 24h automaticamente
4. Visualize informações detalhadas
5. Salve CVEs no banco de dados local

---

## 🔐 Segurança

⚠️ **IMPORTANTE**:
- Este servidor é projetado para **uso em rede local confiável**
- **NÃO exponha à internet** sem proteção adequada
- Não possui autenticação por padrão
- Debug mode deve ser desabilitado em produção
- Não possui HTTPS por padrão

**Recomendações para Produção:**
- Adicionar autenticação (login/senha)
- Usar HTTPS com certificado SSL
- Desabilitar debug mode (`debug=False`)
- Usar servidor WSGI (Gunicorn, uWSGI)
- Configurar firewall adequadamente

---

## 🗺️ Roadmap (Próximas Versões)

### **v2.2 - Correlação IOC ↔ CVE**
- [ ] Correlacionar IoCs com CVEs automaticamente
- [ ] Buscar CVEs relacionadas a IoCs
- [ ] Buscar IoCs relacionados a CVEs
- [ ] Dashboard de correlações

### **v3.0 - Autenticação e Segurança**
- [ ] Sistema de login/senha
- [ ] Autenticação JWT
- [ ] Níveis de permissão (Admin, Analyst, Viewer)
- [ ] Logs de auditoria

### **v3.1 - Integrações Avançadas**
- [ ] MISP Integration
- [ ] TheHive Integration
- [ ] STIX/TAXII Support
- [ ] Exportação para SIEM

---

## 📝 Changelog

### **v2.1 - 25/10/2025**
✨ **Novidades:**
- Navegação consistente em todas as páginas
- Botão "Upload de Logs" acessível de todas as páginas
- Interface modernizada com gradientes
- Buscar CVEs das últimas 24h automaticamente
- Dashboard com gráficos Chart.js interativos

🐛 **Correções:**
- Rotas 404 corrigidas
- Comunicação entre páginas funcionando
- API endpoints atualizados

### **v2.0 - 20/10/2025**
✨ **Primeira Release Estável**

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona NovaFuncionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abra um Pull Request

---

## 📄 Licença

Este projeto está licenciado sob a **GNU General Public License v3.0**. 

Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

**Em resumo:**
- ✅ Uso comercial permitido
- ✅ Modificação permitida
- ✅ Distribuição permitida
- ✅ Uso privado permitido
- ⚠️ **Copyleft** - Trabalhos derivados devem usar a mesma licença
- ⚠️ **Código-fonte** - Código-fonte deve ser disponibilizado

---

## 👤 Autor

**Pablo Oliveira**
- GitHub: [@pablonoliveira](https://github.com/pablonoliveira)
- LinkedIn: [Pablo Oliveira](https://linkedin.com/in/pabloliveir)
- Email: pabloliveir@gmail.com

---

## 🙏 Agradecimentos

- [Flask](https://flask.palletsprojects.com/) - Framework web
- [Chart.js](https://www.chartjs.org/) - Biblioteca de gráficos
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [CISA](https://www.cisa.gov/) - Cybersecurity and Infrastructure Security Agency
- [CIRCL](https://www.circl.lu/) - Computer Incident Response Center Luxembourg

---

## 📞 Suporte

Para suporte, abra uma [issue](https://github.com/pablonoliveira/ioc_analyzer/issues) no GitHub ou entre em contato via email.

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**