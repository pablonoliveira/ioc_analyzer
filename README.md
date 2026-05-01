# IOC Analyzer - Blue Team Platform

Plataforma completa de análise e correlação de **Indicadores de Comprometimento (IoCs)** e **Vulnerabilidades (CVEs)** para equipes de **Blue Team**, **Threat Intelligence**, **DFIR** e **Resposta a Incidentes**.[file:260][file:83]

## Visão Geral

O IOC Analyzer centraliza a consulta, classificação, armazenamento e visualização de IoCs e CVEs em uma interface web construída com Flask, com painéis dedicados para dashboard, upload de logs, análise de IoCs e pesquisa de vulnerabilidades.[file:260][file:83]

A aplicação permite enriquecer dados com múltiplas fontes externas, como AbuseIPDB, VirusTotal, NVD, CIRCL e CISA KEV, além de manter banco local em JSON para persistência das análises.[file:260][file:83]

## Site em produção

A instância publicada da aplicação está disponível em [iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app).[file:260]

### Endpoints principais

- Dashboard: [https://iocanalyzer-production.up.railway.app/](https://iocanalyzer-production.up.railway.app/)[file:83]
- Upload de Logs: [https://iocanalyzer-production.up.railway.app/upload](https://iocanalyzer-production.up.railway.app/upload)[file:83][file:242]
- IOC Panel: [https://iocanalyzer-production.up.railway.app/ioc](https://iocanalyzer-production.up.railway.app/ioc)[file:83][file:241]
- CVE Panel: [https://iocanalyzer-production.up.railway.app/cve](https://iocanalyzer-production.up.railway.app/cve)[file:83][file:239]

> **Observação:** em produção, recomenda-se executar a aplicação com `debug=False`, variáveis sensíveis protegidas e servidor WSGI apropriado para ambiente exposto.[file:260][file:83]

## Funcionalidades

### Dashboard Interativo

- Visualização consolidada de IoCs e CVEs.[file:260][file:83]
- Estatísticas em tempo real.[file:260][file:83]
- Gráficos interativos com Chart.js.[file:260]
- Distribuição de IoCs por tipo e severidade.[file:83]
- Contador de ameaças críticas.[file:260][file:83]

### Gerenciamento de IoCs

- Busca rápida de IPs, domínios, URLs e hashes.[file:260][file:83]
- CRUD básico de IoCs com armazenamento local em JSON.[file:260][file:83]
- Classificação por severidade (`Critical`, `High`, `Medium`, `Low`).[file:260][file:83]
- Filtro por tipo e severidade no painel de IoCs.[file:83][file:241]
- Consulta a fontes externas, com destaque para AbuseIPDB e VirusTotal.[file:260][file:83]
- Exibição opcional de **signature info** do VirusTotal para hashes consultados, quando disponível.[file:260][file:83]
- Consulta avançada de histórico de reports no AbuseIPDB para IPs, sujeita à cota da API.[file:260][file:83]

### Gerenciamento de CVEs

- Busca de CVEs em múltiplas fontes: NVD, CIRCL e CISA KEV.[file:260][file:83]
- Busca por CVE ID específico.[file:260][file:83]
- Coleta automática de CVEs recentes das últimas 24 horas.[file:260][file:83]
- Tradução automática para PT-BR quando `googletrans` está instalado.[file:260][file:83]
- Identificação de CVEs exploradas ativamente com base no catálogo CISA KEV.[file:260][file:83]
- Armazenamento local e paginação no painel de CVEs.[file:260][file:239]

### Upload e Parsing de Logs

- Upload com drag-and-drop.[file:260][file:242]
- Suporte a arquivos `.log`, `.txt`, `.csv`, `.xlsx` e `.json` no backend.[file:83]
- Extração automática de IoCs a partir de logs.[file:260][file:83]
- Enriquecimento automático durante o processamento, conforme o tipo de IOC e disponibilidade de APIs.[file:83]
- Salvamento posterior no banco local por fluxo do painel/aplicação.[file:260][file:83]

### Interface e Navegação

- Navegação consistente entre Dashboard, Upload, IOC Panel e CVE Panel.[file:260][file:239][file:241][file:242]
- Interface responsiva para desktop e mobile.[file:260]
- Paginação nas tabelas principais.[file:260][file:239][file:241]
- Layout com foco operacional para análise rápida.[file:239][file:241][file:242]

## Novidades e correções aplicadas

### Versão 3.1.1

- Padronização da severidade de IoCs e CVEs em inglês: `Low`, `Medium`, `High` e `Critical`.[file:260]
- Paginação com seleção direta de páginas no painel de IoCs e no painel de CVEs.[file:260][file:239][file:241]
- Ajustes visuais em badges, espaçamento e rodapé.[file:260][file:239][file:241][file:242]
- Refatorações internas sem alteração de APIs públicas da aplicação.[file:260]

### Correções relevantes já refletidas no projeto

- Leitura antecipada de variáveis do `.env` com `load_dotenv()` no início da aplicação.[file:83]
- Tradução automática protegida contra erro de importação do `googletrans` e falhas de tradução.[file:83]
- Tratamento para banco de CVEs vazio ou corrompido.[file:260][file:83]
- Filtros por query string no painel de IoCs.[file:83][file:241]
- Suporte ampliado a extensões de upload no backend.[file:83]
- Ajustes na ordenação e persistência de CVEs e IoCs.[file:83]

## Estrutura do Projeto

```text
IOC_ANALYZER/
├── .venv314/
├── data/
│   ├── iocdatabase.json
│   └── cvedatabase.json
├── docs/
├── ioc/
│   ├── abuseipdb_client.py
│   ├── alienvault_client.py
│   ├── cisa_kev_client.py
│   ├── circl_cve_client.py
│   ├── nvd_cve_client.py
│   ├── url_checker.py
│   └── virustotal_client.py
├── parsers/
├── templates/
│   ├── dashboard.html
│   ├── upload.html
│   ├── ioc_panel.html
│   └── cve_panel.html
├── uploads/
├── utils/
├── .env
├── .gitignore
├── app.py
├── LICENSE
├── README.md
└── requirements.txt
```

> A estrutura acima representa a organização funcional do projeto com base nos arquivos anexados e no conteúdo atual do repositório.[file:260][file:83]

## Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/pablonoliveira/ioc_analyzer.git
cd ioc_analyzer
```

### 2. Criar ambiente virtual

```bash
python -m venv .venv
```

#### Windows

```powershell
.\.venv\Scripts\activate
```

#### Linux/macOS

```bash
source .venv/bin/activate
```

### 3. Instalar dependências

```bash
pip install -r requirements.txt
```

## Configuração

Crie um arquivo `.env` na raiz do projeto:

```env
ABUSEIPDB_API_KEY=sua_chave_aqui
VIRUSTOTAL_API_KEY=sua_chave_aqui
FLASK_DEBUG=False
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

### Observações

- As APIs externas são opcionais; sem elas, parte do enriquecimento ficará limitada.[file:260][file:83]
- A tradução automática depende de `googletrans==4.0.0-rc1`.[file:260][file:83]
- Para produção, utilize `FLASK_DEBUG=False`.[file:260][file:83]

## Execução local

```bash
python app.py
```

Saída esperada:

```text
============================================================
🛡️  IOC Analyzer - Blue Team Platform
============================================================
✅ Servidor iniciado
📊 Dashboard: http://localhost:5000
📤 Upload: http://localhost:5000/upload
🔍 IOC Panel: http://localhost:5000/ioc
🛡️  CVE Panel: http://localhost:5000/cve
============================================================
```

## Acesso

### Ambiente local

- Dashboard: [http://localhost:5000](http://localhost:5000)[file:260][file:83]
- Upload: [http://localhost:5000/upload](http://localhost:5000/upload)[file:260][file:83]
- IOC Panel: [http://localhost:5000/ioc](http://localhost:5000/ioc)[file:260][file:83]
- CVE Panel: [http://localhost:5000/cve](http://localhost:5000/cve)[file:260][file:83]

### Ambiente em produção

- Base URL: [https://iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app)[file:260]
- A aplicação está publicada para acesso web externo por meio do Railway.[file:260]

## Dependências principais

- Flask.[file:260][file:19]
- requests.[file:260][file:19]
- python-dotenv.[file:260][file:19]
- pandas.[file:83]
- openpyxl.[file:260]
- `googletrans==4.0.0-rc1`.[file:260]
- `abuseipdb-wrapper`.[file:260][file:19]
- `virustotal-python`.[file:260][file:19]

## APIs suportadas

| API | Descrição | Status |
|---|---|---|
| NVD | National Vulnerability Database | Integrado [file:260][file:83] |
| CIRCL | CVE Search | Integrado [file:260][file:83] |
| CISA KEV | Known Exploited Vulnerabilities | Integrado [file:260][file:83] |
| AbuseIPDB | Reputação de IP | Requer API Key [file:260][file:83] |
| VirusTotal | Análise de hash, IP, domínio e URL | Requer API Key [file:260][file:83] |

## Uso básico

### 1. Dashboard

Acesse o dashboard para visualizar totais, distribuição por severidade e visão consolidada de IoCs e CVEs.[file:260][file:83]

### 2. Upload de logs

1. Acesse `/upload`.[file:242]
2. Envie arquivos suportados para análise.[file:242][file:83]
3. Aguarde a extração dos IoCs.[file:242][file:83]
4. Revise os resultados enriquecidos exibidos pela interface.[file:242][file:83]

### 3. Gerenciar IoCs

1. Acesse `/ioc`.[file:241]
2. Consulte um IOC manualmente ou filtre registros do banco local.[file:241][file:83]
3. Salve, remova e revise a classificação retornada pelas integrações.[file:241][file:83]

### 4. Gerenciar CVEs

1. Acesse `/cve`.[file:239]
2. Busque um CVE específico ou solicite CVEs das últimas 24 horas.[file:239][file:83]
3. Salve resultados e acompanhe severidade, score CVSS e indicadores de exploração ativa.[file:239][file:83]

## Segurança

### Importante

- Não exponha a aplicação em produção sem controles adicionais de segurança.[file:260]
- Não mantenha `debug=True` em ambiente publicado.[file:260][file:83]
- Proteja chaves de API no ambiente de execução.[file:260][file:83]
- Recomenda-se uso de autenticação, proxy reverso e HTTPS quando aplicável.[file:260]

### Recomendações para produção

- Executar com servidor WSGI, como Gunicorn.[file:260]
- Desabilitar debug mode.[file:260][file:83]
- Adicionar autenticação e controle de acesso.[file:260]
- Implementar logs de auditoria e proteção de borda.[file:260]

## Roadmap

### v4.0 - Autenticação e Segurança

- Sistema de login e senha.[file:260]
- Autenticação JWT.[file:260]
- Níveis de permissão (`Admin`, `Analyst`, `Viewer`).[file:260]
- Logs de auditoria.[file:260]

### v4.1 - Integrações Avançadas

- Integração com MISP.[file:260]
- Integração com TheHive.[file:260]
- Suporte a STIX/TAXII.[file:260]
- Exportação para SIEM.[file:260]

## Changelog

### v2.0 - 20/10/2025

- Primeira release estável.[file:260]

### v2.1 - 25/10/2025

**Novidades**
- Navegação consistente em todas as páginas.[file:260]
- Botão de upload de logs acessível de todas as páginas.[file:260]
- Interface modernizada.[file:260]
- Busca automática de CVEs das últimas 24 horas.[file:260]
- Dashboard com gráficos Chart.js interativos.[file:260]

**Correções**
- Rotas 404 corrigidas.[file:260]
- Comunicação entre páginas funcionando.[file:260]
- Endpoints atualizados.[file:260]

### v2.2 - 27/10/2025

**Correções**
- Correlação entre IoCs e CVEs.[file:260]
- Busca de CVEs relacionadas a IoCs.[file:260]
- Busca de IoCs relacionados a CVEs.[file:260]
- Dashboard de correlações.[file:260]

### v2.3 - 28/10/2025

**Correções**
- Validação reforçada dos tipos em campos críticos.[file:260]
- Tradução automática protegida contra erros de tipo e valores nulos.[file:260]
- CVEs duplicadas ou inválidas não são mais salvas no banco.[file:260]
- Proteção contra arquivos JSON vazios ou corrompidos.[file:260]
- Logs de debug adicionados para facilitar diagnóstico.[file:260]

### v3.0 - 20/11/2025

**Correções**
- Correção de exibição do histórico do AbuseIPDB.[file:260]
- Tratamento de listas e variáveis no backend.[file:260]
- Padronização do formato de datas.[file:260]

### v3.1.1 - 31/12/2025

- Melhoria na exibição de severidade de IoCs e CVEs.[file:260]
- Inclusão de paginação com seleção direta de página.[file:260]
- Ajustes visuais gerais.[file:260]
- Refatorações internas sem impacto nas APIs públicas.[file:260]

### Atualização de implantação

- Inclusão da URL pública de produção no Railway: [https://iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app).[file:260]
- Documentação revisada para refletir acesso web em produção e boas práticas mínimas de publicação.[file:260][file:83]

## Contribuindo

Contribuições são bem-vindas.

1. Faça um fork do projeto.[file:260]
2. Crie uma branch para sua feature: `git checkout -b feature/nova-funcionalidade`.[file:260]
3. Commit suas alterações: `git commit -m "Adiciona nova funcionalidade"`.[file:260]
4. Envie para o repositório remoto: `git push origin feature/nova-funcionalidade`.[file:260]
5. Abra um Pull Request.[file:260]

## Licença

Este projeto está licenciado sob a **GNU General Public License v3.0**.[file:260]

Em resumo:

- Uso comercial permitido.[file:260]
- Modificação permitida.[file:260]
- Distribuição permitida.[file:260]
- Uso privado permitido.[file:260]
- Copyleft obrigatório para trabalhos derivados.[file:260]
- Disponibilização do código-fonte quando aplicável.[file:260]

## Autor

**Pablo Nunes de Oliveira**[file:260]

- GitHub: [pablonoliveira](https://github.com/pablonoliveira)[file:260]
- LinkedIn: Pablo Oliveira.[file:260]
- Email: pabloliveir@gmail.com.[file:260]

## Agradecimentos

- Flask.[file:260]
- Chart.js.[file:260]
- NVD.[file:260]
- CISA.[file:260]
- CIRCL.[file:260]

## Suporte

Para suporte, abra uma issue no GitHub ou entre em contato pelos canais do autor.[file:260]

Se este projeto foi útil, considere dar uma estrela no repositório.[file:260]
