# IOC Analyzer - Blue Team Platform

Plataforma completa de análise e correlação de **Indicadores de Comprometimento (IoCs)** e **Vulnerabilidades (CVEs)** para equipes de **Blue Team**, **Threat Intelligence**, **DFIR** e **Resposta a Incidentes**.

## Visão Geral

O IOC Analyzer centraliza a consulta, classificação, armazenamento e visualização de IoCs e CVEs em uma interface web construída com Flask, com painéis dedicados para dashboard, upload de logs, análise de IoCs e pesquisa de vulnerabilidades.

A aplicação permite enriquecer dados com múltiplas fontes externas, como AbuseIPDB, VirusTotal, NVD, CIRCL e CISA KEV, além de manter banco local em JSON para persistência das análises.

## Site em produção

A instância publicada da aplicação está disponível em [iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app).

### Endpoints principais

- Dashboard: [https://iocanalyzer-production.up.railway.app/](https://iocanalyzer-production.up.railway.app/)
- Upload de Logs: [https://iocanalyzer-production.up.railway.app/upload](https://iocanalyzer-production.up.railway.app/upload)[file:83]
- IOC Panel: [https://iocanalyzer-production.up.railway.app/ioc](https://iocanalyzer-production.up.railway.app/ioc)[file:83]
- CVE Panel: [https://iocanalyzer-production.up.railway.app/cve](https://iocanalyzer-production.up.railway.app/cve)[file:83]

> **Observação:** em produção, recomenda-se executar a aplicação com `debug=False`, variáveis sensíveis protegidas e servidor WSGI apropriado para ambiente exposto.

## Funcionalidades

### Dashboard Interativo

- Visualização consolidada de IoCs e CVEs.
- Estatísticas em tempo real.
- Gráficos interativos com Chart.js.
- Distribuição de IoCs por tipo e severidade.
- Contador de ameaças críticas.

### Gerenciamento de IoCs

- Busca rápida de IPs, domínios, URLs e hashes.
- CRUD básico de IoCs com armazenamento local em JSON.
- Classificação por severidade (`Critical`, `High`, `Medium`, `Low`).
- Filtro por tipo e severidade no painel de IoCs.
- Consulta a fontes externas, com destaque para AbuseIPDB e VirusTotal.
- Exibição opcional de **signature info** do VirusTotal para hashes consultados, quando disponível.
- Consulta avançada de histórico de reports no AbuseIPDB para IPs, sujeita à cota da API.

### Gerenciamento de CVEs

- Busca de CVEs em múltiplas fontes: NVD, CIRCL e CISA KEV.
- Busca por CVE ID específico.
- Coleta automática de CVEs recentes das últimas 24 horas.
- Tradução automática para PT-BR quando `deep-translato` está instalado.
- Identificação de CVEs exploradas ativamente com base no catálogo CISA KEV.
- Armazenamento local e paginação no painel de CVEs.

### Upload e Parsing de Logs

- Upload com drag-and-drop.
- Suporte a arquivos `.log`, `.txt`, `.csv`, `.xlsx` e `.json` no backend.
- Extração automática de IoCs a partir de logs.
- Enriquecimento automático durante o processamento, conforme o tipo de IOC e disponibilidade de APIs.
- Salvamento posterior no banco local por fluxo do painel/aplicação.

### Interface e Navegação

- Navegação consistente entre Dashboard, Upload, IOC Panel e CVE Panel.
- Interface responsiva para desktop e mobile.
- Paginação nas tabelas principais.
- Layout com foco operacional para análise rápida.

## Novidades e correções aplicadas

### Versão 3.1.1

- Padronização da severidade de IoCs e CVEs em inglês: `Low`, `Medium`, `High` e `Critical`.
- Paginação com seleção direta de páginas no painel de IoCs e no painel de CVEs.
- Ajustes visuais em badges, espaçamento e rodapé.
- Refatorações internas sem alteração de APIs públicas da aplicação.

### Correções relevantes já refletidas no projeto

- Leitura antecipada de variáveis do `.env` com `load_dotenv()` no início da aplicação.
- Tradução automática protegida contra erro de importação do `deep-translato` e falhas de tradução.
- Tratamento para banco de CVEs vazio ou corrompido.
- Filtros por query string no painel de IoCs.
- Suporte ampliado a extensões de upload no backend.
- Ajustes na ordenação e persistência de CVEs e IoCs.

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

> A estrutura acima representa a organização funcional do projeto com base nos arquivos anexados e no conteúdo atual do repositório.

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

- As APIs externas são opcionais; sem elas, parte do enriquecimento ficará limitada.
- A tradução automática depende de `deep-translator==1.11.4`.
- Para produção, utilize `FLASK_DEBUG=False`.

## Execução local

```bash
python app.py
```

Saída esperada:

```text
============================================================
🛡️  IOC Analyzer - Blue Team Platform
============================================================
✅Servidor iniciado
📊Dashboard: http://localhost:5000
📤Upload: http://localhost:5000/upload
🔍IOC Panel: http://localhost:5000/ioc
🛡️CVE Panel: http://localhost:5000/cve
============================================================
```

## Acesso

### Ambiente local

- Dashboard: [http://localhost:5000](http://localhost:5000)
- Upload: [http://localhost:5000/upload](http://localhost:5000/upload)
- IOC Panel: [http://localhost:5000/ioc](http://localhost:5000/ioc)
- CVE Panel: [http://localhost:5000/cve](http://localhost:5000/cve)

### Ambiente em produção

- Base URL: [https://iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app)
- A aplicação está publicada para acesso web externo por meio do Railway.

## Dependências principais

- Flask
- python-dotenv
- pandas
- openpyxl
- requests
- waitress
- abuseipdb-wrapper==0.2.0
- virustotal-python==1.0.0
- deep-translator==1.11.4

## APIs suportadas

| API | Descrição | Status |
|---|---|---|
| NVD | National Vulnerability Database | Integrado |
| CIRCL | CVE Search | Integrado |
| CISA KEV | Known Exploited Vulnerabilities | Integrado |
| AbuseIPDB | Reputação de IP | Requer API Key |
| VirusTotal | Análise de hash, IP, domínio e URL | Requer API KeY |

## Uso básico

### 1. Dashboard

Acesse o dashboard para visualizar totais, distribuição por severidade e visão consolidada de IoCs e CVEs.

### 2. Upload de logs

1. Acesse `/upload`.
2. Envie arquivos suportados para análise.
3. Aguarde a extração dos IoCs.
4. Revise os resultados enriquecidos exibidos pela interface.

### 3. Gerenciar IoCs

1. Acesse `/ioc`.
2. Consulte um IOC manualmente ou filtre registros do banco local.
3. Salve, remova e revise a classificação retornada pelas integrações.

### 4. Gerenciar CVEs

1. Acesse `/cve`.
2. Busque um CVE específico ou solicite CVEs das últimas 24 horas.
3. Salve resultados e acompanhe severidade, score CVSS e indicadores de exploração ativa.

## Segurança

### Importante

- Não exponha a aplicação em produção sem controles adicionais de segurança.
- Não mantenha `debug=True` em ambiente publicado.
- Proteja chaves de API no ambiente de execução.
- Recomenda-se uso de autenticação, proxy reverso e HTTPS quando aplicável.

### Recomendações para produção

- Executar com servidor WSGI, como Gunicorn.
- Desabilitar debug mode.
- Adicionar autenticação e controle de acesso.
- Implementar logs de auditoria e proteção de borda.

## Roadmap

### v4.0 - Autenticação e Segurança

- Sistema de login e senha.
- Autenticação JWT.
- Níveis de permissão (`Admin`, `Analyst`, `Viewer`).
- Logs de auditoria.

### v4.1 - Integrações Avançadas

- Integração com MISP.
- Integração com TheHive.
- Suporte a STIX/TAXII.
- Exportação para SIEM.

## Changelog

### v2.0 - 20/10/2025

- Primeira release estável.

### v2.1 - 25/10/2025

**Novidades**
- Navegação consistente em todas as páginas.
- Botão de upload de logs acessível de todas as páginas.
- Interface modernizada.
- Busca automática de CVEs das últimas 24 horas.
- Dashboard com gráficos Chart.js interativos.

**Correções**
- Rotas 404 corrigidas.
- Comunicação entre páginas funcionando.
- Endpoints atualizados.

### v2.2 - 27/10/2025

**Correções**
- Correlação entre IoCs e CVEs.
- Busca de CVEs relacionadas a IoCs.
- Busca de IoCs relacionados a CVEs.
- Dashboard de correlações.

### v2.3 - 28/10/2025

**Correções**
- Validação reforçada dos tipos em campos críticos.
- Tradução automática protegida contra erros de tipo e valores nulos.
- CVEs duplicadas ou inválidas não são mais salvas no banco.
- Proteção contra arquivos JSON vazios ou corrompidos.
- Logs de debug adicionados para facilitar diagnóstico.

### v3.0 - 20/11/2025

**Correções**
- Correção de exibição do histórico do AbuseIPDB.
- Tratamento de listas e variáveis no backend.
- Padronização do formato de datas.

### v3.1.1 - 31/12/2025

- Melhoria na exibição de severidade de IoCs e CVEs.
- Inclusão de paginação com seleção direta de página.
- Ajustes visuais gerais.
- Refatorações internas sem impacto nas APIs públicas.

### Atualização de implantação

- Inclusão da URL pública de produção no Railway: [https://iocanalyzer-production.up.railway.app](https://iocanalyzer-production.up.railway.app).
- Documentação revisada para refletir acesso web em produção e boas práticas mínimas de publicação.

## Contribuindo

Contribuições são bem-vindas.

1. Faça um fork do projeto.
2. Crie uma branch para sua feature: `git checkout -b feature/nova-funcionalidade`.
3. Commit suas alterações: `git commit -m "Adiciona nova funcionalidade"`.
4. Envie para o repositório remoto: `git push origin feature/nova-funcionalidade`.
5. Abra um Pull Request.

## Licença

Este projeto está licenciado sob a **GNU General Public License v3.0**.

Em resumo:

- Uso comercial permitido.
- Modificação permitida.
- Distribuição permitida.
- Uso privado permitido.
- Copyleft obrigatório para trabalhos derivados.
- Disponibilização do código-fonte quando aplicável.

## Autor

**Pablo Nunes de Oliveira**

- GitHub: [pablonoliveira](https://github.com/pablonoliveira)
- LinkedIn: [Pablo Oliveira] (https://www.linkedin.com/in/pablonoliveirapro/?locale=en).
- Email: pabloliveir@gmail.com.

## Agradecimentos

- Flask.
- Chart.js.
- NVD.
- CISA.
- CIRCL.
- VirusTotal
- AbuseIPDB

## Suporte

Para suporte, abra uma issue no GitHub ou entre em contato pelos canais do autor.

Se este projeto foi útil, considere dar uma estrela no repositório.
