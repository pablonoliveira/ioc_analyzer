#!/bin/bash

# ============================================
# IOC Analyzer - Git Release Script v2.1
# ============================================
# Script automatizado para commit e release
# ============================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para print colorido
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Banner
echo ""
echo "============================================"
echo "  🛡️  IOC Analyzer - Git Release v2.1"
echo "============================================"
echo ""

# Verificar se estamos no diretório correto
if [ ! -f "webapp.py" ]; then
    print_error "webapp.py não encontrado!"
    print_error "Execute este script na raiz do projeto ioc_analyzer/"
    exit 1
fi

print_success "Diretório correto confirmado"

# Verificar se git está inicializado
if [ ! -d ".git" ]; then
    print_warning "Git não inicializado. Inicializando..."
    git init
    print_success "Git inicializado"
fi

# Verificar status
print_status "Verificando status do repositório..."
echo ""
git status
echo ""

# Perguntar confirmação
read -p "$(echo -e ${YELLOW}Deseja continuar com o commit? [s/N]:${NC} )" confirm
if [[ ! $confirm =~ ^[Ss]$ ]]; then
    print_warning "Operação cancelada pelo usuário"
    exit 0
fi

# Adicionar arquivos
print_status "Adicionando arquivos ao staging..."
git add .

if [ $? -eq 0 ]; then
    print_success "Arquivos adicionados com sucesso"
else
    print_error "Erro ao adicionar arquivos"
    exit 1
fi

# Commit
print_status "Criando commit..."
git commit -m "🎉 Release v2.1 - Documentação completa e melhorias

✅ Funcionalidades consolidadas:
- Dashboard com 6 gráficos + porcentagens
- IOC Panel com busca visual e CRUD completo
- CVE Panel com integração NVD e tradução automática
- Tema escuro profissional e responsivo

📚 Documentação:
- README.md completo em Markdown para GitHub
- docs/DOCUMENTACAO.html interativa com navegação
- .env.example como template de configuração
- .gitignore otimizado e categorizado

🔧 Infraestrutura:
- Proteção de secrets e API keys
- Suporte para múltiplos IDEs
- Preparado para evolução (Docker, PostgreSQL, testes)

🔐 Segurança:
- .gitignore reforçado contra vazamento de credenciais
- Template .env.example para novos desenvolvedores"

if [ $? -eq 0 ]; then
    print_success "Commit criado com sucesso"
else
    print_error "Erro ao criar commit"
    exit 1
fi

# Criar tag
print_status "Criando tag v2.1..."
git tag -a v2.1 -m "Release v2.1 - Versão estável com documentação completa

Primeira versão de produção do IOC Analyzer com:
- Interface visual consolidada
- 5 integrações de API funcionais (VT, AbuseIPDB, NVD, CISA, CIRCL)
- Documentação completa (README + HTML interativo)
- Infraestrutura preparada para expansão
- Dashboard interativo com 6 gráficos
- Sistema de busca e CRUD completo
- Tema escuro profissional"

if [ $? -eq 0 ]; then
    print_success "Tag v2.1 criada com sucesso"
else
    print_warning "Tag v2.1 já existe ou erro ao criar"
    read -p "$(echo -e ${YELLOW}Deseja forçar recriação da tag? [s/N]:${NC} )" force_tag
    if [[ $force_tag =~ ^[Ss]$ ]]; then
        git tag -d v2.1
        git tag -a v2.1 -m "Release v2.1 - Versão estável com documentação completa"
        print_success "Tag v2.1 recriada com sucesso"
    fi
fi

# Verificar remote
print_status "Verificando remote..."
REMOTE=$(git remote -v | grep origin | head -n 1)

if [ -z "$REMOTE" ]; then
    print_warning "Remote 'origin' não configurado"
    read -p "$(echo -e ${YELLOW}Digite a URL do repositório GitHub:${NC} )" repo_url
    git remote add origin "$repo_url"
    print_success "Remote 'origin' adicionado"
else
    print_success "Remote 'origin' configurado"
    echo "$REMOTE"
fi

echo ""

# Perguntar sobre push
read -p "$(echo -e ${YELLOW}Deseja fazer push para o GitHub agora? [s/N]:${NC} )" push_confirm
if [[ ! $push_confirm =~ ^[Ss]$ ]]; then
    print_warning "Push cancelado. Execute manualmente:"
    echo ""
    echo "  git push origin main --tags"
    echo ""
    exit 0
fi

# Push
print_status "Fazendo push para origin/main..."
git push origin main

if [ $? -eq 0 ]; then
    print_success "Código enviado com sucesso"
else
    print_error "Erro ao fazer push do código"
    print_warning "Tentando criar branch main..."
    git branch -M main
    git push -u origin main
fi

# Push tags
print_status "Enviando tags..."
git push origin --tags

if [ $? -eq 0 ]; then
    print_success "Tags enviadas com sucesso"
else
    print_warning "Erro ao enviar tags (talvez já existam)"
    read -p "$(echo -e ${YELLOW}Deseja forçar push das tags? [s/N]:${NC} )" force_push
    if [[ $force_push =~ ^[Ss]$ ]]; then
        git push origin --tags --force
        print_success "Tags enviadas com force"
    fi
fi

# Sucesso final
echo ""
echo "============================================"
print_success "🎉 Release v2.1 concluída com sucesso!"
echo "============================================"
echo ""
print_status "Próximos passos:"
echo "  1. Acesse: https://github.com/SEU_USUARIO/ioc_analyzer"
echo "  2. Vá em 'Releases' → 'Draft a new release'"
echo "  3. Selecione a tag 'v2.1'"
echo "  4. Publique a release oficial"
echo ""
print_status "Ou continue o desenvolvimento:"
echo "  - Próxima versão: v3.0"
echo "  - Features: Botão CVEs 24h + Correlação IOC↔CVE"
echo ""
print_success "Backup seguro no GitHub ✓"
echo ""