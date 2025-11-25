# Atualize seu repositório local com o remoto (resolve divergências antes de enviar)
git pull origin main

# Adicione todas as mudanças no projeto, incluindo .gitignore atualizado
git add .

# Faça um commit com mensagem personalizada
git commit -m "Atualiza .gitignore, remove planilhas, uploads e data/* do versionamento"

# Remova arquivos já versionados que agora estão ignorados (.csv, uploads, data/*)
git rm --cached -r upload || echo "Nenhum arquivo na pasta upload para remover."
git rm --cached -r data || echo "Nenhum arquivo na pasta data para remover."
git rm --cached *.csv *.tsv *.xls *.xlsx *.ods *.numbers 2>nul

# Faça um novo commit para registrar as exclusões do versionamento, se necessário
git commit -m "Remove arquivos sensíveis já versionados (data/, upload/, planilhas)" || echo "Nada para remover."

# Faça o push das mudanças para o GitHub
git push origin main
