services_info = {

"ssh": {
"description": "Secure Shell usado para administração remota.",
"risk": "Baixo se configurado corretamente.",
"recommendation": "Use autenticação por chave e desative login por senha."
},

"telnet": {
"description": "Protocolo antigo para acesso remoto.",
"risk": "ALTO - transmite credenciais sem criptografia.",
"recommendation": "Substituir por SSH."
},

"http": {
"description": "Servidor web padrão.",
"risk": "Depende da aplicação.",
"recommendation": "Considere usar HTTPS."
},

"ftp": {
"description": "Transferência de arquivos.",
"risk": "Médio - credenciais podem ser expostas.",
"recommendation": "Usar SFTP ou FTPS."
}

}