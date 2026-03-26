services_info = {
    "http": {
        "description": "Protocolo de transferência de hipertexto",
        "risk": "Médio",
        "recommendation": "Verifique se o servidor está atualizado e use HTTPS."
    },
    "https": {
        "description": "HTTP Seguro",
        "risk": "Baixo",
        "recommendation": "Verifique certificados SSL/TLS."
    },
    "apache": {
        "description": "Apache HTTP Server",
        "risk": "Alto",
        "recommendation": "Verifique vulnerabilidades de Apache (ex: CVE-2021-41773)."
    },
    "nginx": {
        "description": "Nginx Web Server",
        "risk": "Médio",
        "recommendation": "Mantenha atualizado para evitar vulnerabilidades."
    },
    "ssh": {
        "description": "Secure Shell",
        "risk": "Alto",
        "recommendation": "Desabilite login root e use chaves SSH."
    },
    "mysql": {
        "description": "MySQL Database",
        "risk": "Alto",
        "recommendation": "Verifique vulnerabilidades de SQL Injection."
    },
    "postgresql": {
        "description": "PostgreSQL Database",
        "risk": "Alto",
        "recommendation": "Verifique vulnerabilidades de SQL Injection."
    },
    "ftp": {
        "description": "File Transfer Protocol",
        "risk": "Alto",
        "recommendation": "Considere migrar para SFTP ou SCP."
    }
}