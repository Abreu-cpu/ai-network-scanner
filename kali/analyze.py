import xml.etree.ElementTree as ET
import sys
from knowledge_base import services_info

file = sys.argv[1]

tree = ET.parse(file)
root = tree.getroot()

print("\n===== RELATÓRIO DE SEGURANÇA =====\n")

for host in root.findall("host"):

    address = host.find("address").get("addr")
    print(f"\nHost: {address}")

    for port in host.findall(".//port"):

        portid = port.get("portid")
        service = port.find("service")

        if service is None:
            continue

        service_name = service.get("name")

        print(f"\nPorta {portid} → {service_name}")

        if service_name in services_info:

            info = services_info[service_name]

            print("Descrição:", info["description"])
            print("Risco:", info["risk"])
            print("Recomendação:", info["recommendation"])

        else:

            print("Serviço desconhecido na base.")