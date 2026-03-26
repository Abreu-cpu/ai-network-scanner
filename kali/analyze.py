#!/usr/bin/env python3
import json
import os
import sys
import time
import requests
import xml.etree.ElementTree as ET
from knowledge_base import services_info

VULNERS_API = "https://vulners.com/api/v3/search/lucene/"
TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.4


def get_api_key():
    return os.getenv("VULNERS_API_KEY")


def analyze_service(service_name: str) -> dict:
    info = services_info.get(service_name.lower(), {})
    return {
        "local_risk": info.get("risk", "Desconhecido"),
        "recommendation": info.get("recommendation", "Verificar documentação"),
        "description": info.get("description", "Sem descrição local."),
    }


def build_service_display(service_name: str, product: str, version: str, extrainfo: str) -> str:
    parts = [service_name]
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    if extrainfo:
        parts.append(f"({extrainfo})")
    return " ".join(parts)


def build_search_terms(service_name: str, product: str, version: str):
    terms = []

    product = (product or "").strip()
    version = (version or "").strip()
    service_name = (service_name or "").strip()

    if product and version:
        terms.append(f'"{product} {version}"')
    if product:
        terms.append(f'"{product}"')
    if service_name and version:
        terms.append(f'"{service_name} {version}"')
    if service_name:
        terms.append(f'"{service_name}"')

    return list(dict.fromkeys(terms))


def fetch_vulners_results(search_term: str, api_key: str):
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
    }

    payload = {
        "query": search_term,
        "skip": 0,
        "size": 5,
        "fields": ["id", "title", "href", "cvss"],
    }

    response = requests.post(VULNERS_API, headers=headers, json=payload, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()

    if data.get("result") != "OK":
        raise RuntimeError(f"Resposta inesperada da API: {data}")

    documents = data.get("data", {}).get("search", [])
    cves = []

    for item in documents:
        cve_id = item.get("_source", {}).get("id") or item.get("id") or item.get("_id")
        title = item.get("_source", {}).get("title") or "Sem título"
        href = item.get("_source", {}).get("href") or ""
        score = (
            item.get("_source", {}).get("cvss", {}).get("score")
            or item.get("_source", {}).get("cvss", {}).get("scoreV3")
            or "N/A"
        )

        if cve_id and str(cve_id).startswith("CVE-"):
            cves.append({
                "id": cve_id,
                "title": title,
                "score": score,
                "link": href,
            })

    return cves


def check_vulnerabilities(service_name: str, product: str, version: str):
    api_key = get_api_key()

    if not api_key:
        return {"status": "skipped", "message": "API não configurada", "cves": []}

    terms = build_search_terms(service_name, product, version)

    for term in terms:
        try:
            cves = fetch_vulners_results(term, api_key)
            return {"status": "ok", "message": term, "cves": cves}
        except Exception as e:
            last_error = str(e)

    return {"status": "error", "message": last_error, "cves": []}


def process_xml_file(xml_file: str):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Erro ao ler {xml_file}: {e}")
        return

    print(f"\n{xml_file}\n" + "-" * 50)

    for host in root.findall("host"):
        address = host.find("address").get("addr")
        print(f"\nHost: {address}")

        results = {"host": address, "source_xml": xml_file, "ports": []}

        for port in host.findall(".//port"):
            if port.find("state").get("state") != "open":
                continue

            portid = port.get("portid")
            service = port.find("service")

            if service is None:
                results["ports"].append({
                    "port": portid,
                    "service": "unknown",
                    "risk": "Desconhecido",
                    "cve_status": "skipped",
                    "cve_message": "Serviço não identificado",
                    "cves": []
                })
                continue

            service_name = service.get("name", "unknown")
            product = service.get("product", "")
            version = service.get("version", "")
            extrainfo = service.get("extrainfo", "")

            display = build_service_display(service_name, product, version, extrainfo)
            print(f"\nPorta {portid} → {display}")

            local = analyze_service(service_name)
            print(f"  Risco: {local['local_risk']}")
            print(f"  Recomendação: {local['recommendation']}")

            result = check_vulnerabilities(service_name, product, version)

            api_key = os.getenv("VULNERS_API_KEY", "")
            safe_message = result["message"]

            if api_key:
                safe_message = safe_message.replace(api_key, "[REDACTED]")

            if result["status"] == "ok":
                if result["cves"]:
                    print(f"  [!] {len(result['cves'])} CVE(s) encontrada(s):")
                    for cve in result["cves"]:
                        print(f"      - {cve['id']}: {cve['title']} (Score: {cve['score']})")
                        if cve.get("link"):
                            print(f"        Link: {cve['link']}")
                else:
                    print("  [OK] Consulta realizada, nenhuma CVE encontrada.")
            

            results["ports"].append({
                "port": portid,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "risk": local["local_risk"],
                "recommendation": local["recommendation"],
                "cve_status": result["status"],
                "cve_message": safe_message,
                "cves": result["cves"]
            })

            time.sleep(SLEEP_BETWEEN_REQUESTS)

        filename = f"report_{address.replace('.', '_')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

        print(f"\n[+] JSON salvo: {filename}")


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 analyze.py <xml>")
        sys.exit(1)

    print("\n===== RELATÓRIO =====")

    for file in sys.argv[1:]:
        process_xml_file(file)


if __name__ == "__main__":
    main()