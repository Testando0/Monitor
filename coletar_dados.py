#!/usr/bin/env python3
"""
Coleta dados reais de ameaças e grava dados.json (e um HTML com os dados embutidos).

Fontes:
  - CISA KEV (sem chave): falhas confirmadas como exploradas por atacantes
  - abuse.ch Feodo Tracker (sem chave): servidores C2 de botnets, com país e malware
  - Cloudflare Radar (token gratuito, opcional): países mais atacados e países de origem
    Crie o token em https://dash.cloudflare.com/profile/api-tokens (permissão Radar leitura)
    e exporte:  CLOUDFLARE_API_TOKEN=seu_token

Uso:
    pip install requests
    python coletar_dados.py            # coleta uma vez
    python servidor.py                 # coleta a cada 5 min e serve o painel
"""
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path

import requests

URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URL_CF = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/{tipo}"
HEADERS = {"User-Agent": "Mozilla/5.0 (radar-de-ameacas)"}
PASTA = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()

MARCADOR = "const DADOS_EMBUTIDOS = null;"
CABECALHO = (
    '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
    "<style>:root{color-scheme:dark}body{margin:0;background:#000}</style></head><body>"
)
RODAPE = "</body></html>"


def baixar_json(url, **kw):
    resposta = requests.get(url, headers=kw.pop("headers", HEADERS), timeout=40, **kw)
    resposta.raise_for_status()
    return resposta.json()


def coletar_kev(limite=60):
    bruto = baixar_json(URL_KEV)
    vulns = bruto.get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    corte = (dt.date.today() - dt.timedelta(days=30)).isoformat()
    recentes = [{
        "cve": v.get("cveID"),
        "fabricante": v.get("vendorProject"),
        "produto": v.get("product"),
        "nome": v.get("vulnerabilityName"),
        "descricao": v.get("shortDescription"),
        "acao": v.get("requiredAction"),
        "adicionado": v.get("dateAdded"),
        "prazo": v.get("dueDate"),
        "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
    } for v in vulns[:limite]]
    return {
        "versao": bruto.get("catalogVersion"),
        "total": len(vulns),
        "ultimos_30_dias": sum(1 for v in vulns if v.get("dateAdded", "") >= corte),
        "ransomware": sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"),
        "fabricantes": Counter(v.get("vendorProject", "?") for v in vulns).most_common(8),
        "recentes": recentes,
    }


def coletar_c2(limite=300):
    bruto = baixar_json(URL_FEODO)
    if isinstance(bruto, dict):
        bruto = bruto.get("blocklist") or bruto.get("data") or []
    bruto.sort(key=lambda s: s.get("last_online") or "", reverse=True)
    return {
        "total": len(bruto),
        "online": sum(1 for s in bruto if s.get("status") == "online"),
        "por_pais": dict(Counter((s.get("country") or "??") for s in bruto).most_common()),
        "por_malware": dict(Counter((s.get("malware") or "Desconhecido") for s in bruto).most_common()),
        "servidores": [{
            "ip": s.get("ip_address"), "porta": s.get("port"), "pais": s.get("country") or "??",
            "malware": s.get("malware") or "Desconhecido", "status": s.get("status"),
            "rede": s.get("as_name"), "primeira_vez": s.get("first_seen"), "ultimo_online": s.get("last_online"),
        } for s in bruto[:limite]],
    }


def coletar_cloudflare(tipo, token, limite=30):
    """tipo: 'target' (países atacados) ou 'origin' (países de origem). Camada 7, últimas 24 h."""
    resposta = requests.get(
        URL_CF.format(tipo=tipo),
        headers={**HEADERS, "Authorization": f"Bearer {token}"},
        params={"dateRange": "1d", "limit": limite, "format": "json"},
        timeout=40,
    )
    resposta.raise_for_status()
    resultado = resposta.json().get("result", {})
    lista = next((v for k, v in resultado.items() if k != "meta" and isinstance(v, list)), [])
    campo = f"{tipo}CountryAlpha2"
    itens = [{"pais": i[campo], "valor": float(i.get("value", 0))} for i in lista if i.get(campo)]
    if not itens:
        raise ValueError("resposta da Cloudflare sem itens")
    rotulo = "países mais atacados" if tipo == "target" else "países de origem dos ataques"
    return {"fonte": f"Cloudflare Radar · {rotulo} · requisições HTTP mitigadas, últimas 24 h", "itens": itens}


def coletar(intervalo=300):
    dados = {
        "gerado_em": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "atualiza_a_cada_s": intervalo,
        "erros": {},
    }
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    tarefas = [("kev", coletar_kev), ("c2", coletar_c2)]
    if token:
        tarefas += [("alvos", lambda: coletar_cloudflare("target", token)),
                    ("origens", lambda: coletar_cloudflare("origin", token))]
    else:
        dados["alvos"] = dados["origens"] = None
        dados["erros"]["alvos"] = "sem CLOUDFLARE_API_TOKEN"
    for nome, funcao in tarefas:
        try:
            dados[nome] = funcao()
            print(f"[ok]   {nome}")
        except Exception as erro:  # uma fonte fora do ar não derruba as outras
            dados[nome] = None
            dados["erros"][nome] = str(erro)
            print(f"[erro] {nome}: {erro}", file=sys.stderr)
    if not any(dados.get(k) for k in ("kev", "c2", "alvos", "origens")):
        raise SystemExit("Nenhuma fonte respondeu. Verifique sua conexão e tente de novo.")
    return dados


def executar(intervalo=300, embutir=True):
    dados = coletar(intervalo)
    destino = PASTA / "dados.json"
    temporario = PASTA / "dados.json.tmp"
    temporario.write_text(json.dumps(dados, ensure_ascii=False), encoding="utf-8")
    temporario.replace(destino)  # troca atômica: o painel nunca lê arquivo pela metade
    if embutir:
        modelo = (PASTA / "painel.html").read_text(encoding="utf-8")
        if MARCADOR not in modelo:
            raise SystemExit("painel.html não tem o marcador de dados. Use o arquivo original.")
        embutido = json.dumps(dados, ensure_ascii=False).replace("</", "<\\/")
        pagina = CABECALHO + modelo.replace(MARCADOR, f"const DADOS_EMBUTIDOS = {embutido};") + RODAPE
        (PASTA / "radar_atualizado.html").write_text(pagina, encoding="utf-8")
        print("Pronto: abra radar_atualizado.html (ou rode servidor.py para atualizar sozinho).")
    return dados


if __name__ == "__main__":
    executar()
