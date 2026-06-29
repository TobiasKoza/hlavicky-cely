#!/usr/bin/env python3
"""
Network protocol header assembly practice.
Run: python app.py
"""

import tkinter as tk
import random
import json
import os

# ── Data: protokoly → seznam (název_pole, počet_bitů) ─────────────────────────
PROTOCOLS = {
    "IPv4": [
        ("Version", 4), ("IHL", 4), ("Type of Service (TOS/DSCP)", 8), ("Total Length", 16),
        ("Identification", 16), ("Flags", 3), ("Fragment Offset", 13),
        ("TTL", 8), ("Protocol", 8), ("Header Checksum", 16),
        ("Source IP Address", 32), ("Destination IP Address", 32), ("Options", 32),
    ],
    "TCP": [
        ("Source Port", 16), ("Destination Port", 16),
        ("Sequence Number", 32), ("Acknowledgment Number", 32),
        ("Data Offset", 4), ("Reserved", 6),
        ("Control Bits (URG/ACK/PSH/RST/SYN/FIN)", 6), ("Window", 16),
        ("Checksum", 16), ("Urgent Pointer", 16), ("Options + Padding", 32),
    ],
    "UDP": [
        ("Source Port", 16), ("Destination Port", 16),
        ("Length", 16), ("Checksum", 16),
    ],
    "OSPF": [
        ("OSPF Version", 8), ("Packet Type", 8), ("Packet Length", 16),
        ("Router ID", 32), ("Area ID", 32),
        ("Checksum", 16), ("Authentication", 80),   # AuType(16) + Auth data(64)
    ],
    "Ethernet": [
        ("Preamble + SFD", 64), ("Destination MAC", 48), ("Source MAC", 48),
        ("Type/Length", 16), ("Data + Padding (46–1500 B)", 64), ("FCS", 32),
    ],
    "MPLS": [
        ("Label Value", 20), ("EXP / QoS", 3),
        ("S – Bottom of Stack", 1), ("TTL", 8),
    ],
    "RADIUS": [
        ("Code", 8), ("Identifier", 8), ("Length", 16), ("Authenticator", 128),
    ],
    "IPv6": [
        ("Version", 4), ("Traffic Class", 8), ("Flow Label", 20),
        ("Payload Length", 16), ("Next Header", 8), ("Hop Limit", 8),
        ("Source Address", 128),
        ("Destination Address", 128),
    ],
    "PPPoE": [
        # RFC 2516 – fixed header (6 B = 48 b)
        ("Version", 4), ("Type", 4), ("Code", 8), ("Session ID", 16),
        ("Length", 16),
    ],
    "GRE": [
        # RFC 2784 – mandatory header (4 B = 32 b)
        ("Checksum Present", 1), ("Reserved GRE", 12), ("GRE Version", 3),
        ("Protocol Type", 16),
    ],
    "IPSec AH": [
        # RFC 4302 – fixed header part
        ("Next Header", 8), ("Payload Length", 8), ("Reserved", 16),
        ("Security Parameters Index (SPI)", 32),
        ("Sequence Number", 32),
        ("Integrity Check Value (ICV)", 96),   # HMAC-SHA-1 → 96 b
    ],
    "IPSec ESP": [
        # RFC 4303 – header + trailer (without variable part)
        ("Security Parameters Index (SPI)", 32),
        ("Sequence Number", 32),
        ("Initialization Vector (IV)", 64),       # AES-CBC example
        ("Encrypted Data (Payload)", 32),
        ("Padding", 16), ("Pad Length", 8), ("Next Header", 8),
        ("Integrity Check Value (ICV)", 96),
    ],
}

UNDEFINED = []  # všechny protokoly mají definovaná pole

# ── Definice polí pro double-click popup ──────────────────────────────────────
FIELD_DEFS = {
    # IPv4
    "Version":                          "Verze IP protokolu. U IPv4 vždy hodnota 4.",
    "IHL":                              "Internet Header Length – délka IPv4 hlavičky v 32bitových slovech (minimum 5 = 20 B). Říká, kde začínají data.",
    "Type of Service (TOS/DSCP)":       "Označení priority a kvality služby (QoS). Původně TOS, dnes přeznačeno na DSCP (Differentiated Services Code Point).",
    "Total Length":                     "Celková délka IP paketu v bajtech (hlavička + data). Maximum 65 535 B.",
    "Identification":                   "Identifikátor paketu. Všechny fragmenty jednoho původního paketu mají stejné ID – slouží k jejich zpětnému sestavení.",
    "Flags":                            "Řízení fragmentace. Bit DF (Don't Fragment) zakazuje fragmentaci; bit MF (More Fragments) říká, zda následují další fragmenty.",
    "Fragment Offset":                  "Pozice tohoto fragmentu v původním paketu, v násobcích 8 bajtů. Umožňuje správné sestavení po síti.",
    "TTL":                              "Time To Live – maximální počet hopů (routerů), přes které paket může projít. Každý router sníží o 1; při 0 paket zahodí a pošle ICMP Time Exceeded.",
    "Protocol":                         "Identifikuje protokol v datové části: 6 = TCP, 17 = UDP, 1 = ICMP, 89 = OSPF apod.",
    "Header Checksum":                  "Kontrolní součet pouze IPv4 hlavičky. Každý router jej přepočítává (TTL se mění). U IPv6 bylo toto pole zrušeno.",
    "Source IP Address":                "Zdrojová IPv4 adresa odesílatele (32 bitů = 4 bajty).",
    "Destination IP Address":           "Cílová IPv4 adresa příjemce (32 bitů = 4 bajty).",
    "Options":                          "Volitelná rozšíření IPv4 hlavičky (přítomna jen pokud IHL > 5). Např. Record Route, Timestamp, Strict/Loose Source Route.",
    # TCP
    "Source Port":                      "Zdrojový port odesílatele (0–65535). Spolu s IP adresou tvoří soket (socket).",
    "Destination Port":                 "Cílový port příjemce (0–65535). Identifikuje aplikaci (80 = HTTP, 443 = HTTPS, 22 = SSH…).",
    "Sequence Number":                  "Pořadové číslo prvního bajtu dat v tomto segmentu. Zajišťuje správné seřazení a detekci ztráty paketů.",
    "Acknowledgment Number":            "Číslo dalšího bajtu, které odesílatel očekává od protistrany. Potvrzuje přijetí všech bajtů s nižším číslem (platí jen pokud ACK=1).",
    "Data Offset":                      "Délka TCP hlavičky v 32bitových slovech (minimum 5 = 20 B). Říká, kde začínají data segmentu.",
    "Reserved":                         "Rezervováno pro budoucí použití, musí být nastaveno na 0.",
    "Control Bits (URG/ACK/PSH/RST/SYN/FIN)": "Řídicí příznaky TCP: SYN = navázání spojení, ACK = potvrzení, FIN = ukončení, RST = reset, PSH = okamžité předání aplikaci, URG = urgentní data.",
    "Window":                           "Velikost přijímacího okna v bajtech – kolik dat může odesílatel vyslat bez čekání na potvrzení. Základ flow control.",
    "Checksum":                         "Kontrolní součet TCP hlavičky + dat + pseudo-hlavičky (adresy, protokol). Povinný u TCP.",
    "Urgent Pointer":                   "Ukazuje offset konce urgentních dat od Sequence Number. Platí pouze pokud je nastaven příznak URG.",
    "Options + Padding":                "Volitelná rozšíření TCP: MSS (max. velikost segmentu), Window Scale, SACK (selektivní potvrzení), Timestamps. Padding zarovná hlavičku na 32 b.",
    # UDP
    "Length":                           "Délka UDP datagramu (hlavička + data) v bajtech. Minimum je 8 (samotná hlavička).",
    # OSPF
    "OSPF Version":                     "Verze protokolu OSPF. OSPFv2 pracuje s IPv4, OSPFv3 s IPv6.",
    "Packet Type":                      "Typ OSPF paketu: 1=Hello, 2=Database Description, 3=Link State Request, 4=Link State Update, 5=Link State Acknowledgment.",
    "Packet Length":                    "Celková délka OSPF paketu v bajtech (hlavička + tělo).",
    "Router ID":                        "Unikátní 32bitový identifikátor routeru v OSPF doméně. Obvykle nejvyšší IP adresa nebo adresa loopback rozhraní.",
    "Area ID":                          "Identifikátor OSPF oblasti (area). Area 0.0.0.0 je backbone area, ke které musí být připojeny všechny ostatní oblasti.",
    "Authentication":                   "Autentizace OSPF sousedů: prvních 16 bitů = typ (0=žádná, 1=prostý text, 2=MD5), zbývajících 64 bitů = autentizační data.",
    # Ethernet
    "Preamble + SFD":                   "7 bajtů preambule (střídající se 1 a 0) synchronizuje přijímač; poslední bajt SFD (10101011) označuje začátek rámce.",
    "Destination MAC":                  "48bitová (6 B) MAC adresa cílového zařízení. FF:FF:FF:FF:FF:FF = broadcast.",
    "Source MAC":                       "48bitová (6 B) MAC adresa zdrojového zařízení – toho, které rámec odesílá.",
    "Type/Length":                      "EtherType (≥ 0x0800) identifikuje zapouzdřený protokol (0x0800 = IPv4, 0x86DD = IPv6, 0x8100 = VLAN). Hodnota ≤ 1500 značí délku dat (IEEE 802.3).",
    "Data + Padding (46–1500 B)":        "Vlastní nesená informace. Délka musí být 46–1500 bajtů. Pokud je přenášených dat méně než 46 B, doplní se výplní (Padding), aby byla dodržena minimální velikost rámce pro správnou detekci kolizí. V diagramu zobrazeno symbolicky jako 64 b (2 řádky).",
    "FCS":                              "Frame Check Sequence – 32bitový CRC kontrolní součet celého rámce. Příjemce jej přepočítá; neshoda = rámec zahozen.",
    # MPLS
    "Label Value":                      "20bitový label identifikující LSP (Label Switched Path). Směrovače rozhodují pouze podle labelu, ne podle IP adresy – velmi rychlé přeposílání.",
    "EXP / QoS":                        "Experimentální bity (dnes Traffic Class). Používají se pro označení priority přenosu (QoS / DiffServ).",
    "S – Bottom of Stack":              "Bottom of Stack bit. Hodnota 1 znamená, že jde o poslední (nejnižší) label v zásobníku MPLS labelů.",
    # RADIUS
    "Code":                             "Typ RADIUS zprávy: 1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response…",
    "Identifier":                       "8bitový identifikátor pro spárování požadavků a odpovědí. Klient generuje náhodné číslo; odpověď musí mít stejné ID.",
    "Authenticator":                    "128bitový ověřovací vektor. V požadavku náhodný (Request Authenticator); v odpovědi MD5(Code+ID+Length+RequestAuth+Attributes+Secret).",
    # IPv6
    "Traffic Class":                    "Obdoba TOS/DSCP z IPv4 – 8bitové označení třídy provozu pro QoS a DiffServ.",
    "Flow Label":                       "20bitový identifikátor toku paketů. Pakety stejného toku (stejný zdroj, cíl, aplikace) mají stejný Flow Label – umožňuje rychlé zpracování v routerech.",
    "Payload Length":                   "Délka datové části IPv6 paketu v bajtech (bez základní hlavičky 40 B). Rozšiřující hlavičky jsou součástí payloadu.",
    "Next Header":                      "Identifikuje typ následující hlavičky nebo protokol: 6=TCP, 17=UDP, 43=Routing Header, 44=Fragment Header, 51=AH, 50=ESP…",
    "Hop Limit":                        "Obdoba TTL z IPv4. Každý router sníží o 1; při 0 paket zahodí a odešle ICMPv6 Time Exceeded.",
    "Source Address":                   "Zdrojová IPv6 adresa (128 bitů = 16 bajtů). Zapsána jako 8 skupin po 4 hexadecimálních číslicích.",
    "Destination Address":              "Cílová IPv6 adresa (128 bitů = 16 bajtů).",
    # PPPoE
    "Type":                             "Typ PPPoE, vždy hodnota 1 (dle RFC 2516).",
    "Session ID":                       "16bitový identifikátor PPPoE relace přidělený Access Concentratorem. Společně se MAC adresami jednoznačně identifikuje spojení.",
    # GRE
    "Checksum Present":                 "Pokud nastaven na 1, jsou přítomna volitelná pole Checksum a Reserved1 (dalších 32 bitů za základní hlavičkou).",
    "Reserved GRE":                     "Rezervované bity v GRE hlavičce (zahrnuje i bity Key Present, Sequence Number Present aj.); musí být 0 dle RFC 2784.",
    "GRE Version":                      "Verze GRE protokolu. Hodnota 0 = standardní GRE (RFC 2784). Hodnota 1 = Enhanced GRE (Point-to-Point Tunneling Protocol).",
    "Protocol Type":                    "EtherType zapouzdřeného protokolu: 0x0800 = IPv4, 0x86DD = IPv6, 0x8847 = MPLS…",
    # IPSec AH
    "Payload Length":                   "Délka AH hlavičky v 32bitových slovech minus 2. Minimální hodnota 4 (pro 96bitový ICV).",
    "Security Parameters Index (SPI)":  "32bitový index identifikující Security Association (SA) na straně příjemce – určuje šifru, klíč a politiku.",
    "Sequence Number":                  "Monotónně rostoucí čítač paketů. Příjemce jej kontroluje pro ochranu před replay útoky (opakovaným zasíláním zachycených paketů).",
    "Integrity Check Value (ICV)":      "Kryptografický podpis (HMAC) zajišťující integritu a autenticitu paketu. U AH chrání i IP hlavičku; u ESP jen ESP hlavičku a data.",
    # IPSec ESP
    "Initialization Vector (IV)":       "Náhodný inicializační vektor pro symetrické šifrování (AES-CBC, AES-GCM…). Zabraňuje tomu, aby stejná data vždy vytvořila stejný šifrovaný výstup.",
    "Encrypted Data (Payload)":         "Zašifrovaná datová část – původní protokol (TCP/UDP…) + data aplikace. ESP zajišťuje důvěrnost (na rozdíl od AH).",
    "Padding":                          "Zarovnávací bajty přidané za data, aby délka šifrovaného bloku byla násobkem velikosti bloku šifry.",
    "Pad Length":                       "Počet bajtů paddingu. Příjemce jej použije k odebrání zarovnání po dešifrování.",
}

# ── Port Quiz: databáze služba → port ─────────────────────────────────────────
PORT_QUIZ = [
    # Z PDF (Okruhy-sítě):
    ("DHCP Server",          67,   "UDP"),
    ("DHCP Client",          68,   "UDP"),
    ("RIP / RIPv2",         520,   "UDP"),
    ("RADIUS Auth",        1812,   "UDP"),
    ("RADIUS Accounting",  1813,   "UDP"),
    ("Syslog",              514,   "UDP"),
    ("SNMP",                161,   "UDP"),
    ("SNMP Trap",           162,   "UDP"),
    # Obecně důležité porty:
    ("FTP – přenos dat",     20,   "TCP"),
    ("FTP – řízení",         21,   "TCP"),
    ("SSH",                  22,   "TCP"),
    ("Telnet",               23,   "TCP"),
    ("SMTP",                 25,   "TCP"),
    ("DNS",                  53,   "UDP/TCP"),
    ("TFTP",                 69,   "UDP"),
    ("HTTP",                 80,   "TCP"),
    ("Kerberos",             88,   "TCP/UDP"),
    ("POP3",                110,   "TCP"),
    ("NTP",                 123,   "UDP"),
    ("NetBIOS Name",        137,   "UDP"),
    ("NetBIOS Session",     139,   "TCP"),
    ("IMAP",                143,   "TCP"),
    ("BGP",                 179,   "TCP"),
    ("LDAP",                389,   "TCP"),
    ("HTTPS",               443,   "TCP"),
    ("IKE / ISAKMP",        500,   "UDP"),
    ("SMTP Submission",     587,   "TCP"),
    ("LDAPS",               636,   "TCP"),
    ("IMAP přes TLS",       993,   "TCP"),
    ("POP3 přes TLS",       995,   "TCP"),
    ("OpenVPN",            1194,   "UDP"),
    ("NFS",                2049,   "TCP/UDP"),
    ("iSCSI",              3260,   "TCP"),
    ("RDP",                3389,   "TCP"),
    ("SIP",                5060,   "UDP/TCP"),
    ("SIP přes TLS",       5061,   "TCP"),
    ("SMB / CIFS",          445,   "TCP"),
    ("SMTPS",               465,   "TCP"),
]

PORT_DESC = {
    "DHCP Server":       "DHCP server přijímá Discover a Request pakety od klientů a odpovídá nabídkou/potvrzením IP konfigurace (adresa, maska, brána, DNS, lease time).",
    "DHCP Client":       "DHCP klient přijímá odpovědi Offer a ACK od DHCP serveru po odeslání žádosti o přidělení adresy.",
    "RIP / RIPv2":       "RIP (distance-vector protokol) – routery si vzájemně posílají celé směrovací tabulky každých 30 s. RIPv2 přidává VLSM a autentizaci.",
    "RADIUS Auth":       "RADIUS server ověřuje přihlašovací údaje (Access-Request → Access-Accept/Reject). Používá se v 802.1X, VPN a Wi-Fi (WPA2-Enterprise).",
    "RADIUS Accounting": "RADIUS accounting zaznamenává začátek, průběh a konec relace (Accounting-Request/Response) pro fakturaci a audit.",
    "Syslog":            "Syslog démon přijímá systémové zprávy ze síťových zařízení (routery, switche, servery). Zprávy mají prioritu (facility + severity 0–7).",
    "SNMP":              "SNMP agent odpovídá na Get/Set dotazy SNMP manageru. Umožňuje vzdálené sledování a konfiguraci síťových prvků přes MIB.",
    "SNMP Trap":         "SNMP Trap manager přijímá asynchronní upozornění (Trap/Inform) od agentů při výskytu události – výpadek linky, překročení prahu apod.",
    "FTP – přenos dat":  "FTP aktivní mód – server sám otvírá datové spojení zpět ke klientovi pro přenos souborů. V pasivním módu klient volí náhodný port.",
    "FTP – řízení":      "FTP řídicí kanál – klient posílá příkazy (USER, PASS, LIST, RETR, STOR…). Heslo i příkazy jdou nešifrovaně; nahrazováno SFTP/FTPS.",
    "SSH":               "SSH server nabízí šifrovaný vzdálený přístup k příkazové řádce, přenos souborů (SCP/SFTP) a tunelování portů (port forwarding).",
    "Telnet":            "Telnet server poskytuje nešifrovaný vzdálený terminál. Dnes nahrazen SSH; stále se používá pro ladění CLI síťových zařízení.",
    "SMTP":              "SMTP server přijímá e-maily od jiných mailových serverů (MTA→MTA přenos). Klientské aplikace by měly používat port 587 se STARTTLS.",
    "DNS":               "DNS server odpovídá na dotazy překladu jmen na IP (a opačně). UDP pro většinu dotazů, TCP pro odpovědi > 512 B a přenosy zón (AXFR).",
    "TFTP":              "TFTP server poskytuje jednoduchý přenos souborů bez autentizace. Používá se pro PXE boot, nahrávání firmware a konfigurací na síťových prvcích.",
    "HTTP":              "HTTP server obsluhuje webové požadavky v čistém textu (GET, POST…). Dnes většinou přesměrováno na HTTPS (443).",
    "Kerberos":          "Kerberos KDC vydává tikety pro autentizaci v doméně (Active Directory). Klient získá TGT a pak servisní tikety bez opakovaného zadávání hesla.",
    "POP3":              "POP3 server umožňuje stáhnout e-maily do klienta – zprávy se obvykle ze serveru smažou. Nahrazováno IMAP pro práci na více zařízeních.",
    "NTP":               "NTP server synchronizuje hodiny klientů. Stratum udává vzdálenost od referenčního zdroje (stratum 1 = GPS/atomové hodiny). Přesnost do ms.",
    "NetBIOS Name":      "NetBIOS Name Service překládá NetBIOS jména na IP adresy ve starších Windows sítích. Dnes nahrazeno DNS.",
    "NetBIOS Session":   "NetBIOS Session Service zajišťuje relace pro sdílení souborů ve starších Windows sítích. Moderní alternativou je SMB přímo přes TCP/445.",
    "IMAP":              "IMAP server umožňuje správu e-mailů přímo na serveru – klient zprávy nemaže, synchronizuje složky a stav (přečteno/nepřečteno) přes více zařízení.",
    "BGP":               "BGP (Border Gateway Protocol) je směrovací protokol mezi autonomními systémy (AS) na internetu. Vyměňuje prefixes a aplikuje politiky dostupnosti.",
    "LDAP":              "LDAP server poskytuje adresářové služby – dotazy na uživatele, skupiny a objekty (Active Directory, OpenLDAP). Komunikace jde nešifrovaně.",
    "HTTPS":             "HTTPS = HTTP zabalené v TLS. Šifruje webovou komunikaci a ověřuje identitu serveru certifikátem. Dnes standard pro veškerý web.",
    "IKE / ISAKMP":      "IKE daemon vyjednává Security Associations pro IPSec – dohodne šifrovací algoritmy, vymění klíče (Diffie-Hellman) a ověří účastníky.",
    "SMTP Submission":   "SMTP Submission – poštovní klient odesílá zprávy svému mail serveru. Vyžaduje STARTTLS a autentizaci, na rozdíl od serverového portu 25.",
    "LDAPS":             "LDAPS = LDAP zabalené v TLS. Šifrovaný přístup k adresářovým službám (Active Directory, OpenLDAP) – chrání hesla a data dotazů.",
    "IMAP přes TLS":     "IMAPS = IMAP zabalené v TLS. Šifrovaný přístup k e-mailové schránce; zprávy zůstávají na serveru a synchronizují se přes více zařízení.",
    "POP3 přes TLS":     "POP3S = POP3 zabalené v TLS. Šifrované stahování e-mailů – obsah schránky se přenáší zašifrovaně.",
    "OpenVPN":           "OpenVPN server vytváří šifrované VPN tunely pomocí SSL/TLS. Populární open-source řešení pro vzdálený přístup i site-to-site propojení sítí.",
    "NFS":               "NFS server sdílí souborový systém po síti – klient připojí vzdálený adresář jako lokální (mount). NFSv4 používá výhradně TCP.",
    "iSCSI":             "iSCSI target exportuje blokové úložiště přes TCP/IP. Iniciátor (klient) vidí vzdálený disk jako lokální SCSI zařízení – bez speciální HW sběrnice.",
    "RDP":               "RDP server (Remote Desktop Protocol) poskytuje vzdálenou grafickou plochu Windows. Šifrovaný; podporuje přesměrování zvuku, clipboardu a tiskáren.",
    "SIP":               "SIP proxy/registrar řídí VoIP relace – registrace telefonů, navazování a ukončování hovorů. Samotný hlas přenáší RTP na dynamických portech.",
    "SIP přes TLS":      "SIPS = SIP přes TLS. Šifrovaná VoIP signalizace – chrání navazování hovorů před odposlechem a podvržením.",
    "SMB / CIFS":        "SMB server sdílí soubory, tiskárny a pojmenované roury ve Windows sítích. Port 445 je přímé TCP bez NetBIOS – modernější a rychlejší.",
    "SMTPS":             "SMTPS = SMTP zabalené v SSL/TLS (starší přístup, implicit TLS). Dnes je preferován port 587 s STARTTLS, ale 465 se stále používá.",
}

CUSTOM_PORTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_ports.json")

# Protokoly kreslené lineárně v bajtech místo bitové mřížky 32b/řádek.
# Trojice: (název_pole, zobrazované_bajty, volitelný_popisek_velikosti)
LINEAR_BYTES = {
    "Ethernet": [
        ("Preamble + SFD",              8),
        ("Destination MAC",             6),
        ("Source MAC",                  6),
        ("Type/Length",                 2),
        ("Data + Padding (46–1500 B)", 14, "46–1500 B"),
        ("FCS",                         4),
    ]
}

# ── Konstanty vzhledu ──────────────────────────────────────────────────────────
CW        = 640    # šířka schématu v px
ROW_H     = 44     # výška jednoho řádku schématu
RULER_H   = 20     # výška číselníku bitů nahoře
BPR       = 32     # bitů na jeden řádek
TW, TH    = 80, 56 # rozměry dlaždice v zásobníku
TRAY_H    = TH + 26

C_BG      = "#f0f2f8"
C_EMPTY   = "#dde4f0"  # prázdné pole
C_ETXT    = "#8899bb"
C_SNAP    = "#4caf50"  # správně umístěné pole (zelená)
C_STXT    = "#ffffff"
C_TILE    = "#5c7cfa"  # dlaždice v zásobníku
C_TTXT    = "#ffffff"
C_DONE    = "#b8c0d4"  # použitá dlaždice
C_DTXT    = "#8891aa"
C_HOVER   = "#fff9c4"  # zvýrazněné cílové pole při tažení
C_PLACED  = "#c8d8f8"  # pole s vloženou (dosud neohodnocenou) dlaždicí
C_PTXT    = "#223355"  # text ve vloženém poli
C_WRONG   = "#ffcdd2"  # špatně umístěná dlaždice (po "Ukázat chyby")
C_WTXT    = "#c62828"


class App:
    def __init__(self, root):
        self.root = root
        root.title("Protocol Header Assembly")
        root.configure(bg=C_BG)
        root.minsize(900, 560)

        self.targets      = []    # cílová pole ve schématu
        self.tiles        = []    # dlaždice v zásobníku
        self.drag         = None  # aktivní drag: {"tile", "motion_id", "release_id"}
        self.drag_win     = None  # plovoucí Toplevel během dragu
        self.hover_target = None  # aktuálně zvýrazněné cílové pole

        # Port quiz state
        self.quiz_current  = None
        self.quiz_score    = [0, 0]
        self.quiz_streak   = 0
        self.quiz_answered = False
        self.custom_ports  = self._load_custom_ports()
        self.quiz_pool     = list(PORT_QUIZ) + [
            (e["service"], e["port"], e["protocol"]) for e in self.custom_ports
        ]

        self._build_ui()

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                               bg=C_BG, sashwidth=5, sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Levý panel – scrollovatelný seznam protokolů
        left = tk.Frame(pane, bg=C_BG)
        pane.add(left, minsize=130, width=155)

        tk.Label(left, text="Protocols", bg=C_BG,
                 font=("Segoe UI", 11, "bold")).pack(pady=(4, 3))

        lb_f = tk.Frame(left, bg=C_BG)
        lb_f.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(lb_f)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.lb = tk.Listbox(lb_f, yscrollcommand=sb.set,
                              font=("Segoe UI", 10), activestyle="none",
                              selectbackground=C_TILE, selectforeground="white",
                              bg="white", relief=tk.FLAT, bd=1)
        sb.config(command=self.lb.yview)
        self.lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for p in list(PROTOCOLS) + UNDEFINED:
            self.lb.insert(tk.END, p)
        self.lb.bind("<<ListboxSelect>>", self._on_select)

        tk.Button(left, text="Port Quiz", command=self._show_quiz,
                  bg=C_TILE, fg="white", relief=tk.FLAT,
                  font=("Segoe UI", 9, "bold"), cursor="hand2",
                  pady=5).pack(fill=tk.X, padx=4, pady=(6, 2))

        # Pravý panel – schéma + zásobník  /  quiz portů
        right = tk.Frame(pane, bg=C_BG)
        pane.add(right, minsize=600)

        # ── Rám pro skládání hlaviček ──────────────────────────────────
        self.header_frame = tk.Frame(right, bg=C_BG)
        self.header_frame.pack(fill=tk.BOTH, expand=True)

        # Horní lišta: název protokolu, průběh, reset
        top = tk.Frame(self.header_frame, bg=C_BG)
        top.pack(fill=tk.X, padx=4, pady=(2, 0))
        self.lbl_name = tk.Label(top, text="← Select a protocol from the list",
                                  bg=C_BG, font=("Segoe UI", 13, "bold"))
        self.lbl_name.pack(side=tk.LEFT)
        self.lbl_errors = tk.Label(top, text="", bg=C_BG,
                                    font=("Segoe UI", 10), fg="#e53935")
        self.lbl_errors.pack(side=tk.RIGHT, padx=4)
        self.lbl_prog = tk.Label(top, text="", bg=C_BG,
                                  font=("Segoe UI", 10), fg="#666")
        self.lbl_prog.pack(side=tk.RIGHT, padx=6)
        _bkw = dict(bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                    cursor="hand2", bd=1, padx=4)
        tk.Button(top, text="Show Solution", command=self._show_solution, **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="Show Errors",   command=self._show_errors,   **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="Check",         command=self._check,          **_bkw).pack(side=tk.RIGHT, padx=2)
        tk.Button(top, text="↺ Reset",       command=self._reset,          **_bkw).pack(side=tk.RIGHT, padx=2)

        # Canvas pro schéma – výška se nastaví dynamicky po načtení protokolu
        sch_f = tk.Frame(self.header_frame, bg=C_BG)
        sch_f.pack(fill=tk.X, padx=4, pady=4)
        sch_sb = tk.Scrollbar(sch_f, orient=tk.VERTICAL)
        self.sch = tk.Canvas(sch_f, bg="white", width=CW, height=1,
                               yscrollcommand=sch_sb.set,
                               highlightthickness=1,
                               highlightbackground="#c0c8d8")
        sch_sb.config(command=self.sch.yview)
        sch_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.sch.pack(side=tk.LEFT)

        tk.Frame(self.header_frame, height=2, bg="#c0c8d8").pack(fill=tk.X, padx=4)

        tk.Label(self.header_frame,
                 text="Drag a tile to the correct field in the header:",
                 bg=C_BG, font=("Segoe UI", 9, "italic"),
                 fg="#666").pack(anchor="w", padx=8, pady=(3, 0))

        # Zásobník dlaždic – grid zalamující do řádků, šířka = šířka schématu
        tray_f = tk.Frame(self.header_frame, bg="#e8ecf4", relief=tk.SUNKEN, bd=1)
        tray_f.pack(fill=tk.X, padx=4)
        self.tray = tk.Canvas(tray_f, bg="#e8ecf4", width=CW, height=1,
                               highlightthickness=0)
        self.tray.pack(anchor="w")

        # Hláška po správném složení
        self.lbl_done = tk.Label(self.header_frame, text="", bg=C_BG,
                                  font=("Segoe UI", 11, "bold"), fg="#4caf50")
        self.lbl_done.pack(pady=3)

        # ── Rám pro port quiz (skrytý při startu) ─────────────────────
        self._build_quiz_ui(right)

    # ── Výběr / reset protokolu ────────────────────────────────────────────────
    def _on_select(self, _=None):
        sel = self.lb.curselection()
        if sel:
            self._show_header()
            self._load(self.lb.get(sel[0]))

    def _reset(self):
        sel = self.lb.curselection()
        if sel:
            self._load(self.lb.get(sel[0]))

    def _load(self, name):
        self._cancel_drag()
        self.sch.delete("all")
        self.tray.delete("all")
        self.targets.clear()
        self.tiles.clear()
        self.hover_target = None
        self.lbl_name.config(text=name)
        self.lbl_done.config(text="")
        self.lbl_prog.config(text="")
        self.lbl_errors.config(text="")
        self.sch.bind("<Button-1>",        self._schema_click)
        self.sch.bind("<Double-Button-1>", self._schema_dblclick)

        if name in UNDEFINED:
            self.sch.create_text(CW // 2, 90,
                                  text="Fields not defined",
                                  font=("Segoe UI", 14), fill="#aaa")
            return

        fields = PROTOCOLS[name]
        if name in LINEAR_BYTES:
            self._draw_schema_linear(fields, LINEAR_BYTES[name])
        else:
            self._draw_schema(fields)
        self._draw_tray(self._build_tray_items(fields))
        self._refresh_progress()
        self._resize_window()

    def _cancel_drag(self):
        """Zruší probíhající drag (např. při přepnutí protokolu)."""
        self._clear_hover()
        if self.drag_win:
            self.drag_win.destroy()
            self.drag_win = None
        if self.drag:
            self._return_tile(self.drag["tile"])
            try:
                self.root.unbind("<B1-Motion>",       self.drag["motion_id"])
                self.root.unbind("<ButtonRelease-1>",  self.drag["release_id"])
            except Exception:
                pass
            self.drag = None

    # ── Schéma hlavičky (cílová pole) ─────────────────────────────────────────
    def _draw_schema(self, fields):
        cv  = self.sch
        ppb = CW / BPR  # pixelů na bit

        # Číselník: čárky a čísla každé 4 bity
        for b in range(0, BPR + 1, 4):
            x = b * ppb
            cv.create_line(x, 0, x, RULER_H, fill="#ccc")
        for b in range(0, BPR, 4):
            cv.create_text((b + 2) * ppb, RULER_H // 2,
                            text=str(b), font=("Segoe UI", 7), fill="#bbb")

        row = 0   # aktuální řádek
        col = 0   # bitový offset na aktuálním řádku

        for name, bits in fields:
            remaining = bits
            first     = True
            while remaining > 0:
                avail = BPR - col
                chunk = min(remaining, avail)
                x1 = col * ppb
                y1 = RULER_H + row * ROW_H
                x2 = x1 + chunk * ppb
                y2 = y1 + ROW_H

                r = cv.create_rectangle(x1, y1, x2, y2,
                                         fill=C_EMPTY, outline="#7a8ab0")
                # Prázdné pole — název se zobrazí až po správném přetažení dlaždice
                t = cv.create_text((x1+x2)/2, (y1+y2)/2,
                                    text="", font=("Segoe UI", 8),
                                    fill=C_ETXT, width=(x2-x1)-6)

                self.targets.append({
                    "rect": r, "txt": t,
                    "field_name": name,
                    "bits": bits,        # celková šířka pole
                    "first": first,      # první chunk pole
                    "x": x1, "y": y1,
                    "w": chunk * ppb, "h": ROW_H,
                    "placed_tile": None, # dlaždice aktuálně vložená do tohoto chunku
                })

                first  = False
                col   += chunk
                remaining -= chunk
                if col >= BPR:
                    col = 0
                    row += 1

        # Nastav scroll region na celou výšku schématu
        rows_used = row + (1 if col > 0 else 0)
        total_h   = RULER_H + rows_used * ROW_H + 8
        cv.config(scrollregion=(0, 0, CW, total_h))
        self.sch.config(height=total_h)

    def _draw_schema_linear(self, fields, byte_layout):
        """Lineární bajtová řada políček (Ethernet-style). Šířka pole ∝ počtu bajtů."""
        cv = self.sch
        bits_by_name = {name: bits for name, bits in fields}
        total_bytes  = sum(e[1] for e in byte_layout)
        ppb          = CW / total_bytes   # px na zobrazovaný bajt

        # Ruler: offset v bajtech na každé hranici pole
        cum = 0
        for entry in byte_layout:
            x = cum * ppb
            cv.create_line(x, 0, x, RULER_H, fill="#ccc")
            cv.create_text(x + 3, RULER_H // 2,
                           text=f"{cum} B", font=("Segoe UI", 7),
                           fill="#bbb", anchor="w")
            cum += entry[1]
        cv.create_line(CW, 0, CW, RULER_H, fill="#ccc")
        cv.create_text(CW - 3, RULER_H // 2,
                       text=f"{cum} B", font=("Segoe UI", 7),
                       fill="#bbb", anchor="e")

        # Políčka
        x  = 0
        y1 = RULER_H
        y2 = y1 + ROW_H
        for entry in byte_layout:
            name       = entry[0]
            disp_bytes = entry[1]
            size_label = entry[2] if len(entry) > 2 else f"{disp_bytes} B"
            w          = disp_bytes * ppb
            actual_bits = bits_by_name.get(name, disp_bytes * 8)

            r = cv.create_rectangle(x, y1, x + w, y2,
                                     fill=C_EMPTY, outline="#7a8ab0")
            t = cv.create_text(x + w / 2, (y1 + y2) / 2,
                                text="", font=("Segoe UI", 8),
                                fill=C_ETXT, width=max(w - 6, 1))

            self.targets.append({
                "rect": r, "txt": t,
                "field_name":  name,
                "bits":        actual_bits,
                "size_label":  size_label,   # zobrazuje se v labelu i popupu
                "byte_mode":   True,
                "first":       True,
                "x": x, "y": y1,
                "w": w, "h": ROW_H,
                "placed_tile": None,
            })
            x += w

        total_h = RULER_H + ROW_H + 8
        cv.config(scrollregion=(0, 0, CW, total_h))
        self.sch.config(height=total_h)

    # ── Sestavení dlaždic: správná pole + distraktori ─────────────────────────
    def _build_tray_items(self, fields):
        """Vrátí zamíchaný seznam (name, bits, is_distractor) pro zásobník."""
        current_names = {name for name, _ in fields}

        # Sbírej unikátní pole ze všech ostatních protokolů
        seen, pool = set(), []
        for proto_fields in PROTOCOLS.values():
            for n, b in proto_fields:
                if n not in current_names and n not in seen:
                    seen.add(n)
                    pool.append((n, b))

        n_dist  = min(5, len(pool))
        distract = random.sample(pool, n_dist)

        items  = [(n, b, False) for n, b in fields]
        items += [(n, b, True)  for n, b in distract]
        random.shuffle(items)
        return items

    # ── Zásobník dlaždic ───────────────────────────────────────────────────────
    def _draw_tray(self, items):
        # items: seznam trojic (name, bits, is_distractor)
        cv  = self.tray
        PAD = 8
        tiles_per_row = max(1, (CW - PAD) // (TW + PAD))
        col = row = 0

        for name, bits, is_distractor in items:
            x = PAD + col * (TW + PAD)
            y = PAD + row * (TH + PAD)

            r = cv.create_rectangle(x, y, x+TW, y+TH,
                                     fill=C_TILE, outline="#3a5bd0",
                                     tags=("tile",))
            t = cv.create_text(x+TW/2, y+TH/2-7,
                                text=name, font=("Segoe UI", 7, "bold"),
                                fill=C_TTXT, width=TW-10, tags=("tile",))
            b = cv.create_text(x+TW/2, y+TH-10,
                                text="", font=("Segoe UI", 7),
                                fill="#c0ccff", tags=("tile",))

            tile = {"rect": r, "txt": t, "blbl": b,
                    "field_name": name, "bits": bits,
                    "is_distractor": is_distractor,
                    "placed": False, "placed_group": None}
            self.tiles.append(tile)

            for item in (r, t, b):
                cv.tag_bind(item, "<Button-1>",
                             lambda e, tl=tile: self._drag_start(e, tl))

            col += 1
            if col >= tiles_per_row:
                col = 0
                row += 1

        n_rows  = row + (1 if col > 0 else 0)
        tray_h  = PAD + n_rows * (TH + PAD)
        cv.config(width=CW, height=tray_h,
                  scrollregion=(0, 0, CW, tray_h))

    # ── Drag & Drop ────────────────────────────────────────────────────────────
    def _drag_start(self, event, tile):
        if tile["placed"] or self.drag:
            return

        # Zesvětli dlaždici v zásobníku
        self.tray.itemconfig(tile["rect"], fill="#8ea8f8")

        # Plovoucí okno sledující kurzor
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.wm_attributes("-topmost", True)
        try:
            win.wm_attributes("-alpha", 0.88)
        except Exception:
            pass
        self.drag_win = win

        frm = tk.Frame(win, bg=C_TILE, bd=2, relief=tk.RAISED)
        frm.pack(fill=tk.BOTH, expand=True)
        tk.Label(frm, text=tile["field_name"], bg=C_TILE, fg=C_TTXT,
                 font=("Segoe UI", 8, "bold"),
                 wraplength=TW-8, justify=tk.CENTER).pack(expand=True)
        win.geometry(f"{TW}x{TH}+{event.x_root - TW//2}+{event.y_root - TH//2}")

        # Globální handlery platí po celou dobu dragu (i mimo tray canvas)
        mid = self.root.bind("<B1-Motion>",      self._drag_motion,   add="+")
        rid = self.root.bind("<ButtonRelease-1>", self._drag_release,  add="+")
        self.drag = {"tile": tile, "motion_id": mid, "release_id": rid}

    def _drag_motion(self, event):
        if not self.drag or not self.drag_win:
            return
        self.drag_win.geometry(
            f"+{event.x_root - TW//2}+{event.y_root - TH//2}")
        self._update_hover(event)

    def _drag_release(self, event):
        if not self.drag:
            return

        tile = self.drag["tile"]
        mid  = self.drag["motion_id"]
        rid  = self.drag["release_id"]

        self._clear_hover()
        if self.drag_win:
            self.drag_win.destroy()
            self.drag_win = None
        try:
            self.root.unbind("<B1-Motion>",      mid)
            self.root.unbind("<ButtonRelease-1>", rid)
        except Exception:
            pass
        self.drag = None

        # Puštěno nad schématem → vlož do pole pod kurzorem
        cv = self.sch
        sx, sy = cv.winfo_rootx(), cv.winfo_rooty()
        if (sx <= event.x_root <= sx + cv.winfo_width() and
                sy <= event.y_root <= sy + cv.winfo_height()):
            cx = cv.canvasx(event.x_root - sx)
            cy = cv.canvasy(event.y_root - sy)
            hit = next(
                (t for t in self.targets
                 if t["x"] <= cx <= t["x"] + t["w"]
                 and t["y"] <= cy <= t["y"] + t["h"]),
                None)
            if hit:
                self._place_tile(tile, hit["field_name"])
                return

        # Puštěno mimo schéma → vrátit do zásobníku
        self._return_tile(tile)

    # ── Hover: zvýraznění cílového pole pod kurzorem ──────────────────────────
    def _clear_hover(self):
        """Odstraní zvýraznění aktuálně podsvíceného pole a obnoví správnou barvu."""
        if self.hover_target:
            t = self.hover_target
            if t["placed_tile"] is not None:
                self.sch.itemconfig(t["rect"], fill=C_PLACED, outline="#5c7cfa")
            else:
                self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
            self.hover_target = None

    def _update_hover(self, event):
        """Zvýrazní nezaplněné pole pod kurzorem; ostatní odzvýrazní."""
        cv = self.sch
        sx, sy = cv.winfo_rootx(), cv.winfo_rooty()
        new_hover = None
        if (sx <= event.x_root <= sx + cv.winfo_width() and
                sy <= event.y_root <= sy + cv.winfo_height()):
            cx = cv.canvasx(event.x_root - sx)
            cy = cv.canvasy(event.y_root - sy)
            new_hover = next(
                (t for t in self.targets
                 if t["x"] <= cx <= t["x"] + t["w"]
                 and t["y"] <= cy <= t["y"] + t["h"]),
                None)

        if new_hover is self.hover_target:
            return  # beze změny

        self._clear_hover()
        if new_hover:
            self.sch.itemconfig(new_hover["rect"],
                                fill=C_HOVER, outline="#f9a825")
            self.hover_target = new_hover

    # ── Volné skládání ─────────────────────────────────────────────────────────
    def _place_tile(self, tile, field_name):
        """Vloží dlaždici do pole field_name; starou dlaždici případně vrátí do zásobníku."""
        # Pokud pole obsazené jinou dlaždicí → tu vrátit
        old = next((t["placed_tile"] for t in self.targets
                    if t["field_name"] == field_name
                    and t["placed_tile"] is not None), None)
        if old is not None and old is not tile:
            self._clear_field(field_name)
            self._return_tile(old)

        # Pokud dlaždice byla v jiném poli → to pole vyčistit
        if tile["placed_group"] and tile["placed_group"] != field_name:
            self._clear_field(tile["placed_group"])

        # Vložit do všech chunků pole
        bits = tile["bits"]
        for t in self.targets:
            if t["field_name"] == field_name:
                t["placed_tile"] = tile
                if t["first"]:
                    size = t["size_label"] if t.get("byte_mode") else f"{bits} b"
                    label = f"{tile['field_name']}\n{size}"
                else:
                    label = f"↩ {tile['field_name']}"
                self.sch.itemconfig(t["rect"], fill=C_PLACED, outline="#5c7cfa")
                self.sch.itemconfig(t["txt"], text=label, fill=C_PTXT,
                                    font=("Segoe UI", 8))

        # Zamknout dlaždici v zásobníku
        tile["placed"]       = True
        tile["placed_group"] = field_name
        cv = self.tray
        cv.itemconfig(tile["rect"], fill=C_DONE, outline="#aaa")
        cv.itemconfig(tile["txt"],  fill=C_DTXT)
        for item in (tile["rect"], tile["txt"], tile["blbl"]):
            cv.tag_unbind(item, "<Button-1>")

        self._refresh_progress()

    def _clear_field(self, field_name):
        """Vizuálně i datově vyčistí pole; nesahá na dlaždici."""
        for t in self.targets:
            if t["field_name"] == field_name:
                t["placed_tile"] = None
                self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
                self.sch.itemconfig(t["txt"],  text="", fill=C_ETXT,
                                    font=("Segoe UI", 8))

    def _return_tile(self, tile):
        """Vrátí dlaždici zpět do zásobníku; nesahá na pole."""
        tile["placed"]       = False
        tile["placed_group"] = None
        cv = self.tray
        cv.itemconfig(tile["rect"], fill=C_TILE, outline="#3a5bd0")
        cv.itemconfig(tile["txt"],  fill=C_TTXT)
        for item in (tile["rect"], tile["txt"], tile["blbl"]):
            cv.tag_unbind(item, "<Button-1>")
            cv.tag_bind(item, "<Button-1>",
                        lambda e, tl=tile: self._drag_start(e, tl))

    def _schema_click(self, event):
        """Kliknutí na schéma — pokud je v poli dlaždice, zvedni ji pro přetažení."""
        if self.drag:
            return
        cx = self.sch.canvasx(event.x)
        cy = self.sch.canvasy(event.y)
        hit = next(
            (t for t in self.targets
             if t["x"] <= cx <= t["x"] + t["w"]
             and t["y"] <= cy <= t["y"] + t["h"]
             and t["placed_tile"] is not None),
            None)
        if hit is None:
            return
        tile = hit["placed_tile"]
        self._clear_field(tile["placed_group"])
        self._return_tile(tile)
        self._drag_start(event, tile)

    def _schema_dblclick(self, event):
        """Dvojklik na pole schématu → zobrazí popup s definicí pole."""
        if self.drag:
            return
        cx = self.sch.canvasx(event.x)
        cy = self.sch.canvasy(event.y)
        hit = next(
            (t for t in self.targets
             if t["x"] <= cx <= t["x"] + t["w"]
             and t["y"] <= cy <= t["y"] + t["h"]),
            None)
        if hit:
            self._field_info_popup(hit["field_name"], hit["bits"], event.x_root, event.y_root,
                                   size_label=hit.get("size_label"))

    def _field_info_popup(self, field_name, bits, rx, ry, size_label=None):
        """Zobrazí malé okenko s názvem pole, šířkou a popisem."""
        pop = tk.Toplevel(self.root)
        pop.overrideredirect(True)
        pop.wm_attributes("-topmost", True)

        outer = tk.Frame(pop, bg="#223355", bd=1)
        outer.pack(fill=tk.BOTH, expand=True)

        inner = tk.Frame(outer, bg="#f7f9ff", padx=10, pady=8)
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        tk.Label(inner, text=field_name, bg="#f7f9ff",
                 font=("Segoe UI", 10, "bold"), fg="#223355",
                 wraplength=320, justify=tk.LEFT).pack(anchor="w")
        tk.Label(inner, text=size_label if size_label else f"{bits} bitů", bg="#f7f9ff",
                 font=("Segoe UI", 8), fg="#5c7cfa").pack(anchor="w")

        tk.Frame(inner, height=1, bg="#c0c8d8").pack(fill=tk.X, pady=(4, 5))

        desc = FIELD_DEFS.get(field_name, "Popis pro toto pole není k dispozici.")
        tk.Label(inner, text=desc, bg="#f7f9ff",
                 font=("Segoe UI", 9), fg="#334466",
                 wraplength=320, justify=tk.LEFT).pack(anchor="w")

        pop.update_idletasks()
        pw, ph = pop.winfo_reqwidth(), pop.winfo_reqheight()
        sw, sh = pop.winfo_screenwidth(), pop.winfo_screenheight()
        x = min(rx + 12, sw - pw - 4)
        y = min(ry + 12, sh - ph - 4)
        pop.geometry(f"+{x}+{y}")

        # Zavři kliknutím kdekoli nebo po 6 sekundách
        pop.bind("<Button-1>", lambda e: pop.destroy())
        self.root.bind("<Button-1>", lambda e, p=pop: p.destroy(), add="+")
        pop.after(6000, lambda: pop.destroy() if pop.winfo_exists() else None)

    # ── Akční tlačítka ─────────────────────────────────────────────────────────
    def _check(self):
        all_n   = len({t["field_name"] for t in self.targets})
        correct = sum(1 for t in self.targets
                      if t["first"]
                      and t["placed_tile"] is not None
                      and t["placed_tile"]["field_name"] == t["field_name"])
        wrong   = sum(1 for t in self.targets
                      if t["first"]
                      and t["placed_tile"] is not None
                      and t["placed_tile"]["field_name"] != t["field_name"])
        missing = all_n - correct - wrong

        if wrong == 0 and missing == 0:
            self.lbl_errors.config(text=f"Vše správně! ({correct}/{all_n})", fg="#2e7d32")
            self.lbl_done.config(text="Výborně! Hlavička je správně složená.")
            self._show_errors()
        else:
            parts = []
            if wrong:
                parts.append(f"{wrong} špatně umístěn{'á' if wrong == 1 else 'é'}")
            if missing:
                parts.append(f"{missing} chybějíc{'í' if missing == 1 else 'í'}")
            parts.append(f"{correct}/{all_n} správně")
            self.lbl_errors.config(text="  ·  ".join(parts), fg="#e53935")
            self.lbl_done.config(text="")

    def _show_errors(self):
        """Obarví pole: zelená = správně umístěná dlaždice, červená = špatně."""
        for t in self.targets:
            if t["placed_tile"] is None:
                continue
            if t["placed_tile"]["field_name"] == t["field_name"]:
                self.sch.itemconfig(t["rect"], fill=C_SNAP,  outline="#2e7d32")
                self.sch.itemconfig(t["txt"],  fill=C_STXT,  font=("Segoe UI", 8, "bold"))
            else:
                self.sch.itemconfig(t["rect"], fill=C_WRONG, outline="#c62828")
                self.sch.itemconfig(t["txt"],  fill=C_WTXT,  font=("Segoe UI", 8, "bold"))

    def _show_solution(self):
        """Doplní správné dlaždice do všech polí a obarví schéma zeleně."""
        # Vrátit vše do zásobníku a vyčistit schéma
        for tile in self.tiles:
            if tile["placed"]:
                tile["placed"]       = False
                tile["placed_group"] = None
                self.tray.itemconfig(tile["rect"], fill=C_TILE, outline="#3a5bd0")
                self.tray.itemconfig(tile["txt"],  fill=C_TTXT)
                for item in (tile["rect"], tile["txt"], tile["blbl"]):
                    self.tray.tag_unbind(item, "<Button-1>")
                    self.tray.tag_bind(item, "<Button-1>",
                                       lambda e, tl=tile: self._drag_start(e, tl))
        for t in self.targets:
            t["placed_tile"] = None
            self.sch.itemconfig(t["rect"], fill=C_EMPTY, outline="#7a8ab0")
            self.sch.itemconfig(t["txt"],  text="", fill=C_ETXT, font=("Segoe UI", 8))

        # Vložit správné dlaždice (rovnou zeleně)
        done = set()
        for t in self.targets:
            fn = t["field_name"]
            if fn in done:
                continue
            done.add(fn)
            tile = next((tl for tl in self.tiles
                         if tl["field_name"] == fn and not tl["is_distractor"]), None)
            if tile is None:
                continue
            bits = t["bits"]
            for chunk in self.targets:
                if chunk["field_name"] == fn:
                    chunk["placed_tile"] = tile
                    if chunk["first"]:
                        size  = chunk["size_label"] if chunk.get("byte_mode") else f"{bits} b"
                        label = f"{fn}\n{size}"
                    else:
                        label = f"↩ {fn}"
                    self.sch.itemconfig(chunk["rect"], fill=C_SNAP,  outline="#2e7d32")
                    self.sch.itemconfig(chunk["txt"],  text=label,   fill=C_STXT,
                                        font=("Segoe UI", 8, "bold"))
            tile["placed"]       = True
            tile["placed_group"] = fn
            self.tray.itemconfig(tile["rect"], fill=C_DONE, outline="#aaa")
            self.tray.itemconfig(tile["txt"],  fill=C_DTXT)
            for item in (tile["rect"], tile["txt"], tile["blbl"]):
                self.tray.tag_unbind(item, "<Button-1>")

        self._refresh_progress()
        self.lbl_done.config(text="This is the correct solution.")

    def _refresh_progress(self):
        all_f = {t["field_name"] for t in self.targets}
        occ_f = {t["field_name"] for t in self.targets if t["placed_tile"] is not None}
        n, d  = len(all_f), len(occ_f)
        self.lbl_prog.config(text=f"{d}/{n} placed" if self.targets else "")

    def _resize_window(self):
        """Přizpůsobí okno přesné výšce schématu + zásobníku."""
        schema_h = int(self.sch.cget("height"))
        tray_h   = int(self.tray.cget("height"))
        # Fixní overhead: horní lišta, popisky, rámy, dekorace okna OS
        OVERHEAD = 140
        win_h    = schema_h + tray_h + OVERHEAD
        win_w    = CW + 200  # levý panel (155) + sash (5) + scrollbar + okraje
        self.root.geometry(f"{win_w}x{win_h}")

    # ── Port Quiz ──────────────────────────────────────────────────────────────
    def _build_quiz_ui(self, parent):
        self.quiz_frame = tk.Frame(parent, bg=C_BG)

        # Horní lišta
        q_top = tk.Frame(self.quiz_frame, bg=C_BG)
        q_top.pack(fill=tk.X, padx=8, pady=(8, 4))
        tk.Label(q_top, text="Quiz: čísla portů", bg=C_BG,
                 font=("Segoe UI", 13, "bold"), fg="#223355").pack(side=tk.LEFT)
        tk.Button(q_top, text="← Zpět na hlavičky", command=self._show_header,
                  bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                  cursor="hand2", bd=1, padx=6).pack(side=tk.RIGHT)

        # Skóre a série
        score_f = tk.Frame(self.quiz_frame, bg=C_BG)
        score_f.pack(fill=tk.X, padx=8, pady=(0, 6))
        self.lbl_q_score  = tk.Label(score_f, text="Skóre: 0 / 0", bg=C_BG,
                                      font=("Segoe UI", 10), fg="#444")
        self.lbl_q_score.pack(side=tk.LEFT)
        self.lbl_q_streak = tk.Label(score_f, text="Série: 0", bg=C_BG,
                                      font=("Segoe UI", 10), fg="#4caf50")
        self.lbl_q_streak.pack(side=tk.LEFT, padx=14)
        self.lbl_q_pool   = tk.Label(score_f, text="", bg=C_BG,
                                      font=("Segoe UI", 9), fg="#888")
        self.lbl_q_pool.pack(side=tk.RIGHT)

        # Karta s otázkou
        card_outer = tk.Frame(self.quiz_frame, bg="#d0d8ee", bd=1, relief=tk.SOLID)
        card_outer.pack(padx=30, pady=(4, 8), fill=tk.X)
        card = tk.Frame(card_outer, bg="white", padx=24, pady=22)
        card.pack(fill=tk.BOTH, padx=1, pady=1)
        self.lbl_q_service = tk.Label(card, text="", bg="white",
                                       font=("Segoe UI", 26, "bold"), fg="#223355")
        self.lbl_q_service.pack()
        self.lbl_q_proto   = tk.Label(card, text="", bg="white",
                                       font=("Segoe UI", 12), fg="#5c7cfa")
        self.lbl_q_proto.pack()

        # Vstupní pole
        input_f = tk.Frame(self.quiz_frame, bg=C_BG)
        input_f.pack(pady=(4, 2))
        tk.Label(input_f, text="Číslo portu:", bg=C_BG,
                 font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=(0, 8))
        self.quiz_var   = tk.StringVar()
        self.quiz_entry = tk.Entry(input_f, textvariable=self.quiz_var,
                                    font=("Segoe UI", 16, "bold"), width=7,
                                    justify=tk.CENTER)
        self.quiz_entry.pack(side=tk.LEFT)
        self.quiz_entry.bind("<Return>", lambda e: self._quiz_check())
        self.btn_q_check = tk.Button(input_f, text="Zkontrolovat",
                                      command=self._quiz_check,
                                      bg=C_TILE, fg="white", relief=tk.FLAT,
                                      font=("Segoe UI", 10, "bold"),
                                      cursor="hand2", padx=10, pady=3)
        self.btn_q_check.pack(side=tk.LEFT, padx=(10, 0))

        # Výsledková zpráva
        self.lbl_q_feedback = tk.Label(self.quiz_frame, text="", bg=C_BG,
                                        font=("Segoe UI", 13, "bold"))
        self.lbl_q_feedback.pack(pady=(6, 2))

        # Popis co naslouchá na daném portu
        self.lbl_q_desc = tk.Label(self.quiz_frame, text="", bg=C_BG,
                                    font=("Segoe UI", 9), fg="#334466",
                                    wraplength=560, justify=tk.LEFT)
        self.lbl_q_desc.pack(padx=30, pady=(0, 4))

        # Spodní tlačítka
        bot_f = tk.Frame(self.quiz_frame, bg=C_BG)
        bot_f.pack(pady=(2, 10))
        tk.Button(bot_f, text="Přeskočit", command=self._quiz_skip,
                  bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                  cursor="hand2", padx=8).pack(side=tk.LEFT, padx=6)
        tk.Button(bot_f, text="Zobrazit řešení", command=self._quiz_show_solution,
                  bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                  cursor="hand2", padx=8).pack(side=tk.LEFT, padx=6)
        tk.Button(bot_f, text="+ Přidat port", command=self._quiz_add_port,
                  bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                  cursor="hand2", padx=8).pack(side=tk.LEFT, padx=6)
        tk.Button(bot_f, text="Seznam portů", command=self._quiz_show_list,
                  bg="#e4e8f4", relief=tk.FLAT, font=("Segoe UI", 9),
                  cursor="hand2", padx=8).pack(side=tk.LEFT, padx=6)

    def _show_quiz(self):
        self._cancel_drag()
        self.header_frame.pack_forget()
        self.quiz_frame.pack(fill=tk.BOTH, expand=True)
        self.quiz_score    = [0, 0]
        self.quiz_streak   = 0
        self._quiz_next()

    def _show_header(self):
        self.quiz_frame.pack_forget()
        self.header_frame.pack(fill=tk.BOTH, expand=True)

    def _quiz_next(self):
        if not self.quiz_pool:
            self.lbl_q_service.config(text="Žádné porty!")
            return
        self.quiz_answered = False
        self.quiz_current  = random.choice(self.quiz_pool)
        service, _port, proto = self.quiz_current
        self.lbl_q_service.config(text=service)
        self.lbl_q_proto.config(text=f"({proto})")
        self.lbl_q_feedback.config(text="", fg="#333")
        self.lbl_q_desc.config(text="")
        self.btn_q_check.config(text="Zkontrolovat", bg=C_TILE)
        self.quiz_var.set("")
        self.quiz_entry.config(state=tk.NORMAL)
        self.quiz_entry.focus_set()
        self.lbl_q_pool.config(text=f"{len(self.quiz_pool)} portů v poolu")
        self._update_quiz_score_labels()

    def _quiz_check(self):
        if self.quiz_answered:
            self._quiz_next()
            return
        if not self.quiz_current:
            return
        raw = self.quiz_var.get().strip()
        if not raw.isdigit():
            self.lbl_q_feedback.config(text="Zadej číslo portu!", fg="#e53935")
            return
        answer = int(raw)
        _service, correct_port, _proto = self.quiz_current
        self.quiz_answered = True
        self.quiz_score[1] += 1
        if answer == correct_port:
            self.quiz_score[0] += 1
            self.quiz_streak  += 1
            self.lbl_q_feedback.config(
                text=f"Správně!  Port {correct_port}", fg="#2e7d32")
        else:
            self.quiz_streak = 0
            self.lbl_q_feedback.config(
                text=f"Špatně.  Správná odpověď: {correct_port}", fg="#c62828")
        self.quiz_entry.config(state=tk.DISABLED)
        self.btn_q_check.config(text="Další  →", bg="#5a6a8a")
        self._update_quiz_score_labels()
        desc = PORT_DESC.get(_service, "")
        self.lbl_q_desc.config(text=desc)

    def _quiz_skip(self):
        self.quiz_answered = False
        self._quiz_next()

    def _quiz_show_solution(self):
        if not self.quiz_current or self.quiz_answered:
            return
        _service, correct_port, _proto = self.quiz_current
        self.quiz_answered = True
        self.quiz_streak   = 0
        self.quiz_score[1] += 1
        self.lbl_q_feedback.config(
            text=f"Řešení: port {correct_port}", fg="#7b5ea7")
        desc = PORT_DESC.get(_service, "")
        self.lbl_q_desc.config(text=desc)
        self.quiz_entry.config(state=tk.DISABLED)
        self.btn_q_check.config(text="Další  →", bg="#5a6a8a")
        self._update_quiz_score_labels()

    def _update_quiz_score_labels(self):
        c, t = self.quiz_score
        self.lbl_q_score.config(text=f"Skóre: {c} / {t}")
        streak_col = "#2e7d32" if self.quiz_streak >= 3 else "#444"
        self.lbl_q_streak.config(
            text=f"Série: {self.quiz_streak}" + (" 🔥" if self.quiz_streak >= 3 else ""),
            fg=streak_col)

    def _quiz_add_port(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Přidat port do poolu")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=C_BG)

        pad = dict(padx=12, pady=5)
        tk.Label(dlg, text="Název služby:", bg=C_BG,
                 font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", **pad)
        e_service = tk.Entry(dlg, font=("Segoe UI", 10), width=24)
        e_service.grid(row=0, column=1, **pad)
        e_service.focus_set()

        tk.Label(dlg, text="Číslo portu:", bg=C_BG,
                 font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", **pad)
        e_port = tk.Entry(dlg, font=("Segoe UI", 10), width=10)
        e_port.grid(row=1, column=1, sticky="w", **pad)

        tk.Label(dlg, text="Protokol:", bg=C_BG,
                 font=("Segoe UI", 10)).grid(row=2, column=0, sticky="w", **pad)
        e_proto = tk.Entry(dlg, font=("Segoe UI", 10), width=12)
        e_proto.insert(0, "TCP")
        e_proto.grid(row=2, column=1, sticky="w", **pad)

        err_lbl = tk.Label(dlg, text="", bg=C_BG, fg="#c62828",
                            font=("Segoe UI", 9))
        err_lbl.grid(row=3, column=0, columnspan=2, pady=(0, 4))

        def _save():
            svc  = e_service.get().strip()
            pstr = e_port.get().strip()
            prot = e_proto.get().strip() or "TCP"
            if not svc:
                err_lbl.config(text="Vyplň název služby.")
                return
            if not pstr.isdigit():
                err_lbl.config(text="Port musí být číslo.")
                return
            port = int(pstr)
            if not (1 <= port <= 65535):
                err_lbl.config(text="Port musí být v rozsahu 1–65535.")
                return
            self.custom_ports.append({"service": svc, "port": port, "protocol": prot})
            self._save_custom_ports()
            self._rebuild_quiz_pool()
            dlg.destroy()

        btn_f = tk.Frame(dlg, bg=C_BG)
        btn_f.grid(row=4, column=0, columnspan=2, pady=10)
        _bkw = dict(relief=tk.FLAT, font=("Segoe UI", 9), cursor="hand2", padx=10, pady=4)
        tk.Button(btn_f, text="Přidat", command=_save,
                  bg=C_TILE, fg="white", **_bkw).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_f, text="Zrušit", command=dlg.destroy,
                  bg="#e4e8f4", **_bkw).pack(side=tk.LEFT, padx=6)

        e_service.bind("<Return>", lambda e: e_port.focus_set())
        e_port.bind("<Return>",    lambda e: e_proto.focus_set())
        e_proto.bind("<Return>",   lambda e: _save())

    def _quiz_show_list(self):
        win = tk.Toplevel(self.root)
        win.title("Všechny porty v poolu")
        win.configure(bg=C_BG)
        win.resizable(True, True)

        # Header
        hdr = tk.Frame(win, bg="#223355")
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text=f"  {'Port':<7}  {'Protokol':<10}  Služba",
                 bg="#223355", fg="white",
                 font=("Segoe UI Mono", 9, "bold"),
                 anchor="w").pack(fill=tk.X, padx=4, pady=4)

        # Scrollovatelný seznam
        frame = tk.Frame(win, bg="white")
        frame.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        lb = tk.Listbox(frame, yscrollcommand=sb.set,
                         font=("Segoe UI Mono", 10), bg="white",
                         selectbackground=C_TILE, selectforeground="white",
                         relief=tk.FLAT, bd=0, activestyle="none")
        sb.config(command=lb.yview)
        lb.pack(fill=tk.BOTH, expand=True)

        sorted_pool = sorted(self.quiz_pool, key=lambda e: e[1])
        for service, port, proto in sorted_pool:
            lb.insert(tk.END, f"  {port:<7}  {proto:<10}  {service}")

        # Označit zvýrazněně vlastní (custom) porty
        custom_names = {e["service"] for e in self.custom_ports}
        for i, (service, _port, _proto) in enumerate(sorted_pool):
            if service in custom_names:
                lb.itemconfig(i, fg="#5c7cfa")

        tk.Label(win, text=f"Celkem {len(sorted_pool)} portů  •  modře = vlastní",
                 bg=C_BG, font=("Segoe UI", 8), fg="#888").pack(pady=(2, 4))

        win.geometry("420x500")

    def _rebuild_quiz_pool(self):
        self.quiz_pool = list(PORT_QUIZ) + [
            (e["service"], e["port"], e["protocol"]) for e in self.custom_ports
        ]
        if hasattr(self, "lbl_q_pool"):
            self.lbl_q_pool.config(text=f"{len(self.quiz_pool)} portů v poolu")

    def _load_custom_ports(self):
        if os.path.exists(CUSTOM_PORTS_FILE):
            try:
                with open(CUSTOM_PORTS_FILE, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_custom_ports(self):
        try:
            with open(CUSTOM_PORTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.custom_ports, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
