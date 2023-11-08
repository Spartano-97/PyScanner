import socket
import pyfiglet
import json

OPEN_PORTS = []
PORTS_DATA_JSON = {1: "fast_scan_ports.json", 2: "deep_scan_ports.json"}

def get_json_data(json_file):
    with open(json_file, "r") as file:
        data = json.load(file)
    return data

def get_ports_info(option):
    data = get_json_data(PORTS_DATA_JSON[option])
    return {int(k) : v for (k, v) in data.items()}

def get_ip_addr(target):
    try:
        ip_addr = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Errore: non e' stato possibile gestire il target fornito: {e}")
    else:
        return ip_addr

# Funzione principale per la scansione della porta
def scan_port(ip, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.settimeout(1.0)
    connection_status = soc.connect_ex((ip, port))
    if connection_status == 0:
        OPEN_PORTS.append(port)
    soc.close()

if __name__ == "__main__":
    print(pyfiglet.figlet_format("TCP PortScanner", justify = "center"))
    print(pyfiglet.figlet_format("by LoSpartano", justify = "center"))

    # Selezione del target per la scansione delle porte
    target = input("Inserire il target per il port scan: ")
    ip_addr = get_ip_addr(target)
    print(f"Inizializzo lo scan delle porte per l'indirizzo IP: {ip_addr}")

    # Selezione della tipologia di scan
    while True:
        try:
            scan_option = int(input("""Selezionare la tipologia di scan <int>:
            1. Fast Scan
            2. Deep Scan\n"""))      
            if scan_option == 1 or scan_option == 2:
                ports_info = get_ports_info(scan_option)
                break
            else: 
                print("Errore: E' stata selezionata un'opzione non valida riprovare\n")
        except:
            print("Errore: E' stata inserita una tipologia di input non valida, utilizzare un <int> per la selezione della tipologia di scan\n")

    # Start per lo scanning delle porte
    for port in ports_info.keys():
        try:
            print(f"Scanning: {ip_addr}:{port}")            
            scan_port(ip_addr, port)
        except KeyboardInterrupt:
            print("\nAnnullamento scansione porte...")
            break

    # Print del risultato delle scansioni
    print(f"Sono state trovate le seguenti porte aperte:")
    for port in OPEN_PORTS:
        print(ip_addr, str(port), ports_info[port])