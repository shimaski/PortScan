import socket
import ipaddress
from urllib.parse import urlparse
import concurrent.futures
import nmap

def verificar_portas(alvo, portas):
    print(f"Verificando portas para {alvo}...")
    resultados = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futuros = {executor.submit(verificar_porta, alvo, porta): porta for porta in portas}
        for futuro in concurrent.futures.as_completed(futuros):
            porta = futuros[futuro]
            try:
                resultado = futuro.result()
                if resultado:
                    resultados.append(porta)
            except Exception as exc:
                print(f'A verificação da porta {porta} gerou uma exceção: {exc}')
    return resultados

def verificar_porta(alvo, porta):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    resultado = sock.connect_ex((alvo, porta))
    sock.close()
    return resultado == 0

def sugerir_metodos_intrusao(porta):
    metodos = {
        21: "FTP - Possível ataque de força bruta ou exploração de vulnerabilidades no servidor FTP",
        22: "SSH - Tentativa de força bruta ou exploração de vulnerabilidades SSH",
        23: "Telnet - Interceptação de tráfego não criptografado",
        80: "HTTP - Ataques de injeção SQL, XSS ou exploração de vulnerabilidades web",
        443: "HTTPS - Ataques man-in-the-middle ou exploração de vulnerabilidades SSL/TLS",
        3306: "MySQL - Ataque de força bruta ou exploração de vulnerabilidades no banco de dados",
        3389: "RDP - Ataque de força bruta ou exploração de vulnerabilidades no protocolo RDP"
    }
    print(f"Possíveis métodos de intrusão para a porta {porta}:")
    print(metodos.get(porta, "Método de intrusão desconhecido para esta porta"))

def identificar_servicos(alvo, portas_abertas):
    nm = nmap.PortScanner()
    print("Identificando serviços nas portas abertas...")
    nm.scan(alvo, ','.join(map(str, portas_abertas)))
    for porta in portas_abertas:
        try:
            servico = nm[alvo]['tcp'][porta]['name']
            print(f"Porta {porta}: {servico}")
        except:
            print(f"Não foi possível identificar o serviço na porta {porta}")

def main():
    alvo = input("Digite o endereço IP ou URL do site: ")
    
    try:
        ip = ipaddress.ip_address(alvo)
    except ValueError:
        parsed_url = urlparse(alvo)
        if not parsed_url.scheme:
            alvo = "http://" + alvo
            parsed_url = urlparse(alvo)
        try:
            ip = socket.gethostbyname(parsed_url.netloc)
        except socket.gaierror:
            print("Não foi possível resolver o nome do host.")
            return

    portas_comuns = range(1, 1025)  # Verifica as primeiras 1024 portas
    portas_abertas = verificar_portas(ip, portas_comuns)
    
    if portas_abertas:
        print("\nPortas abertas encontradas:")
        for porta in portas_abertas:
            print(f"Porta {porta} está aberta")
            sugerir_metodos_intrusao(porta)
        
        identificar_servicos(str(ip), portas_abertas)
    else:
        print("Nenhuma porta aberta encontrada.")

if __name__ == "__main__":
    main()

print("\nObrigado por usar nosso scanner de portas!")
print("Lembre-se de usar esta ferramenta apenas em redes e sistemas que você tem permissão para testar.")
print("O uso não autorizado pode ser ilegal.")

# Adicione aqui qualquer limpeza ou fechamento de recursos necessários

# Registrar a execução do programa
import datetime
with open("log_execucao.txt", "a") as log_file:
    log_file.write(f"Programa executado em: {datetime.datetime.now()}\n")


