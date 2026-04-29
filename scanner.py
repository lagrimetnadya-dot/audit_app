import socket

def scan_ports(target):
    open_ports = []
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)

        try:
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)  # فقط رقم
        except:
            pass

        s.close()

    return open_ports