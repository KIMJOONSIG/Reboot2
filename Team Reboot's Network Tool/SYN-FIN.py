import scapy.all as scapy
import subprocess

def packet_callback(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        ip_layer = packet[scapy.IP]
        tcp_layer = packet[scapy.TCP]

        if tcp_layer.flags == "F" and tcp_layer.flags == "ACK":
            print("Detected ACK-FIN packet combination:")
            print(packet.summary())
            # Add your custom logic here, e.g., perform an action based on the packet.

def main():
    iface = "eth0"  # 네트워크 인터페이스 이름을 적절하게 변경하세요.
    scapy.sniff(iface=iface, filter="tcp", prn=packet_callback)

if __name__ == "__main__":
    main()

# Check iptables rules using subprocess
def check_iptables_rules():
    cmd = "iptables -L INPUT -n"
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
        print("Current iptables rules:")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error:", e)

if __name__ == "__main__":
    check_iptables_rules()
