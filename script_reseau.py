import pyshark

# Chemin d'accès au fichier pcap
pcap_file = '4gpcap.pcap'

# Ouvrir le fichier pcap
capture = pyshark.FileCapture(pcap_file)

# Initialiser les variables de statistiques
total_packets = 0
total_bytes = 0
packet_lengths = {}
packet_sources = {}
packet_destinations = {}
protocols = {}
tcp_source_ports = {}
tcp_destination_ports = {}
tcp_packets = 0
udp_packets = 0
http_requests = 0
http_responses = 0
ssl_handshakes = 0
total_dns_requests = 0
dns_request_names = {}
dns_request_types = {}
dns_response_codes = {}
dns_response_lengths = {}

# Parcourir chaque paquet dans le fichier pcap
for packet in capture:
        # Vérifier si le paquet est une requête DNS
    if 'DNS' in packet and packet.dns.qry_name:

        # Incrémenter le nombre total de requêtes DNS
        total_dns_requests += 1

        # Ajouter le nom de la requête DNS à un dictionnaire pour les noms de requête DNS
        dns_request_name = packet.dns.qry_name.lower()
        if dns_request_name in dns_request_names:
            dns_request_names[dns_request_name] += 1
        else:
            dns_request_names[dns_request_name] = 1

        # Ajouter le type de la requête DNS à un dictionnaire pour les types de requête DNS
        dns_request_type = packet.dns.qry_type
        if dns_request_type in dns_request_types:
            dns_request_types[dns_request_type] += 1
        else:
            dns_request_types[dns_request_type] = 1
        try:
            # Ajouter le code de réponse DNS à un dictionnaire pour les codes de réponse DNS
            dns_response_code = packet.dns.respcode
            if dns_response_code in dns_response_codes:
                dns_response_codes[dns_response_code] += 1
            else:
                dns_response_codes[dns_response_code] = 1
        except:
            pass
        try:
        # Ajouter la longueur de la réponse DNS à un dictionnaire pour les longueurs de réponse DNS
            dns_response_length = packet.dns.resp_len
            if dns_response_length in dns_response_lengths:
                dns_response_lengths[dns_response_length] += 1
            else:
                dns_response_lengths[dns_response_length] = 1
        except:
            pass
        # Analyser les ports source et destination pour les paquets TCP
    if 'tcp' in packet:
        source_port = packet.tcp.srcport
        if source_port in tcp_source_ports:
            tcp_source_ports[source_port] += 1
        else:
            tcp_source_ports[source_port] = 1

        destination_port = packet.tcp.dstport
        if destination_port in tcp_destination_ports:
            tcp_destination_ports[destination_port] += 1
        else:
            tcp_destination_ports[destination_port] = 1
    # Analyser les protocoles utilisés
    for layer in packet.layers:
        if layer.layer_name in protocols:
            protocols[layer.layer_name] += 1
        else:
            protocols[layer.layer_name] = 1
    # Incrémenter le nombre total de paquets
    total_packets += 1

    # Ajouter la longueur du paquet au total des octets
    total_bytes += int(packet.length)

    # Ajouter la longueur du paquet à un dictionnaire pour les longueurs de paquets
    packet_length = int(packet.length)
    if packet_length in packet_lengths:
        packet_lengths[packet_length] += 1
    else:
        packet_lengths[packet_length] = 1

    # Ajouter les adresses sources et destinations à des dictionnaires distincts
    try:
        source_address = packet.ip.src
        if source_address in packet_sources:
            packet_sources[source_address] += 1
        else:
            packet_sources[source_address] = 1

        destination_address = packet.ip.dst
        if destination_address in packet_destinations:
            packet_destinations[destination_address] += 1
        else:
            packet_destinations[destination_address] = 1
    except:
        pass
        # Compter les paquets TCP et UDP
    if 'tcp' in packet:
        tcp_packets += 1
    elif 'udp' in packet:
        udp_packets += 1

    # Compter les requêtes HTTP et les réponses HTTP
    try:
        if 'http' in packet:
            if packet.http.request_method:
                http_requests += 1
            elif packet.http.response_for:
                http_responses += 1
    except:
        pass

    # Compter les poignées de main SSL/TLS
    try:
        if 'tls' in packet or 'SSL' in packet:
            if packet.ssl.handshake:
                ssl_handshakes += 1
    except:
        pass


# Fermer la capture
capture.close()

# Imprimer les statistiques
print("Nombre total de paquets : ", total_packets)
print("Nombre total d'octets : ", total_bytes)
print("Longueurs de paquets : ", packet_lengths)
print("Sources de paquets : ", packet_sources)
print("Destinations de paquets : ", packet_destinations)
print("Protocoles utilisés : ", protocols)
print("Nombre de paquets TCP : ", tcp_packets)
print("Nombre de paquets UDP : ", udp_packets)
print("Nombre de requêtes HTTP : ", http_requests)
print("Nombre de réponses HTTP : ", http_responses)
print("Nombre de poignées de main SSL/TLS : ", ssl_handshakes)
print("Ports source TCP utilisés : ", tcp_source_ports)
print("Ports destination TCP utilisés : ", tcp_destination_ports)
print("Nombre total de requêtes DNS : ", total_dns_requests)
print("Noms de requête DNS : ", dns_request_names)
print("Types de requête DNS : ", dns_request_types)
print("Codes de réponse DNS : ", dns_response_codes)
print("Longueurs de réponse DNS : ", dns_response_lengths)