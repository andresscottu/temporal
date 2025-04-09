#!/bin/bash

# Definicion colores 

BLUE='\033[1;34m'
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m' # Reset


# Declaracion de arreglos asociativos para guardar datos por segmento
declare -A segments
declare -A targets
declare -A spoof_ips

# Solicitar numero de segmentos
read -p "¿Cuantos segmentos quieres atacar? " num_segments

# Validar que sea un numero
if ! [[ "$num_segments" =~ ^[0-9]+$ ]]; then
    echo "Por favor ingresa un número valido."
    exit 1
fi

# Recopilar informacion por cada segmento
for ((i = 1; i <= num_segments; i++)); do
    echo "Segmento $i:"
    read -p "  Segmento (ej. 10.116.21.0/26): " segment
    read -p "  IP principal a atacar: " ip_target
    read -p "  IPs de enmascaramiento (separadas por comas): " spoof

    segments["$i"]="$segment"
    targets["$i"]="$ip_target"
    spoof_ips["$i"]="$spoof"
done

# Procesar cada segmento
for i in "${!segments[@]}"; do
    segment="${segments[$i]}"
    target="${targets[$i]}"
    spoof_list="${spoof_ips[$i]}"
    spoof_array=(${spoof_list//,/ })

    # Crear carpetas base
    base_output_dir="attack_results"
    mkdir -p "$base_output_dir/scan1_nmap"
    mkdir -p "$base_output_dir/scan2_hping3"
    mkdir -p "$base_output_dir/scan3_fragmented"
    mkdir -p "$base_output_dir/scan4_decoys"

	output_nmap="${base_output_dir}/scan1_nmap/ip_scan_${segment//\//_}.txt"
	echo 
    echo -e "${BLUE}=== Escaneando segmento $segment con nmap ===${NC}"
	echo 
	echo -e "${BLUE}Comando: sudo nmap -sS --min-rate 5000 -Pn -n $segment -oN $output_nmap${NC}"
	echo
    sudo nmap -sS --min-rate 5000 -Pn -n "$segment" -oN "$output_nmap"

    if grep -E "open|filtered" "$output_nmap" > /dev/null; then
		echo
        echo -e "${RED}[ALERTA] Puertos abiertos o filtrados en $segment${NC}"
		echo
        cp "$output_nmap" "${base_output_dir}/scan1_nmap/no_compliant_${segment//\//_}.txt"
    else
		echo
		echo -e "${GREEN}[OK] Segmento $segment sin hallazgos. Cumple con la segmentacion.${NC}"
		echo
	fi
	
	echo
    echo -e "${BLUE}=== Realizando hping3 desde IPs enmascaradas a $target ===${NC}"
	echo
    output_hping="${base_output_dir}/scan2_hping3/hping3_scan_${segment//\//_}.txt"
    > "$output_hping"

    for spoof_ip in "${spoof_array[@]}"; do
        for proto in "" "-1" "-2"; do
            cmd="sudo hping3 -c 1 $proto $target -a $spoof_ip"
			echo
            echo -e "${BLUE}Ejecutando: $cmd${NC}" >> "$output_hping"
			echo
            eval $cmd >> "$output_hping" 2>&1

            cmd_nospoof="sudo hping3 -c 1 $proto $target"
			echo
            echo -e "${BLUE}Ejecutando (directo): $cmd_nospoof${NC}" >> "$output_hping"
			echo
            eval $cmd_nospoof >> "$output_hping" 2>&1
        done
    done

    if grep -Ei "len=|ttl=|icmp_seq=|[0-9]+\s+packets\s+received" "$output_hping" | grep -v "0 packets received" > /dev/null; then
		echo
        echo -e "${RED}[ALERTA] Respuesta detectada en hping3 para $target${NC}"
		echo
        cp "$output_hping" "${base_output_dir}/scan2_hping3/no_compliant_${segment//\//_}.txt"
    else
		echo
		echo -e "${GREEN}[OK] Segmento $segment sin hallazgos. Cumple con la segmentacion.${NC}"
		echo
	fi

	echo
    echo -e "${BLUE}=== Realizando escaneo fragmentado con Nmap a $target ===${NC}"
	echo
    output_scan3="${base_output_dir}/scan3_fragmented/scan3_${segment//\//_}.txt"
    sudo nmap -sS -T5 -f -Pn "$target" -oN "$output_scan3"
	echo
	echo -e "${BLUE}Comando: sudo nmap -sS -T5 -f -Pn $target -oN $output_scan3${NC}"
	echo 
    if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\|filtered)[[:space:]]+" "$output_scan3" > /dev/null; then
		echo
        echo -e "${RED}[ALERTA] Respuesta detectada en hping3 para $target${NC}"
		echo
        cp "$output_scan3" "${base_output_dir}/scan3_fragmented/no_compliant_${segment//\//_}.txt"
    else
		echo
		echo -e "${GREEN}[OK] Segmento $segment sin hallazgos. Cumple con la segmentacion.${NC}"
		echo
	fi

	echo
    echo -e "${BLUE}=== Realizando escaneo con decoys a $target ===${NC}"
	echo
    decoys=$(IFS=,; echo "${spoof_array[*]},ME")
    output_scan4="${base_output_dir}/scan4_decoys/scan4_${segment//\//_}.txt"
    sudo nmap -sS -T5 -n -Pn -D "$decoys" "$target" -oN "$output_scan4"
	echo
	echo -e "${BLUE}Comando: sudo nmap -sS T5 -n -Pn -D $decoys $target -oN $output_scan4${NC}" 
	echo
    if grep -E "^[0-9]+/tcp[[:space:]]+(open|filtered|open\|filtered)[[:space:]]+" "$output_scan4" > /dev/null; then
		echo
        echo "[ALERTA] Puertos abiertos o filtrados en escaneo con decoys para $target"
		echo
        cp "$output_scan4" "${base_output_dir}/scan4_decoys/no_compliant_${segment//\//_}.txt"
    else
		echo
		echo -e "${GREEN}[OK] Segmento $segment sin hallazgos. Cumple con la segmentacion.${NC}"
		echo
	fi

    echo -e "${GREEN}>>> Segmento $segment finalizado <<<${NC}"
    echo "======================================="
done

