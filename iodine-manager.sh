#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

CONF_DIR="/etc/iodine-manager"
CONF_FILE="$CONF_DIR/tunnel.conf"
PASSWORD_FILE="$CONF_DIR/password"
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="iodine-mgr"
LOG_FILE="/var/log/iodine-manager.log"
LOCK_FILE="/var/run/iodine-manager.lock"
TUN_SERVER_IP="10.50.50.1"
DNS_RESOLVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")
LOG_MAX_SIZE=$((5 * 1024 * 1024))

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "Another instance is running."
    exit 1
fi

cleanup_on_exit() {
    rm -f /tmp/iodine-mgr-* 2>/dev/null
    flock -u 200 2>/dev/null
    unset PASSWORD PASSWORD2
}

trap cleanup_on_exit EXIT
trap 'echo -e "\n${YELLOW}Interrupted${NC}"; cleanup_on_exit; exit 130' INT TERM

log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    if [ -f "$LOG_FILE" ]; then
        local log_size
        log_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$log_size" -gt "$LOG_MAX_SIZE" ]; then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            gzip "${LOG_FILE}.old" 2>/dev/null &
        fi
    fi
    echo "$message" >> "$LOG_FILE"
    case $level in
        ERROR) echo -e "${RED}[ERROR] $*${NC}" >&2 ;;
        WARN)  echo -e "${YELLOW}[WARN] $*${NC}" >&2 ;;
        INFO)  echo -e "${GREEN}[INFO] $*${NC}" ;;
        *)     echo "$message" ;;
    esac
}

validate_domain() {
    local domain=$1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_port_list() {
    local port_list=$1
    IFS=',' read -ra PORTS <<< "$port_list"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        validate_port "$port" || return 1
    done
    return 0
}

load_config() {
    local conf_file="$1"
    if [ ! -f "$conf_file" ]; then
        log ERROR "Config file not found: $conf_file"
        return 1
    fi
    local file_owner
    file_owner=$(stat -c '%u' "$conf_file")
    if [ "$file_owner" != "0" ]; then
        log ERROR "Config file not owned by root"
        return 1
    fi
    local allowed_keys=(ROLE DOMAIN PORT_LIST MTU_SIZE DNS_TYPE DOWN_CODEC LAZY_INTERVAL FORCE_DNS MAX_HOSTNAME_LEN)
    ROLE=""
    DOMAIN=""
    PORT_LIST=""
    MTU_SIZE=""
    DNS_TYPE=""
    DOWN_CODEC=""
    LAZY_INTERVAL=""
    FORCE_DNS=""
    MAX_HOSTNAME_LEN=""
    while IFS='=' read -r key value; do
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        local valid=false
        for allowed in "${allowed_keys[@]}"; do
            if [ "$key" == "$allowed" ]; then
                valid=true
                break
            fi
        done
        if ! $valid; then
            log WARN "Ignoring unknown config key: $key"
            continue
        fi
        if [[ "$value" =~ [^a-zA-Z0-9.,_:/-] ]]; then
            log WARN "Suspicious value for $key, skipping"
            continue
        fi
        declare -g "$key=$value"
    done < "$conf_file"
    if [[ -n "$ROLE" && "$ROLE" != "server" && "$ROLE" != "client" ]]; then
        log ERROR "Invalid ROLE value: $ROLE"
        return 1
    fi
    if [[ -n "$DOMAIN" ]] && ! validate_domain "$DOMAIN"; then
        log ERROR "Invalid DOMAIN value: $DOMAIN"
        return 1
    fi
    if [[ -n "$MTU_SIZE" && ! "$MTU_SIZE" =~ ^[0-9]+$ ]]; then
        log ERROR "Invalid MTU_SIZE: $MTU_SIZE"
        return 1
    fi
    if [[ -n "$LAZY_INTERVAL" && ! "$LAZY_INTERVAL" =~ ^[0-9]+$ ]]; then
        log ERROR "Invalid LAZY_INTERVAL: $LAZY_INTERVAL"
        return 1
    fi
    return 0
}

show_progress() {
    local duration=${1}
    local prefix=${2}
    local block="█"
    local empty="░"
    local width=30
    echo -ne "${prefix} "
    for (( i=0; i<=$width; i++ )); do
        local percent=$(( i * 100 / width ))
        local num_block=$i
        local num_empty=$(( width - i ))
        local bar_str=""
        for (( j=0; j<num_block; j++ )); do bar_str="${bar_str}${block}"; done
        for (( j=0; j<num_empty; j++ )); do bar_str="${bar_str}${empty}"; done
        echo -ne "[${BLUE}${bar_str}${NC}] ${percent}%\r"
        sleep "$duration"
    done
    echo -ne "\n"
}

draw_header() {
    clear
    local service_stat="inactive"
    local role="NONE"
    if systemctl is-active --quiet iodine-server; then
        service_stat="${GREEN}RUNNING${NC}"
        role="SERVER"
    elif systemctl is-active --quiet iodine-client; then
        service_stat="${GREEN}RUNNING${NC}"
        role="CLIENT"
    else
        service_stat="${RED}STOPPED${NC}"
    fi
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}I O D I N E   D N S   T U N N E L   M A N A G E R${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                 ${YELLOW}Created by: Dnt3e${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Status: ${service_stat}     Role: ${YELLOW}${role}${NC}"
    if [[ "$service_stat" == *"RUNNING"* ]]; then
        local tun_ip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        [ -n "$tun_ip" ] && echo -e "${CYAN}║${NC}  Tunnel IP: ${BLUE}${tun_ip}${NC}"
    fi
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
}

preflight_checks() {
    if [ ! -e /dev/net/tun ]; then
        log ERROR "/dev/net/tun not found"
        echo -e "${RED}TUN device not available${NC}" >&2
        echo -e "${YELLOW}Run: mkdir -p /dev/net && mknod /dev/net/tun c 10 200${NC}" >&2
        exit 1
    fi
    if ! lsmod | grep -q tun 2>/dev/null; then
        modprobe tun 2>/dev/null || true
    fi
    local free_space
    free_space=$(df -m /etc 2>/dev/null | awk 'NR==2{print $4}')
    if [ -n "$free_space" ] && [ "$free_space" -lt 50 ]; then
        log WARN "Low disk space: ${free_space}MB"
        echo -e "${YELLOW}Warning: Low disk space: ${free_space}MB free${NC}" >&2
    fi
}

preflight_checks

enable_ip_forward_permanent() {
    log INFO "Enabling permanent IP forwarding"
    echo -e "${YELLOW}Enabling IP forwarding (permanent)...${NC}" >&2
    sysctl -w net.ipv4.ip_forward=1 >> "$LOG_FILE" 2>&1
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iodine.conf
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}✓ IP forwarding enabled (persists after reboot)${NC}" >&2
    log INFO "IP forwarding configured permanently"
}

mtu_detect() {
    local target=$1
    log INFO "Starting binary search MTU detection for $target"
    echo -e "${YELLOW}Detecting optimal MTU via binary search...${NC}" >&2
    local low=1280
    local high=1500
    local optimal=$low
    if ! ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Target unreachable, using default MTU 1280${NC}" >&2
        echo "1280"
        return
    fi
    while [ $low -le $high ]; do
        local mid=$(( (low + high) / 2 ))
        echo -ne "Testing MTU ${CYAN}${mid}${NC}... " >&2
        if ping -M do -s $((mid - 28)) -c 2 -W 2 "$target" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}" >&2
            optimal=$mid
            low=$((mid + 1))
        else
            echo -e "${RED}✗${NC}" >&2
            high=$((mid - 1))
        fi
    done
    log INFO "Optimal MTU detected: $optimal"
    echo -e "${GREEN}✓ Optimal MTU: ${BOLD}$optimal${NC}" >&2
    echo "$optimal"
}

test_dns_multi() {
    local domain=$1
    log INFO "Testing DNS delegation for $domain"
    echo -e "${YELLOW}Testing DNS delegation...${NC}"
    local resolvers_ok=0
    for resolver in "${DNS_RESOLVERS[@]}"; do
        echo -ne "Resolver ${CYAN}${resolver}${NC}... "
        local ns_result=$(dig +short NS "$domain" "@$resolver" +time=2 +tries=1 2>/dev/null | head -n1)
        if [ -n "$ns_result" ]; then
            echo -e "${GREEN}✓${NC}"
            ((resolvers_ok++))
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    if [ $resolvers_ok -eq 0 ]; then
        log ERROR "No NS records found for $domain"
        echo -e "\n${RED}⚠ No NS records found!${NC}"
        echo -e "${YELLOW}Required DNS setup:${NC}"
        echo -e "1. A record:  ${CYAN}tun.yourdomain.com${NC} → Your IP"
        echo -e "2. NS record: ${CYAN}$domain${NC} → ${CYAN}tun.yourdomain.com${NC}"
        echo ""
        read -p "Continue anyway? (y/n): " cont
        [[ "$cont" =~ ^[Yy]$ ]] || return 1
    else
        echo -e "${GREEN}✓ DNS working on $resolvers_ok/${#DNS_RESOLVERS[@]} resolvers${NC}"
    fi
    return 0
}

fw_apply() {
    log INFO "Applying firewall rules"
    if [ ! -f "$CONF_FILE" ]; then
        log ERROR "Config file not found"
        echo -e "${RED}Error: Run setup first${NC}" >&2
        return 1
    fi
    load_config "$CONF_FILE" || return 1
    local DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -z "$DEFAULT_IF" ]; then
        log ERROR "Cannot determine default interface"
        return 1
    fi
    echo -e "${YELLOW}Configuring firewall on $DEFAULT_IF...${NC}"
    enable_ip_forward_permanent
    iptables -t nat -N IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST 2>/dev/null
    iptables -t nat -A IODINE_POST -s 10.50.50.0/24 -o "$DEFAULT_IF" -j MASQUERADE
    if ! iptables -t nat -C POSTROUTING -j IODINE_POST 2>/dev/null; then
        iptables -t nat -A POSTROUTING -j IODINE_POST
    fi
    iptables -D FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT
    iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    if [ "$ROLE" == "client" ] && [ -n "$PORT_LIST" ]; then
        iptables -t nat -N IODINE_PRE 2>/dev/null
        iptables -t nat -F IODINE_PRE 2>/dev/null
        IFS=',' read -ra PORTS <<< "$PORT_LIST"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            validate_port "$port" || continue
            iptables -t nat -A IODINE_PRE -i "$DEFAULT_IF" -p tcp --dport "$port" -j DNAT --to-destination "$TUN_SERVER_IP:$port"
            iptables -t nat -A IODINE_PRE -i "$DEFAULT_IF" -p udp --dport "$port" -j DNAT --to-destination "$TUN_SERVER_IP:$port"
            iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -p udp --dport "$port" -j ACCEPT 2>/dev/null
            echo -e "${GREEN}✓ Port $port → $TUN_SERVER_IP (via $DEFAULT_IF)${NC}"
        done
        if ! iptables -t nat -C PREROUTING -j IODINE_PRE 2>/dev/null; then
            iptables -t nat -A PREROUTING -j IODINE_PRE
        fi
    fi
    echo -e "${GREEN}✓ Firewall configured${NC}"
    log INFO "Firewall rules applied successfully"
}

fw_clean() {
    log INFO "Removing firewall rules"
    echo -e "${YELLOW}Cleaning firewall rules...${NC}"
    iptables -t nat -D POSTROUTING -j IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST 2>/dev/null
    iptables -t nat -X IODINE_POST 2>/dev/null
    iptables -t nat -D PREROUTING -j IODINE_PRE 2>/dev/null
    iptables -t nat -F IODINE_PRE 2>/dev/null
    iptables -t nat -X IODINE_PRE 2>/dev/null
    local DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -n "$DEFAULT_IF" ]; then
        iptables -D FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi
    echo -e "${GREEN}✓ Firewall cleaned${NC}"
    log INFO "Firewall cleanup completed"
}

service_create() {
    local service_name="iodine-${ROLE}"
    local exec_cmd=""
    local password
    password=$(cat "$PASSWORD_FILE" 2>/dev/null)
    if [ -z "$password" ]; then
        log ERROR "Password file empty or missing"
        return 1
    fi
    log INFO "Creating systemd service: $service_name"
    if [ "$ROLE" == "server" ]; then
        exec_cmd="/usr/sbin/iodined -f -c -P ${password}"
        [ -n "$MTU_SIZE" ] && exec_cmd="$exec_cmd -M $MTU_SIZE"
        [ -n "$DNS_TYPE" ] && exec_cmd="$exec_cmd -T $DNS_TYPE"
        [ -n "$LAZY_INTERVAL" ] && exec_cmd="$exec_cmd -I $LAZY_INTERVAL"
        exec_cmd="$exec_cmd $TUN_SERVER_IP $DOMAIN"
    else
        exec_cmd="/usr/sbin/iodine -f -P ${password}"
        [ -n "$MTU_SIZE" ] && exec_cmd="$exec_cmd -M $MTU_SIZE"
        [ -n "$MAX_HOSTNAME_LEN" ] && exec_cmd="$exec_cmd -m $MAX_HOSTNAME_LEN"
        [ -n "$DNS_TYPE" ] && exec_cmd="$exec_cmd -T $DNS_TYPE"
        [ -n "$DOWN_CODEC" ] && exec_cmd="$exec_cmd -O $DOWN_CODEC"
        [ -n "$LAZY_INTERVAL" ] && exec_cmd="$exec_cmd -I $LAZY_INTERVAL"
        [ "$FORCE_DNS" == "yes" ] && exec_cmd="$exec_cmd -r"
        exec_cmd="$exec_cmd $DOMAIN"
    fi
    cat <<EOF > /etc/systemd/system/${service_name}.service
[Unit]
Description=Iodine DNS Tunnel ($ROLE)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$exec_cmd
ExecStartPost=/bin/sleep 3
ExecStartPost=$INSTALL_DIR/$SCRIPT_NAME --apply-fw
ExecStopPost=$INSTALL_DIR/$SCRIPT_NAME --clean-fw
Restart=always
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=iodine-${ROLE}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${service_name}" >/dev/null 2>&1
    systemctl restart "${service_name}"
    sleep 4
    if ! systemctl is-active --quiet "${service_name}"; then
        log ERROR "Service failed to start"
        echo -e "${RED}✗ Tunnel failed to start${NC}"
        echo -e "Check logs: ${YELLOW}journalctl -u ${service_name} -n 20${NC}"
        return 1
    fi
    log INFO "Service $service_name started successfully"
    return 0
}

install_deps() {
    log INFO "Checking dependencies"
    echo -e "${YELLOW}Checking dependencies...${NC}"
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    local missing_tools=()
    for tool in iodined iodine iptables lsof dig; do
        command -v "$tool" &>/dev/null || missing_tools+=("$tool")
    done
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log INFO "Installing: ${missing_tools[*]}"
        local install_ok=false
        if [ -f /etc/debian_version ]; then
            if ! apt-get update -qq 2>>"$LOG_FILE"; then
                log ERROR "apt-get update failed"
                exit 1
            fi
            if apt-get install -y -qq iodine iproute2 iptables lsof dnsutils bc >>"$LOG_FILE" 2>&1; then
                install_ok=true
            fi
        elif [ -f /etc/redhat-release ]; then
            yum install -y -q epel-release >>"$LOG_FILE" 2>&1 || true
            if yum install -y -q iodine iproute iptables lsof bind-utils bc >>"$LOG_FILE" 2>&1; then
                install_ok=true
            fi
        elif [ -f /etc/arch-release ]; then
            if pacman -S --noconfirm iodine iproute2 iptables lsof bind-tools bc >>"$LOG_FILE" 2>&1; then
                install_ok=true
            fi
        else
            log ERROR "Unsupported distribution"
            echo -e "${RED}Unsupported Linux distribution${NC}"
            exit 1
        fi
        if ! $install_ok; then
            log ERROR "Package installation failed"
            echo -e "${RED}Installation failed. Check $LOG_FILE${NC}"
            exit 1
        fi
        for tool in iodined iodine iptables; do
            if ! command -v "$tool" &>/dev/null; then
                log ERROR "$tool still not found after install"
                echo -e "${RED}$tool not found after installation${NC}"
                exit 1
            fi
        done
    fi
    local current_path
    current_path="$(realpath "$0" 2>/dev/null || readlink -f "$0")"
    if [[ "$current_path" != "$INSTALL_DIR/$SCRIPT_NAME" ]]; then
        cp "$current_path" "$INSTALL_DIR/$SCRIPT_NAME"
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
        log INFO "Script installed to $INSTALL_DIR/$SCRIPT_NAME"
    fi
    echo -e "${GREEN}✓ Dependencies ready${NC}"
    log INFO "Dependencies check completed"
}

check_port_53() {
    log INFO "Checking UDP port 53"
    echo -e "${YELLOW}Checking UDP port 53...${NC}"
    local occupier=$(lsof -i UDP:53 -t 2>/dev/null | head -n1)
    if [ -n "$occupier" ]; then
        local process_name=$(ps -p "$occupier" -o comm= 2>/dev/null || echo "unknown")
        log WARN "Port 53 busy: $process_name (PID: $occupier)"
        echo -e "${RED}Port 53 occupied by: ${BOLD}$process_name${NC}"
        if [[ "$process_name" == *"systemd-resolve"* ]] || [[ "$process_name" == "systemd-resolved" ]]; then
            read -p "Stop systemd-resolved? (y/n): " fix_dns
            if [[ "$fix_dns" =~ ^[Yy]$ ]]; then
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ] && \
                    cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%s)
                rm -f /etc/resolv.conf
                cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF
                chmod 644 /etc/resolv.conf
                echo -e "${GREEN}✓ Port 53 freed${NC}"
                log INFO "DNS conflict resolved"
            else
                log ERROR "User aborted - port 53 busy"
                exit 1
            fi
        else
            echo -e "${YELLOW}Free manually: sudo kill $occupier${NC}"
            log ERROR "Unknown process on port 53"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ Port 53 available${NC}"
    fi
}

test_dns_types() {
    local domain=$1
    echo -e "\n${BOLD}Testing DNS request types...${NC}"
    for type in NULL TXT SRV MX CNAME; do
        local result=$(dig +short -t "$type" "z456.$domain" "@${DNS_RESOLVERS[0]}" +time=2 2>/dev/null | head -n1)
        if [ -n "$result" ]; then
            echo -e "${GREEN}✓ $type${NC}"
        else
            echo -e "${RED}✗ $type${NC}"
        fi
    done
    echo -e "\n${CYAN}Tip: NULL is fastest, TXT/SRV work if NULL blocked${NC}"
    read -p "Press Enter..."
}

save_password() {
    local password="$1"
    local password_file="$2"
    (
        umask 077
        printf '%s' "$password" > "$password_file"
    )
    if [ ! -f "$password_file" ]; then
        log ERROR "Failed to save password file"
        return 1
    fi
    chown root:root "$password_file"
    chmod 600 "$password_file"
    log INFO "Password saved securely"
    return 0
}

read_password() {
    local password=""
    local password2=""
    while true; do
        read -rs -p "Tunnel Password (min 8 chars): " password
        echo
        if [ ${#password} -lt 8 ]; then
            echo -e "${RED}Password too short (min 8 characters)${NC}"
            continue
        fi
        read -rs -p "Confirm: " password2
        echo
        if [ "$password" == "$password2" ]; then
            break
        fi
        echo -e "${RED}Passwords don't match${NC}"
    done
    save_password "$password" "$PASSWORD_FILE"
    password=""
    password2=""
    unset password password2
}

run_setup() {
    install_deps
    echo -e "${BOLD}Select Role:${NC}"
    echo "1) Server (Exit Node)"
    echo "2) Client (Entry Point)"
    read -p "Select [1/2]: " opt
    if [ "$opt" == "1" ]; then
        ROLE="server"
        check_port_53
        echo -e "\n${YELLOW}DNS Requirements:${NC}"
        echo "1. A record:  tun.example.com → Your IP"
        echo "2. NS record: t1.example.com → tun.example.com"
        echo ""
        while true; do
            read -p "NS Subdomain (e.g. t1.example.com): " DOMAIN
            validate_domain "$DOMAIN" && break
            echo -e "${RED}Invalid domain format${NC}"
        done
        test_dns_multi "$DOMAIN" || return 1
        read -p "Test DNS request types? (y/n): " test_types
        [[ "$test_types" =~ ^[Yy]$ ]] && test_dns_types "$DOMAIN"
        read_password
        echo -e "\n${BOLD}Advanced Options:${NC}"
        read -p "Auto-detect MTU? (y/n, recommended): " auto_mtu
        if [[ "$auto_mtu" =~ ^[Yy]$ ]]; then
            MTU_SIZE=$(mtu_detect "8.8.8.8")
        else
            read -p "MTU size (default: 1280): " MTU_SIZE
            MTU_SIZE=${MTU_SIZE:-1280}
        fi
        read -p "DNS type (null/txt/srv/mx, default: auto): " DNS_TYPE
        read -p "Lazy interval seconds (default: 4): " LAZY_INTERVAL
        LAZY_INTERVAL=${LAZY_INTERVAL:-4}
        PORT_LIST=""
        FORCE_DNS="no"
        MAX_HOSTNAME_LEN=""
        DOWN_CODEC=""
    elif [ "$opt" == "2" ]; then
        ROLE="client"
        while true; do
            read -p "Server NS Subdomain: " DOMAIN
            validate_domain "$DOMAIN" && break
            echo -e "${RED}Invalid domain format${NC}"
        done
        read_password
        echo -e "\n${YELLOW}Ports to forward (comma-separated, e.g. 443,2053):${NC}"
        while true; do
            read -p "Ports: " PORT_LIST
            [ -z "$PORT_LIST" ] && break
            validate_port_list "$PORT_LIST" && break
            echo -e "${RED}Invalid port format${NC}"
        done
        echo -e "\n${BOLD}Advanced Options:${NC}"
        read -p "Auto-detect MTU? (y/n, recommended): " auto_mtu
        if [[ "$auto_mtu" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Will detect after tunnel is up${NC}"
            MTU_SIZE=""
        else
            read -p "MTU size (default: 1280): " MTU_SIZE
            MTU_SIZE=${MTU_SIZE:-1280}
        fi
        read -p "Max hostname length (default: 255): " MAX_HOSTNAME_LEN
        read -p "DNS type (null/txt/srv/mx, default: auto): " DNS_TYPE
        read -p "Downstream codec (raw/base128/base64, default: auto): " DOWN_CODEC
        read -p "Lazy interval seconds (default: 4): " LAZY_INTERVAL
        LAZY_INTERVAL=${LAZY_INTERVAL:-4}
        read -p "Force DNS mode? (y/n, default: n): " force_answer
        [[ "$force_answer" =~ ^[Yy]$ ]] && FORCE_DNS="yes" || FORCE_DNS="no"
    else
        echo "Invalid option"
        return
    fi
    cat <<EOF > "$CONF_FILE"
ROLE=$ROLE
DOMAIN=$DOMAIN
PORT_LIST=$PORT_LIST
MTU_SIZE=$MTU_SIZE
DNS_TYPE=$DNS_TYPE
DOWN_CODEC=$DOWN_CODEC
LAZY_INTERVAL=$LAZY_INTERVAL
FORCE_DNS=$FORCE_DNS
MAX_HOSTNAME_LEN=$MAX_HOSTNAME_LEN
EOF
    chmod 600 "$CONF_FILE"
    log INFO "Configuration saved"
    systemctl stop iodine-server iodine-client 2>/dev/null
    systemctl disable iodine-server iodine-client 2>/dev/null
    rm -f /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service
    systemctl daemon-reload
    show_progress 0.05 "Creating service"
    if ! service_create; then
        echo -e "${RED}Setup failed${NC}"
        return 1
    fi
    echo -e "\n${GREEN}✓ Iodine $ROLE installed${NC}"
    log INFO "Setup completed"
    if [ "$ROLE" == "client" ] && [ -z "$MTU_SIZE" ]; then
        echo -e "\n${YELLOW}Detecting optimal MTU...${NC}"
        sleep 3
        local detected_mtu
        detected_mtu=$(mtu_detect "$TUN_SERVER_IP")
        if [[ "$detected_mtu" =~ ^[0-9]+$ ]]; then
            MTU_SIZE="$detected_mtu"
            sed -i "s/^MTU_SIZE=.*/MTU_SIZE=$MTU_SIZE/" "$CONF_FILE"
            service_create
            echo -e "${GREEN}✓ MTU set to $MTU_SIZE${NC}"
        else
            echo -e "${YELLOW}⚠ MTU detection failed, using default${NC}"
        fi
    fi
    echo -e "\n${CYAN}Configuration:${NC}"
    echo -e "Role:     ${YELLOW}$ROLE${NC}"
    echo -e "Domain:   ${YELLOW}$DOMAIN${NC}"
    echo -e "MTU:      ${YELLOW}${MTU_SIZE:-auto}${NC}"
    [ -n "$PORT_LIST" ] && echo -e "Ports:    ${YELLOW}$PORT_LIST${NC}"
    echo ""
    read -p "Check status? (y/n): " do_check
    [[ "$do_check" =~ ^[Yy]$ ]] && check_status
}

check_status() {
    draw_header
    echo -e "${BOLD}Interface Status:${NC}"
    if ip addr show dns0 2>/dev/null | grep -q inet; then
        ip addr show dns0 2>/dev/null | grep inet
    else
        echo -e "${RED}⚠ dns0 not found${NC}"
    fi
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "\n${RED}No configuration found${NC}"
        read -p "Press Enter..."
        return
    fi
    load_config "$CONF_FILE" || return
    local svc="iodine-${ROLE}"
    echo -e "\n${BOLD}Service Status:${NC}"
    if systemctl is-active --quiet "$svc"; then
        echo -e "${GREEN}✓ Running${NC}"
        echo ""
        journalctl -u "$svc" --no-pager -n 5 2>/dev/null
    else
        echo -e "${RED}✗ Stopped${NC}"
        systemctl start "$svc"
    fi
    echo -e "\n${BOLD}Connection Test:${NC}"
    if [ "$ROLE" == "server" ]; then
        echo "Server listening on $TUN_SERVER_IP"
    else
        echo -ne "Pinging $TUN_SERVER_IP... "
        if ping -c 3 -W 3 "$TUN_SERVER_IP" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
            local rtt=$(ping -c 10 -q "$TUN_SERVER_IP" 2>/dev/null | grep 'rtt min' | awk -F'/' '{print $5}')
            [ -n "$rtt" ] && echo -e "Latency: ${CYAN}${rtt} ms${NC}"
        else
            echo -e "${RED}✗ Failed${NC}"
        fi
    fi
    echo ""
    read -p "Press Enter..."
}

quick_status() {
    draw_header
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        sleep 2
        return
    fi
    load_config "$CONF_FILE" || return
    local svc="iodine-${ROLE}"
    echo -e "${BOLD}Quick Status:${NC}\n"
    if systemctl is-active --quiet "$svc"; then
        echo -e "Service:  ${GREEN}● Running${NC}"
    else
        echo -e "Service:  ${RED}● Stopped${NC}"
    fi
    if ip link show dns0 >/dev/null 2>&1; then
        local tun_ip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e "Tunnel:   ${GREEN}● Up${NC} (${tun_ip})"
    else
        echo -e "Tunnel:   ${RED}● Down${NC}"
    fi
    if [ "$ROLE" == "client" ]; then
        if ping -c 1 -W 2 "$TUN_SERVER_IP" >/dev/null 2>&1; then
            echo -e "Connect:  ${GREEN}● OK${NC}"
        else
            echo -e "Connect:  ${RED}● Failed${NC}"
        fi
    fi
    echo ""
    read -p "Press Enter..."
}

test_performance() {
    draw_header
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        read -p "Press Enter..."
        return
    fi
    load_config "$CONF_FILE" || return
    if [ "$ROLE" != "client" ]; then
        echo -e "${YELLOW}Performance test only for client mode${NC}"
        read -p "Press Enter..."
        return
    fi
    echo -e "${BOLD}Performance Test${NC}\n"
    echo -e "${CYAN}[1/3] Latency Test${NC}"
    if ping -c 20 -q "$TUN_SERVER_IP" >/dev/null 2>&1; then
        ping -c 20 -q "$TUN_SERVER_IP" | grep 'rtt min'
    else
        echo -e "${RED}Failed${NC}"
    fi
    echo -e "\n${CYAN}[2/3] Recent Logs${NC}"
    journalctl -u iodine-client --since "10 minutes ago" | grep -i "frag\|codec\|kbps" | tail -10
    echo -e "\n${CYAN}[3/3] Interface Stats${NC}"
    ip -s link show dns0 2>/dev/null || echo "Not available"
    echo ""
    read -p "Press Enter..."
}

edit_config() {
    draw_header
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        read -p "Press Enter..."
        return
    fi
    load_config "$CONF_FILE" || return
    echo -e "${BOLD}Configuration Editor${NC}\n"
    echo "1) DNS Type: ${YELLOW}${DNS_TYPE:-auto}${NC}"
    echo "2) MTU Size: ${YELLOW}${MTU_SIZE:-auto}${NC}"
    echo "3) Lazy Interval: ${YELLOW}${LAZY_INTERVAL:-4}s${NC}"
    [ "$ROLE" == "client" ] && echo "4) Codec: ${YELLOW}${DOWN_CODEC:-auto}${NC}"
    echo "5) Change Password"
    echo "0) Back"
    echo ""
    read -p "Edit: " edit_opt
    case $edit_opt in
        1)
            read -p "DNS Type (null/txt/srv/mx): " DNS_TYPE
            sed -i "s/^DNS_TYPE=.*/DNS_TYPE=$DNS_TYPE/" "$CONF_FILE"
            ;;
        2)
            read -p "Auto-detect? (y/n): " auto_mtu
            if [[ "$auto_mtu" =~ ^[Yy]$ ]]; then
                MTU_SIZE=$(mtu_detect "$TUN_SERVER_IP")
                if ! [[ "$MTU_SIZE" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}Detection failed${NC}"
                    read -p "Press Enter..."
                    return
                fi
            else
                read -p "MTU: " MTU_SIZE
            fi
            sed -i "s/^MTU_SIZE=.*/MTU_SIZE=$MTU_SIZE/" "$CONF_FILE"
            ;;
        3)
            read -p "Lazy Interval (s): " LAZY_INTERVAL
            sed -i "s/^LAZY_INTERVAL=.*/LAZY_INTERVAL=$LAZY_INTERVAL/" "$CONF_FILE"
            ;;
        4)
            if [ "$ROLE" == "client" ]; then
                read -p "Codec (raw/base128/base64): " DOWN_CODEC
                sed -i "s/^DOWN_CODEC=.*/DOWN_CODEC=$DOWN_CODEC/" "$CONF_FILE"
            fi
            ;;
        5)
            read_password
            ;;
        0) return ;;
    esac
    echo -e "\n${GREEN}Updated${NC}"
    read -p "Restart service? (y/n): " restart
    if [[ "$restart" =~ ^[Yy]$ ]]; then
        load_config "$CONF_FILE" || return
        service_create
        echo -e "${GREEN}✓ Restarted${NC}"
    fi
    read -p "Press Enter..."
}

backup_config() {
    draw_header
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Nothing to backup${NC}"
        read -p "Press Enter..."
        return
    fi
    local backup_file="$CONF_DIR/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" -C "$CONF_DIR" tunnel.conf password 2>/dev/null
    if [ -f "$backup_file" ]; then
        chmod 600 "$backup_file"
        echo -e "${GREEN}✓ Backup saved: $backup_file${NC}"
        log INFO "Backup created: $backup_file"
    else
        echo -e "${RED}Backup failed${NC}"
    fi
    read -p "Press Enter..."
}

restore_config() {
    draw_header
    echo -e "${BOLD}Available Backups:${NC}\n"
    local backups=()
    while IFS= read -r -d '' file; do
        backups+=("$file")
    done < <(find "$CONF_DIR" -name 'backup-*.tar.gz' -print0 2>/dev/null | sort -rz)
    if [ ${#backups[@]} -eq 0 ]; then
        echo -e "${YELLOW}No backups found${NC}"
        read -p "Press Enter..."
        return
    fi
    local i=1
    for backup in "${backups[@]}"; do
        local bname
        bname=$(basename "$backup")
        local bsize
        bsize=$(du -h "$backup" 2>/dev/null | cut -f1)
        echo "$i) $bname ($bsize)"
        ((i++))
    done
    echo "0) Cancel"
    echo ""
    read -p "Restore: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Invalid input${NC}"
        read -p "Press Enter..."
        return
    fi
    if [ "$choice" -eq 0 ] || [ "$choice" -gt "${#backups[@]}" ]; then
        return
    fi
    local selected="${backups[$((choice-1))]}"
    if ! tar -tzf "$selected" >/dev/null 2>&1; then
        echo -e "${RED}Backup file corrupted${NC}"
        read -p "Press Enter..."
        return
    fi
    if [ -f "$CONF_FILE" ]; then
        cp "$CONF_FILE" "${CONF_FILE}.pre-restore.$(date +%s)"
    fi
    tar -xzf "$selected" -C "$CONF_DIR" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Restored${NC}"
        log INFO "Config restored from $selected"
        if load_config "$CONF_FILE"; then
            read -p "Restart service? (y/n): " do_restart
            if [[ "$do_restart" =~ ^[Yy]$ ]]; then
                service_create
            fi
        else
            echo -e "${RED}Restored config is invalid${NC}"
        fi
    else
        echo -e "${RED}Restore failed${NC}"
    fi
    read -p "Press Enter..."
}

clean_all() {
    draw_header
    echo -e "${RED}${BOLD}Complete Removal${NC}"
    echo -e "${RED}This will remove:${NC}"
    echo "  • Iodine services"
    echo "  • Firewall rules"
    echo "  • Configuration files"
    echo "  • Backup files"
    echo "  • IP forwarding settings"
    echo "  • Log files"
    echo ""
    read -p "Type 'YES' to confirm: " confirm
    [[ "$confirm" != "YES" ]] && return
    log INFO "Starting cleanup"
    for svc in iodine-server iodine-client; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc"
        fi
        systemctl disable "$svc" 2>/dev/null
        rm -f "/etc/systemd/system/${svc}.service"
    done
    fw_clean
    local DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -n "$DEFAULT_IF" ]; then
        iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -p tcp -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -p udp -j ACCEPT 2>/dev/null
    fi
    rm -f /etc/sysctl.d/99-iodine.conf
    sysctl --system >/dev/null 2>&1
    if [ -d "$CONF_DIR" ]; then
        rm -rf "$CONF_DIR"
    fi
    rm -f "$LOG_FILE" "${LOG_FILE}.old" "${LOG_FILE}.old.gz"
    rm -f "$LOCK_FILE"
    systemctl daemon-reload
    local self_path="$INSTALL_DIR/$SCRIPT_NAME"
    if [ -f "$self_path" ]; then
        rm -f "$self_path"
    fi
    echo -e "${GREEN}✓ Completely removed${NC}"
    log INFO "Cleanup completed"
    sleep 2
    exit 0
}

service_menu() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        sleep 2
        return
    fi
    load_config "$CONF_FILE" || return
    local svc="iodine-${ROLE}"
    while true; do
        draw_header
        echo -e "${BOLD}Service Management${NC}"
        echo "1) Live Logs"
        echo "2) Recent Logs"
        echo "3) Restart"
        echo "4) Stop"
        echo "5) Start"
        echo "6) Status"
        echo "0) Back"
        echo ""
        read -p "Select: " s_opt
        case $s_opt in
            1)
                echo -e "\n${CYAN}Press Ctrl+C to exit${NC}\n"
                sleep 1
                journalctl -u "$svc" -f
                ;;
            2)
                journalctl -u "$svc" --no-pager -n 50
                read -p "Press Enter..."
                ;;
            3)
                service_create
                echo -e "${GREEN}✓ Restarted${NC}"
                sleep 1
                ;;
            4)
                systemctl stop "$svc"
                echo -e "${YELLOW}Stopped${NC}"
                sleep 1
                ;;
            5)
                systemctl start "$svc"
                echo -e "${GREEN}✓ Started${NC}"
                sleep 1
                ;;
            6)
                systemctl status "$svc" --no-pager
                read -p "Press Enter..."
                ;;
            0) break ;;
        esac
    done
}

show_usage() {
    echo "Usage: $SCRIPT_NAME [OPTION]"
    echo ""
    echo "Options:"
    echo "  --setup         Run interactive setup"
    echo "  --status        Show quick status"
    echo "  --start         Start tunnel service"
    echo "  --stop          Stop tunnel service"
    echo "  --restart       Restart tunnel service"
    echo "  --apply-fw      Apply firewall rules"
    echo "  --clean-fw      Remove firewall rules"
    echo "  --backup        Backup configuration"
    echo "  --uninstall     Remove everything"
    echo "  --help          Show this help"
    echo ""
    echo "Without options: show interactive menu"
}

case "${1:-}" in
    --apply-fw)    fw_apply; exit $? ;;
    --clean-fw)    fw_clean; exit $? ;;
    --setup)       run_setup; exit $? ;;
    --status)      quick_status; exit $? ;;
    --start)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; systemctl start "iodine-${ROLE}"; } || echo "Not configured"
        exit $?
        ;;
    --stop)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; systemctl stop "iodine-${ROLE}"; } || echo "Not configured"
        exit $?
        ;;
    --restart)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; service_create; } || echo "Not configured"
        exit $?
        ;;
    --backup)      backup_config; exit $? ;;
    --uninstall)   clean_all; exit $? ;;
    --help|-h)     show_usage; exit 0 ;;
    "")            ;;
    *)             echo "Unknown option: $1"; show_usage; exit 1 ;;
esac

while true; do
    draw_header
    echo "1) Install & Configure"
    echo "2) Quick Status"
    echo "3) Full Diagnostics"
    echo "4) Service Manager"
    echo "5) Performance Test"
    echo "6) Edit Configuration"
    echo "7) Backup/Restore"
    echo "8) Uninstall"
    echo "9) Documentation"
    echo "0) Exit"
    echo ""
    read -p "Select: " opt
    case $opt in
        1) run_setup ;;
        2) quick_status ;;
        3) check_status ;;
        4) service_menu ;;
        5) test_performance ;;
        6) edit_config ;;
        7)
            draw_header
            echo "1) Backup Config"
            echo "2) Restore Config"
            echo "0) Back"
            read -p "Select: " br_opt
            case $br_opt in
                1) backup_config ;;
                2) restore_config ;;
            esac
            ;;
        8) clean_all ;;
        9)
            clear
            echo -e "${CYAN}${BOLD}Iodine DNS Tunnel Manager${NC}"
            echo -e "${YELLOW}Created by: Dnt3e${NC}\n"
            echo "Official: https://code.kryo.se/iodine"
            echo "GitHub: https://github.com/yarrick/iodine"
            echo ""
            echo -e "${YELLOW}Features:${NC}"
            echo "• Binary search MTU detection"
            echo "• Multi-resolver DNS testing"
            echo "• Permanent IP forwarding"
            echo "• Clean firewall chains"
            echo "• Automatic fail detection"
            echo "• Config backup/restore"
            echo ""
            echo -e "${YELLOW}Tips:${NC}"
            echo "• Use NULL for best speed"
            echo "• Try TXT/SRV if NULL blocked"
            echo "• Lower lazy interval for faster DNS"
            echo "• Reduce hostname length if DNS unreliable"
            echo ""
            echo "Logs: $LOG_FILE"
            echo ""
            read -p "Press Enter..."
            ;;
        0)
            log INFO "Exiting"
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
    esac
done
