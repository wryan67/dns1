#!/usr/bin/env bash
# dnsq.sh - send a raw DNS A query with nc and decode the reply.
# usage: ./dnsq.sh <domain> [host] [port] [udp|tcp]
set -uo pipefail

domain=${1:?usage: dnsq.sh <domain> [host] [port] [udp|tcp]}
host=${2:-127.0.0.1}
port=${3:-5353}
proto=${4:-udp}

# QNAME: each label prefixed with its length, terminated by a zero byte.
qname=""
IFS='.' read -ra labels <<< "$domain"
for l in "${labels[@]}"; do
    [ -z "$l" ] && continue
    qname+=$(printf '\\x%02x%s' "${#l}" "$l")
done
qname+='\x00'

# ID 0xaaaa, flags 0x0100 (standard query, RD), QDCOUNT 1, QTYPE A, QCLASS IN
query='\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'"$qname"'\x00\x01\x00\x01'

if [ "$proto" = tcp ]; then
    # DNS over TCP prefixes the message with its 2-byte big-endian length.
    len=$(printf "$query" | wc -c)
    body=$(printf '\\x%02x\\x%02x' $((len >> 8)) $((len & 255)))"$query"
    # -W1 exits as soon as one packet arrives; without it nc idles out the full -w.
    reply=$(printf "$body" | timeout 6 nc -W1 -w3 "$host" "$port" | xxd -p | tr -d '\n')
    reply=${reply:4}   # strip the 2-byte length prefix from the response
else
    reply=$(printf "$query" | timeout 6 nc -u -W1 -w3 "$host" "$port" | xxd -p | tr -d '\n')
fi

if [ -z "$reply" ]; then
    echo "no reply from $host:$port/$proto"
    exit 1
fi

flags=$((0x${reply:4:4}))
rcode=$((flags & 15))
case $rcode in
    0) name=NOERROR ;;  1) name=FORMERR ;;  2) name=SERVFAIL ;;
    3) name=NXDOMAIN ;; 5) name=REFUSED ;;  *) name=RCODE$rcode ;;
esac

echo "domain   : $domain via $host:$port/$proto"
echo "rcode    : $name ($rcode)"
echo "answers  : $((0x${reply:12:4}))"

# Answers begin after the 12-byte header and the question section.
# QNAME on the wire is len(domain)+2 bytes, plus 4 for QTYPE and QCLASS.
off=$(( 24 + (${#domain} + 2 + 4) * 2 ))
# Walk the answer records to pull out the A-record addresses.
for _ in $(seq 1 $((0x${reply:12:4}))); do
    rdlen=$((0x${reply:$((off + 20)):4}))
    if [ "$((0x${reply:$((off + 4)):4}))" -eq 1 ] && [ "$rdlen" -eq 4 ]; then
        rd=${reply:$((off + 24)):8}
        echo "A        : $((0x${rd:0:2})).$((0x${rd:2:2})).$((0x${rd:4:2})).$((0x${rd:6:2}))  ttl=$((0x${reply:$((off + 12)):8}))"
    fi
    off=$((off + 24 + rdlen * 2))
done
