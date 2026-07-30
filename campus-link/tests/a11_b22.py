#!/usr/bin/env python3
"""Deterministic A11/B22 transport integrity and concurrency probe."""

import argparse
import concurrent.futures
import hashlib
import hmac
import math
import socket
import struct
import threading
import time


HEADER = struct.Struct("!QQ")
DIGEST_SIZE = 32
MAX_PAYLOAD = 2 * 1024 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
STATUS_OK = 0
STATUS_DIGEST_MISMATCH = 1
MAX_RECORDS = 1_000_000
MAX_CONCURRENCY = 4096
MAX_PIPELINE_WINDOW = 65_536
MAX_UDP_PACKETS = 1_000_000


def recv_exact(conn, size, allow_clean_eof=False):
    chunks = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            if allow_clean_eof and remaining == size:
                return None
            raise EOFError(f"connection ended with {remaining} bytes outstanding")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def payload_chunks(sequence, length):
    if not 0 <= sequence < 1 << 64:
        raise ValueError("sequence is outside uint64")
    if not 0 <= length <= MAX_PAYLOAD:
        raise ValueError("payload length is outside the bounded range")
    remaining = length
    chunk_index = 0
    while remaining:
        size = min(remaining, CHUNK_SIZE)
        seed = hashlib.sha256(
            b"campus-link-record-v2\0"
            + struct.pack("!QQQ", sequence, chunk_index, length)
        ).digest()
        yield (seed * ((size + len(seed) - 1) // len(seed)))[:size]
        remaining -= size
        chunk_index += 1


def digest_for(sequence, length):
    digest = hashlib.sha256()
    for chunk in payload_chunks(sequence, length):
        digest.update(chunk)
    return digest.digest()


def handle_tcp(conn):
    with conn:
        conn.settimeout(30)
        while True:
            header = recv_exact(conn, HEADER.size, allow_clean_eof=True)
            if header is None:
                return
            sequence, length = HEADER.unpack(header)
            if length > MAX_PAYLOAD:
                raise ValueError("payload exceeds server safety limit")
            digest = hashlib.sha256()
            remaining = length
            payload_matches = True
            for expected_chunk in payload_chunks(sequence, length):
                chunk = recv_exact(conn, len(expected_chunk))
                digest.update(chunk)
                payload_matches &= hmac.compare_digest(chunk, expected_chunk)
                remaining -= len(chunk)
            if remaining != 0:
                raise AssertionError("server payload accounting mismatch")
            claimed = recv_exact(conn, DIGEST_SIZE)
            actual = digest.digest()
            if not payload_matches or not hmac.compare_digest(claimed, actual):
                conn.sendall(HEADER.pack(sequence, STATUS_DIGEST_MISMATCH) + actual)
                return
            conn.sendall(HEADER.pack(sequence, STATUS_OK) + actual)


def tcp_server(bind, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, port))
        listener.listen(256)
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


def udp_server(bind, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((bind, port))
        while True:
            packet, peer = server.recvfrom(2048)
            if parse_udp_wire(packet) is not None:
                server.sendto(packet, peer)


def serve(args):
    threading.Thread(target=udp_server, args=(args.bind, args.udp_port), daemon=True).start()
    tcp_server(args.bind, args.tcp_port)


def open_client(source, destination, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(120)
    conn.bind((source, 0))
    conn.connect((destination, port))
    return conn


def send_request(conn, sequence, length):
    digest = hashlib.sha256()
    conn.sendall(HEADER.pack(sequence, length))
    for chunk in payload_chunks(sequence, length):
        conn.sendall(chunk)
        digest.update(chunk)
    expected = digest.digest()
    conn.sendall(expected)
    return expected


def read_response(conn, sequence, expected):
    response = recv_exact(conn, HEADER.size + DIGEST_SIZE)
    got_sequence, got_length = HEADER.unpack(response[: HEADER.size])
    if got_sequence != sequence or got_length != STATUS_OK or response[HEADER.size :] != expected:
        raise AssertionError("response sequence or digest mismatch")


def exchange(conn, sequence, length, half_close=False):
    expected = send_request(conn, sequence, length)
    if half_close:
        conn.shutdown(socket.SHUT_WR)
    read_response(conn, sequence, expected)


def one_flow(source, destination, port, sequence):
    with open_client(source, destination, port) as conn:
        exchange(conn, sequence, 1024)


def parse_udp_wire(wire, sequence_limit=None):
    if len(wire) != 8 + DIGEST_SIZE:
        return None
    sequence = struct.unpack("!Q", wire[:8])[0]
    if sequence_limit is not None and not 0 <= sequence < sequence_limit:
        return None
    expected = digest_for(sequence, 64)
    if not hmac.compare_digest(wire[8:], expected):
        return None
    return sequence


def valid_udp_echo(wire, peer, expected_address, expected_port, sequence_limit):
    if peer != (expected_address, expected_port):
        return None
    return parse_udp_wire(wire, sequence_limit)


def udp_probe(source, destination, port, packets, interval_ms, wait_seconds):
    received = set()
    expected_address = socket.gethostbyname(destination)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(0.05)
        conn.bind((source, 0))
        stop = threading.Event()

        def receive():
            while not stop.is_set():
                try:
                    wire, peer = conn.recvfrom(2048)
                except TimeoutError:
                    continue
                sequence = valid_udp_echo(
                    wire, peer, expected_address, port, packets
                )
                if sequence is not None:
                    received.add(sequence)

        receiver = threading.Thread(target=receive)
        receiver.start()
        for sequence in range(packets):
            wire = struct.pack("!Q", sequence) + digest_for(sequence, 64)
            conn.sendto(wire, (destination, port))
            time.sleep(interval_ms / 1000)
        time.sleep(wait_seconds)
        stop.set()
        receiver.join(timeout=1)
    return len(received)


def client(args):
    if not 1 <= args.records <= MAX_RECORDS:
        raise ValueError("record count is outside the bounded range")
    if not 1 <= args.pipeline_window <= MAX_PIPELINE_WINDOW:
        raise ValueError("pipeline window is outside the bounded range")
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        raise ValueError("concurrency is outside the bounded range")
    if not 0 <= args.bulk_bytes <= MAX_PAYLOAD or not 0 <= args.record_bytes <= MAX_PAYLOAD:
        raise ValueError("payload size is outside the bounded range")
    if not 0 <= args.udp_packets <= MAX_UDP_PACKETS:
        raise ValueError("UDP packet count is outside the bounded range")
    if (
        not math.isfinite(args.udp_interval_ms)
        or not 0 <= args.udp_interval_ms <= 60_000
        or not math.isfinite(args.udp_wait_seconds)
        or not 0 <= args.udp_wait_seconds <= 3600
    ):
        raise ValueError("UDP timings are outside the bounded range")
    if not math.isfinite(args.min_udp_ratio) or not 0 <= args.min_udp_ratio <= 1:
        raise ValueError("minimum UDP ratio must be between zero and one")
    started = time.monotonic()
    with open_client(args.source, args.destination, args.tcp_port) as conn:
        for first in range(1, args.records + 1, args.pipeline_window):
            last = min(first + args.pipeline_window, args.records + 1)
            expected = [
                send_request(conn, sequence, args.record_bytes)
                for sequence in range(first, last)
            ]
            for sequence, digest in zip(range(first, last), expected):
                read_response(conn, sequence, digest)
    print(f"PHASE records=pass seconds={time.monotonic() - started:.3f}", flush=True)
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [
            pool.submit(one_flow, args.source, args.destination, args.tcp_port, 1_000_000 + sequence)
            for sequence in range(args.concurrency)
        ]
        for future in futures:
            future.result()
    print(f"PHASE concurrency=pass seconds={time.monotonic() - started:.3f}", flush=True)
    started = time.monotonic()
    with open_client(args.source, args.destination, args.tcp_port) as conn:
        exchange(conn, 2_000_000, args.bulk_bytes)
    print(f"PHASE bulk=pass seconds={time.monotonic() - started:.3f}", flush=True)
    started = time.monotonic()
    with open_client(args.source, args.destination, args.tcp_port) as conn:
        exchange(conn, 3_000_000, 4096, half_close=True)
    print(f"PHASE half_close=pass seconds={time.monotonic() - started:.3f}", flush=True)
    started = time.monotonic()
    udp_received = udp_probe(
        args.source,
        args.destination,
        args.udp_port,
        args.udp_packets,
        args.udp_interval_ms,
        args.udp_wait_seconds,
    )
    print(f"PHASE udp=measured seconds={time.monotonic() - started:.3f}", flush=True)
    if args.udp_packets and udp_received / args.udp_packets < args.min_udp_ratio:
        raise AssertionError(
            f"UDP delivery ratio {udp_received}/{args.udp_packets} is below {args.min_udp_ratio:.3f}"
        )
    print(
        f"PASS source={args.source} destination={args.destination} records={args.records} "
        f"concurrency={args.concurrency} bulk_bytes={args.bulk_bytes} "
        f"udp_received={udp_received}/{args.udp_packets}"
    )


def health(args):
    try:
        one_flow(args.source, args.destination, args.tcp_port, 9_000_000)
    except AssertionError:
        print("HEALTH=integrity-failure", flush=True)
        raise SystemExit(76)
    except (EOFError, OSError, TimeoutError):
        print("HEALTH=transport-unavailable", flush=True)
        raise SystemExit(75)
    print("HEALTH=pass")


def parser():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--bind", required=True)
    server.add_argument("--tcp-port", type=int, default=18080)
    server.add_argument("--udp-port", type=int, default=18081)
    server.set_defaults(function=serve)
    probe = sub.add_parser("client")
    probe.add_argument("--source", required=True)
    probe.add_argument("--destination", required=True)
    probe.add_argument("--tcp-port", type=int, default=18080)
    probe.add_argument("--udp-port", type=int, default=18081)
    probe.add_argument("--records", type=int, default=10_000)
    probe.add_argument("--record-bytes", type=int, default=128)
    probe.add_argument("--pipeline-window", type=int, default=1024)
    probe.add_argument("--concurrency", type=int, default=100)
    probe.add_argument("--bulk-bytes", type=int, default=32 * 1024 * 1024)
    probe.add_argument("--udp-packets", type=int, default=1000)
    probe.add_argument("--udp-interval-ms", type=float, default=10)
    probe.add_argument("--udp-wait-seconds", type=float, default=3)
    probe.add_argument("--min-udp-ratio", type=float, default=0.9)
    probe.set_defaults(function=client)
    check = sub.add_parser("health")
    check.add_argument("--source", required=True)
    check.add_argument("--destination", required=True)
    check.add_argument("--tcp-port", type=int, default=18080)
    check.set_defaults(function=health)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.function(arguments)
