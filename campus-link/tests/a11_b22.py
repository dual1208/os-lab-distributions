#!/usr/bin/env python3
"""Deterministic A11/B22 transport integrity and concurrency probe."""

import argparse
import concurrent.futures
import hashlib
import socket
import struct
import threading
import time


HEADER = struct.Struct("!QQ")
DIGEST_SIZE = 32
MAX_PAYLOAD = 2 * 1024 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


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
    seed = hashlib.sha256(f"campus-link:{sequence}".encode()).digest()
    remaining = length
    while remaining:
        size = min(remaining, CHUNK_SIZE)
        yield (seed * ((size + len(seed) - 1) // len(seed)))[:size]
        remaining -= size


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
            while remaining:
                chunk = recv_exact(conn, min(remaining, CHUNK_SIZE))
                digest.update(chunk)
                remaining -= len(chunk)
            claimed = recv_exact(conn, DIGEST_SIZE)
            actual = digest.digest()
            if claimed != actual:
                raise ValueError("payload digest mismatch")
            conn.sendall(HEADER.pack(sequence, 0) + actual)


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
            if len(packet) == 8 + DIGEST_SIZE:
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
    if got_sequence != sequence or got_length != 0 or response[HEADER.size :] != expected:
        raise AssertionError("response sequence or digest mismatch")


def exchange(conn, sequence, length, half_close=False):
    expected = send_request(conn, sequence, length)
    if half_close:
        conn.shutdown(socket.SHUT_WR)
    read_response(conn, sequence, expected)


def one_flow(source, destination, port, sequence):
    with open_client(source, destination, port) as conn:
        exchange(conn, sequence, 1024)


def udp_probe(source, destination, port, packets, interval_ms, wait_seconds):
    received = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(0.05)
        conn.bind((source, 0))
        stop = threading.Event()

        def receive():
            while not stop.is_set():
                try:
                    wire, _ = conn.recvfrom(2048)
                except TimeoutError:
                    continue
                if len(wire) == 8 + DIGEST_SIZE:
                    received.add(struct.unpack("!Q", wire[:8])[0])

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
    if args.pipeline_window < 1 or args.records < 1 or args.concurrency < 1:
        raise ValueError("records, pipeline window, and concurrency must be positive")
    if not 0 <= args.bulk_bytes <= MAX_PAYLOAD or args.record_bytes < 0:
        raise ValueError("payload size is outside the bounded range")
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
    one_flow(args.source, args.destination, args.tcp_port, 9_000_000)
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
