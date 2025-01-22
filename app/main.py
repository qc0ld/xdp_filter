import psycopg2
from bcc import BPF
import pyroute2
import time
import sys
import ctypes
import socket
import threading
import dns.resolver

import sys
sys.path.append('../')
from database import db

flags = 0
device = None

def initialize():
    flags = 0
    device = None
    if len(sys.argv) >= 2:
        if "-S" in sys.argv:
            flags |= BPF.XDP_FLAGS_SKB_MODE
        if "-D" in sys.argv:
            flags |= BPF.XDP_FLAGS_DRV_MODE
        if "-H" in sys.argv:
            flags |= BPF.XDP_FLAGS_HW_MODE
        device = sys.argv[-1]
    return flags, device

mode = BPF.XDP

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"


class Data(ctypes.Structure):
    _fields_ = [("source_ip", ctypes.c_uint32),
                ("dest_ip", ctypes.c_uint32)]


def handle_ip_event(cpu, data, size, blocked_ips_map, cursor):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    dest_ip = socket.inet_ntoa(event.dest_ip.to_bytes(4, 'little'))
    try:
        if db.is_ip_blocked(cursor, dest_ip):
            ip_int = socket.htonl(int(socket.inet_aton(dest_ip).hex(), 16))
            key = ctypes.c_uint32(ip_int)
            value = ctypes.c_uint32(1)
            blocked_ips_map[key] = value
            print(f"Destination IP address {dest_ip} is added to block list.")
        else:
            print(f"Destination IP address {dest_ip} not found in database, passing packet.")

    except Exception as e:
        print(f"Error: {e}")



def main():
    flags, device = initialize()

    conn, cursor = db.connect_to_db()
    
    if not conn:
        sys.exit(1)

    db.add_ips_to_database(conn, cursor)

    with open("xdp_program.c", "r") as f:
        bpf_program = f.read()

    b = BPF(text=bpf_program.replace("{ctxtype}", ctxtype))

    blocked_ips_map = b.get_table("blocked_ips")

    fn = b.load_func("xdp_drop", mode)
    if mode == BPF.XDP:
        b.attach_xdp(device, fn, flags)
    else:
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index
        ip.tc("add", "clsact", idx)
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff2", classid=1, direct_action=True)

    b["events"].open_perf_buffer(lambda cpu, data, size: handle_ip_event(cpu, data, size, blocked_ips_map, cursor))

    print("\nSystem is ready")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n\nExiting...")

    if mode == BPF.XDP:
        b.remove_xdp(device, flags)
    else:
        ip.tc("del", "clsact", idx)
        ipdb.release()

    db.close_db_connection(conn)

if __name__ == "__main__":
    main()
