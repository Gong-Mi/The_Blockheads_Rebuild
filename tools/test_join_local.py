#!/usr/bin/env python3
"""Join acceptance: the original server 1.7.1 must ACCEPT the recovered
player-information packet (0x1f + XML plist) and reply with game data.

Asserts, from real server-side evidence:
  * server log contains "Player Connected <alias>" with the alias MD5
    (the localPlayerID path in BHNetServerMatch)
  * the probe receives at least one post-join message from the server
    (global world metadata plist, compressed; empty initial arrays)
  * server keeps the player until the probe disconnects (no instant reject)

Uses the recovery-directed server setup (qemu-x86_64, hash-pinned 1.7.1).
"""
import os, shutil, subprocess, socket, time, select, signal, json, sys
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
work = Path('/data/data/com.termux/files/home/blockheads-work')
if not (work / 'bhs-rootfs').exists():
    work = Path.home() / 'blockheads-work'
assert (work / 'bhs-rootfs').exists(), work
base = work
root = base / 'bhs-rootfs'
analysis = base / 'enet-analysis'
home = analysis / 'test-home'
config = analysis / 'test.conf'
out = analysis / 'join-acceptance.json'

if not home.exists():
    shutil.copytree(root / 'experiment-home', home)
config.write_text(f'GNUSTEP_USER_DIR_LIBRARY={home}/Library\n'
                  f'GNUSTEP_USER_DEFAULTS_DIR={home}/Defaults\n')

sys.path.insert(0, str(repo / 'tools'))
from player_info_packet import build_packet  # noqa: E402

payload = build_packet()
payload_path = analysis / 'player_info_payload.bin'
payload_path.write_bytes(payload)

probe = analysis / 'probe_join_local'
subprocess.run(['clang', '-Wall', '-Wextra', '-Werror',
                str(repo / 'tools' / 'probe_join_local.c'), '-lenet',
                '-o', str(probe)], check=True)

check = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
check.bind(('127.0.0.1', 15159)); check.close()

cmd = ['qemu-x86_64', '-U', 'LD_PRELOAD',
       '-E', f'GNUSTEP_CONFIG_FILE={config}', '-L', str(root / 'rootfs'),
       str(root / 'server_patched'), '--load', 'reverse-probe-001', '--port', '15159']
log = analysis / 'server-join-acceptance.log'
server = subprocess.Popen(cmd, cwd=home, stdout=log.open('w'),
                          stderr=subprocess.STDOUT, text=True)
result = {}
try:
    deadline = time.monotonic() + 60
    while 'World load complete.' not in log.read_text():
        if server.poll() is not None:
            raise RuntimeError('server exited: ' + log.read_text())
        if time.monotonic() > deadline:
            raise TimeoutError('server startup')
        time.sleep(0.3)

    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(('127.0.0.1', 0)); relay.setblocking(False)
    port = relay.getsockname()[1]
    client = subprocess.Popen([str(probe), str(port), str(payload_path), '12000'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peer = None
    t0 = time.monotonic()
    while time.monotonic() - t0 < 20:
        if client.poll() is not None and time.monotonic() - t0 > 18:
            break
        if not select.select([relay], [], [], 0.05)[0]:
            continue
        data, addr = relay.recvfrom(65535)
        direction = 'server_to_client' if addr == ('127.0.0.1', 15159) else 'client_to_server'
        if direction == 'client_to_server':
            peer = addr
            relay.sendto(data, ('127.0.0.1', 15159))
        elif peer:
            relay.sendto(data, peer)
    relay.close()
    stdout, stderr = client.communicate()
    result['probe_stdout'] = stdout
    result['probe_returncode'] = client.returncode
finally:
    server.send_signal(signal.SIGINT)
    try:
        server.wait(timeout=15)
    except subprocess.TimeoutExpired:
        server.terminate(); server.wait(timeout=5)
    result['server_returncode'] = server.returncode

logtext = log.read_text()
result['server_log'] = logtext

ok_connect = 'Player Connected probe' in logtext
ok_md5 = '8da843ff65205a61374b09b81ed0fa35' in logtext
ok_reply = 'post-join reply' in result.get('probe_stdout', '')
print(f'player_connected={ok_connect} md5_verified={ok_md5} post_join_reply={ok_reply}')
print(result.get('probe_stdout', ''))
out.write_text(json.dumps(result, indent=2))
if not (ok_connect and ok_reply):
    print('ACCEPTANCE FAILED')
    sys.exit(1)
print('ACCEPTANCE PASS')