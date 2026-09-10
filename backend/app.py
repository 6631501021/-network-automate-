from flask import Flask, request, jsonify
import paramiko
import socket
import time
import os
import ipaddress

app = Flask(__name__)

ROUTER_USERNAME = os.getenv("ROUTER_USERNAME", "admin")
ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD", "cisco")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))


def prefer_algorithm(current_algorithms, preferred_algorithms):
    current = list(current_algorithms)

    preferred = [
        algo
        for algo in preferred_algorithms
        if algo in current
    ]

    remaining = [
        algo
        for algo in current
        if algo not in preferred
    ]

    return tuple(preferred + remaining)


def read_output(channel, idle_timeout=1.0, max_timeout=10):
    output = ""
    start_time = time.time()
    last_data_time = time.time()

    while time.time() - start_time < max_timeout:

        if channel.recv_ready():
            data = channel.recv(65535).decode(
                "utf-8",
                errors="ignore"
            )

            output += data
            last_data_time = time.time()

        else:
            if time.time() - last_data_time >= idle_timeout:
                break

            time.sleep(0.1)

    return output


def execute_ssh(router_ip, command):
    sock = None
    transport = None
    channel = None

    try:
        sock = socket.create_connection(
            (router_ip, SSH_PORT),
            timeout=10
        )

        transport = paramiko.Transport(sock)

        security = transport.get_security_options()

        # Compatibility with older Cisco IOS in GNS3
        security.kex = prefer_algorithm(
            security.kex,
            [
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group-exchange-sha1",
            ]
        )

        security.ciphers = prefer_algorithm(
            security.ciphers,
            [
                "aes128-cbc",
                "aes192-cbc",
                "aes256-cbc",
            ]
        )

        security.key_types = prefer_algorithm(
            security.key_types,
            [
                "ssh-rsa",
            ]
        )

        transport.start_client(timeout=10)

        transport.auth_password(
            username=ROUTER_USERNAME,
            password=ROUTER_PASSWORD
        )

        if not transport.is_authenticated():
            raise Exception("SSH authentication failed")

        channel = transport.open_session()

        channel.get_pty(
            term="vt100",
            width=200,
            height=1000
        )

        channel.invoke_shell()

        time.sleep(0.5)

        # Clear initial banner
        while channel.recv_ready():
            channel.recv(65535)

        # Disable Cisco pagination
        channel.send("terminal length 0\n")

        time.sleep(0.5)

        while channel.recv_ready():
            channel.recv(65535)

        # Allows one or multiple commands
        commands = command.replace(
            "\r\n",
            "\n"
        ).split("\n")

        for cmd in commands:
            cmd = cmd.strip()

            if not cmd:
                continue

            channel.send(cmd + "\n")
            time.sleep(0.4)

        output = read_output(channel)

        return output.strip()

    finally:

        if channel:
            try:
                channel.close()
            except Exception:
                pass

        if transport:
            try:
                transport.close()
            except Exception:
                pass

        if sock:
            try:
                sock.close()
            except Exception:
                pass


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


@app.route("/api/execute", methods=["POST"])
def execute():

    data = request.get_json(silent=True) or {}

    router_ip = str(
        data.get("ip", "")
    ).strip()

    command = str(
        data.get("command", "")
    ).strip()

    if not router_ip:
        return jsonify({
            "success": False,
            "error": "Router IP is required"
        }), 400

    if not command:
        return jsonify({
            "success": False,
            "error": "Router command is required"
        }), 400

    try:
        ipaddress.ip_address(router_ip)
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid IP address"
        }), 400

    try:

        output = execute_ssh(
            router_ip,
            command
        )

        return jsonify({
            "success": True,
            "router": router_ip,
            "command": command,
            "output": output
        })

    except paramiko.AuthenticationException:

        return jsonify({
            "success": False,
            "error": "Username or password incorrect"
        }), 401

    except socket.timeout:

        return jsonify({
            "success": False,
            "error": "Router connection timeout"
        }), 504

    except Exception as error:

        print(
            f"ERROR: {error}",
            flush=True
        )

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
