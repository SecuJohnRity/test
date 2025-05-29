import socket
import argparse
import sys

def send_udp_message(ip, port, message, message_type="standard"):
    """
    Sends a message over UDP to the specified IP and port.

    Args:
        ip (str): The destination IP address.
        port (int): The destination port.
        message (str): The message payload to send.
        message_type (str): Type of message, e.g., "standard", "encrypted", "malformed".
                            This is used to potentially prepend prefixes.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    full_message = message

    # Placeholder for message type handling.
    # In a real scenario, "encrypted" would involve actual encryption.
    if message_type == "encrypted":
        # This is a very basic placeholder. Real encryption is needed.
        full_message = f"!{message}" # Example: Prepend "!" for encrypted messages
        print(f"Prepared (placeholder) encrypted message: {full_message}")
    elif message_type == "control":
        full_message = f"#{message}" # Example: Prepend "#" for control messages
        print(f"Prepared control message: {full_message}")
    elif message_type == "malformed":
        # The message itself is already malformed as per the test step.
        print(f"Sending malformed message as is: {full_message}")
    # Standard messages are sent as is (assuming they already have "1:" prefix if needed)

    try:
        print(f"Attempting to send UDP message to {ip}:{port}")
        sock.sendto(full_message.encode('utf-8'), (ip, port))
        print(f"Successfully sent {len(full_message.encode('utf-8'))} bytes: '{full_message}'")
    except socket.gaierror:
        print(f"Error: Address-related error connecting to {ip}:{port}. Check IP/hostname.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error sending UDP message: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()
        print("Socket closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send a legacy OSSEC-style message over UDP.")
    parser.add_argument("--ip", default="127.0.0.1", help="Destination IP address.")
    parser.add_argument("--port", type=int, default=5140, help="Destination port.")
    parser.add_argument("--message", required=True, help="The message payload to send.")
    parser.add_argument("--type", choices=["standard", "encrypted", "control", "malformed"], default="standard",
                        help="Type of message to send (affects potential formatting/prefixing).")

    args = parser.parse_args()

    send_udp_message(args.ip, args.port, args.message, args.type)
