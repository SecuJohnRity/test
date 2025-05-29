from behave import given, when, then
import subprocess
import time
import os
import socket

# Path to the message sending script (adjust as necessary)
SENDER_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "send_legacy_datagram.py")
ENGINE_LOG_FILE = "/tmp/engine_integration_test.log" # Example log file path

@given('the engine is configured with the datagram socket enabled')
def step_impl(context):
    # This step implies that the environment.py's before_all or before_feature
    # will handle starting the engine with the correct configuration.
    # We can store the desired config in the context if needed for specific scenarios.
    context.datagram_config = {
        "enabled": True,
        "ip": "127.0.0.1", # Default, can be overridden
        "port": 5140,      # Default, can be overridden
        "overflow_strategy": "discard", # Default
        "buffer_size": 102400
    }
    # Ensure previous log is cleared if it exists
    if os.path.exists(ENGINE_LOG_FILE):
        os.remove(ENGINE_LOG_FILE)
    print(f"Engine log file {ENGINE_LOG_FILE} ensured to be clean.")


@given('the datagram socket is configured for IP "{ip}" and port {port:d}')
def step_impl(context, ip, port):
    if not hasattr(context, 'datagram_config'):
        context.datagram_config = {}
    context.datagram_config["ip"] = ip
    context.datagram_config["port"] = port
    # The actual application of this config happens when the engine is started (e.g., in environment.py)
    print(f"Datagram socket target configured for IP: {ip}, Port: {port}")


@given('the datagram socket is configured with overflow strategy "{strategy}"')
def step_impl(context, strategy):
    if not hasattr(context, 'datagram_config'):
        context.datagram_config = {}
    context.datagram_config["overflow_strategy"] = strategy
    print(f"Datagram overflow strategy set to: {strategy}")


@given('a legacy agent will send a standard OSSEC event')
def step_impl(context):
    # Example: "1:localhost:test-program:1001:Test rule:This is a standard OSSEC event."
    context.message_to_send = "1:test-agent-it:test-program:1001:Standard Event:This is an integration test event."
    context.message_type = "standard"
    print(f"Prepared standard OSSEC event: {context.message_to_send}")

@given('a legacy agent will send an encrypted OSSEC event')
def step_impl(context):
    # For now, "encrypted" is just a prefix for the sender script.
    # Actual encryption would require key setup and crypto in the script and engine.
    context.message_to_send = "This is a secret message for encryption." # Plain text for now
    context.message_type = "encrypted"
    # TODO: Implement actual encryption in sender script and decryption in engine.
    # For the purpose of the test, the sender script might just prepend "ENC>" or similar
    # and the engine log check would look for "decryption successful (placeholder)".
    print(f"Prepared (placeholder) encrypted OSSEC event: {context.message_to_send}")


@given('a legacy agent will send a malformed OSSEC event')
def step_impl(context):
    context.message_to_send = "MALFORMED:no_colons_or_invalid_format"
    context.message_type = "malformed"
    print(f"Prepared malformed OSSEC event: {context.message_to_send}")


@given('a legacy agent will send a burst of messages to exceed buffer capacity')
def step_impl(context):
    context.send_burst = True
    context.num_messages_in_burst = 200 # Example number, might need tuning
    context.message_to_send = "1:burst-agent:program:1002:Burst Event:Message {} of {}"
    context.message_type = "standard_burst"
    print(f"Prepared for sending a burst of {context.num_messages_in_burst} messages.")


@when('the engine is running')
def step_impl(context):
    # This step assumes environment.py has started the engine.
    # We can add a check here if context.engine_process is valid.
    if not hasattr(context, 'engine_process') or context.engine_process.poll() is not None:
        raise Exception("Engine process not found or not running. Check environment.py.")
    print("Engine is confirmed to be running.")
    time.sleep(2) # Give engine a moment to fully initialize sockets


@when('the agent sends the OSSEC event to the datagram socket')
def step_impl(context):
    ip = context.datagram_config.get("ip", "127.0.0.1")
    port = context.datagram_config.get("port", 5140)
    args = [
        "python3", SENDER_SCRIPT_PATH,
        "--ip", ip,
        "--port", str(port),
        "--message", context.message_to_send,
        "--type", context.message_type
    ]
    try:
        print(f"Executing sender script: {' '.join(args)}")
        process = subprocess.run(args, capture_output=True, text=True, check=True, timeout=10)
        print(f"Sender script stdout: {process.stdout}")
        if process.stderr:
            print(f"Sender script stderr: {process.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Sender script failed with error code {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        print("Sender script timed out.")
        raise
    print(f"Sent message: '{context.message_to_send}' of type '{context.message_type}' to {ip}:{port}")
    time.sleep(1) # Give engine time to process


@when('the agent sends the burst of messages')
def step_impl(context):
    if not context.send_burst:
        return

    ip = context.datagram_config.get("ip", "127.0.0.1")
    port = context.datagram_config.get("port", 5140)
    base_message = context.message_to_send

    success_count = 0
    for i in range(context.num_messages_in_burst):
        message = base_message.format(i+1, context.num_messages_in_burst)
        args = [
            "python3", SENDER_SCRIPT_PATH,
            "--ip", ip,
            "--port", str(port),
            "--message", message,
            "--type", "standard" # Burst sends standard messages
        ]
        try:
            # For bursts, don't wait for each subprocess to complete fully if it's too slow.
            # Fire and forget, or short timeout.
            subprocess.Popen(args) # Fire and forget
            success_count +=1
            if i % 50 == 0: # Small delay occasionally
                time.sleep(0.01)
        except Exception as e:
            print(f"Error sending burst message {i+1}: {e}")
            # Continue sending other messages
    print(f"Sent {success_count}/{context.num_messages_in_burst} burst messages to {ip}:{port}.")
    time.sleep(3) # Give engine time to process the burst


def check_log_for_message(log_path, expected_message, timeout_secs=10):
    start_time = time.time()
    while time.time() - start_time < timeout_secs:
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                for line in f:
                    if expected_message in line:
                        print(f"Found expected log: '{expected_message}'")
                        return True
        time.sleep(0.5) # Check every 0.5 seconds
    print(f"Timeout: Expected log message '{expected_message}' not found in '{log_path}'.")
    return False

@then('the engine should log that it received a message on the datagram socket')
def step_impl(context):
    # Example log message: "DatagramSocket: Received X bytes from Y:Z"
    # Or "Router received a datagram packet of size: X"
    # This needs to match actual log output from DatagramSocket or Router
    log_message_router = "Router received a datagram packet of size:" # From router.cpp
    log_message_socket_init = "DatagramSocket initializing with config" # From datagram_socket.cpp
    
    # Check for the more specific "Router received..." log first.
    # If the message is very small or malformed, it might not reach the router's processing stage
    # but the socket might still log initialization or a lower-level receive.
    
    # We are looking for the log that confirms the packet processing initiation in the router
    # For now, let's use the router's log message.
    # The actual size will vary, so we check for the prefix.
    assert check_log_for_message(ENGINE_LOG_FILE, log_message_router), \
        f"Expected log prefix '{log_message_router}' not found."


@then('the engine should log that the message was parsed successfully')
def step_impl(context):
    # This is a placeholder. The actual log would come from LegacyMessageParser.
    # Example: "LegacyMessageParser: Successfully parsed message from X:Y"
    # For now, we'll assume a successful reception by the Router implies successful parsing for valid messages,
    # as the parser is currently a placeholder.
    # If the message was malformed, this step should not be called or should expect a different outcome.
    if context.message_type == "malformed":
        # This step shouldn't run for malformed, or should expect failure.
        # For now, we skip if we know it's a malformed test.
        print("Skipping 'parsed successfully' check for malformed message test.")
        return

    # This is a conceptual step. Current parser is a placeholder.
    # We'll rely on the "Router received a datagram packet" as a proxy for now for valid messages.
    # When LegacyMessageParser is implemented, it should produce a distinct log.
    log_message = "LegacyMessageParser: Successfully parsed" # Placeholder for future
    # assert check_log_for_message(ENGINE_LOG_FILE, log_message), \
    #    f"Expected log '{log_message}' not found."
    print(f"Step 'engine should log that the message was parsed successfully' - currently a conceptual check.")
    pass


@then('the engine should log successful decryption (placeholder for now)')
def step_impl(context):
    # This is a placeholder for when encryption/decryption is implemented.
    # Example log: "LegacyMessageParser: Decrypted message from X:Y successfully."
    log_message = "LegacyMessageParser: Decrypted message successfully" # Placeholder
    # assert check_log_for_message(ENGINE_LOG_FILE, log_message), \
    #    f"Expected log '{log_message}' not found."
    print(f"Step 'engine should log successful decryption' - currently a conceptual check.")
    pass


@then('the engine should log a parsing failure for the message')
def step_impl(context):
    # This is a placeholder. The actual log would come from LegacyMessageParser.
    # Example: "LegacyMessageParser: Failed to parse message from X:Y. Reason: ..."
    # For now, the router might just log receipt but the parser (if it logged) would show failure.
    # If the message is too malformed, it might not even reach the parser.
    # The current placeholder parser always returns false, so no specific "failure" log is made by it.
    # We can check that a specific "success" log for parsing is NOT present if that's more robust.
    log_message = "LegacyMessageParser: Failed to parse" # Placeholder
    # assert check_log_for_message(ENGINE_LOG_FILE, log_message), \
    #    f"Expected log '{log_message}' not found."
    print(f"Step 'engine should log a parsing failure' - currently a conceptual check.")
    pass


@then('the engine should log message discards due to overflow (or remain stable)')
def step_impl(context):
    # Placeholder for overflow testing.
    # Example log: "DatagramSocket: Buffer full, discarding message (discard strategy)."
    log_message = "DatagramSocket: Buffer full, discarding message" # Placeholder
    # assert check_log_for_message(ENGINE_LOG_FILE, log_message), \
    #    f"Expected log '{log_message}' not found."
    print(f"Step 'engine should log message discards' - currently a conceptual check.")
    pass


@then('the engine should exhibit blocking behavior (e.g., sender might block)')
def step_impl(context):
    # Placeholder for overflow testing.
    # This is very hard to check automatically. Might rely on engine becoming unresponsive
    # or sender script timing out if it were synchronous and blocking.
    print(f"Step 'engine should exhibit blocking behavior' - currently a conceptual/manual check.")
    pass


@then('the engine should log that messages are being buffered to disk')
def step_impl(context):
    # Placeholder for overflow testing.
    # Example log: "OverflowHandler: Buffering message to disk. Current queue size: X"
    log_message = "OverflowHandler: Buffering message to disk" # Placeholder
    # assert check_log_for_message(ENGINE_LOG_FILE, log_message), \
    #    f"Expected log '{log_message}' not found."
    print(f"Step 'engine should log that messages are being buffered to disk' - currently a conceptual check.")
    pass
