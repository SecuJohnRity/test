from behave import given, when, then
import requests # Add this import. Ensure 'requests' and 'requests_unixsocket' are in test requirements.
import requests_unixsocket # Add this import.
import time
import os

# Helper to get the base URL for the event server (via Unix socket)
def get_event_server_url(context):
    engine_handler = context.shared_data['engine_instance']
    event_socket_path = engine_handler.config_env.get("WAZUH_SERVER_EVENT_SOCKET")
    if not event_socket_path:
        raise ValueError("WAZUH_SERVER_EVENT_SOCKET not found in engine config")
    # URL encode the socket path
    encoded_socket_path = requests.utils.quote(event_socket_path, safe='')
    return f"http+unix://{encoded_socket_path}"

@given('the engine is running')
def step_engine_is_running(context):
    # The environment.py's before_all starts the engine.
    # This step can ensure the engine_handler is on the context for other steps.
    assert 'engine_instance' in context.shared_data, "Engine instance not found in shared_data"
    context.engine_handler = context.shared_data['engine_instance']
    assert context.engine_handler.process is not None, "Engine process is not running"
    # Optionally, add a small delay or a specific check if liveness can be flaky right after start
    time.sleep(1) # Small delay to ensure server is ready, if needed

@when('I send the datagram string "{datagram_string}" to the endpoint "{endpoint}"')
def step_send_datagram(context, datagram_string, endpoint):
    base_url = get_event_server_url(context)
    url = base_url + endpoint
    
    session = requests_unixsocket.Session()
    try:
        response = session.post(url, data=datagram_string.encode('utf-8'), headers={'Content-Type': 'application/octet-stream'})
        context.response_status = response.status_code
        context.response_text = response.text
    except requests.exceptions.RequestException as e:
        context.response_status = None
        context.response_text = str(e)
        # Fail the test immediately if the request fails, as this is unexpected
        assert False, f"HTTP request failed: {e}"


@then('the HTTP response status should be {status_code:d}')
def step_check_http_status(context, status_code):
    assert context.response_status == status_code, f"Expected status {status_code} but got {context.response_status}. Response: {context.response_text}"

@then('the datagram "{expected_datagram}" should be present in the archive file')
def step_check_archive(context, expected_datagram):
    engine_handler = context.engine_handler
    archive_file_path = engine_handler.config_env.get("WAZUH_ARCHIVER_PATH")
    if not archive_file_path:
        raise ValueError("WAZUH_ARCHIVER_PATH not found in engine config")

    assert os.path.exists(archive_file_path), f"Archive file not found at {archive_file_path}"

    max_attempts = 5
    found = False
    content = "" # Ensure content is defined in the broader scope for the final assert message
    for i in range(max_attempts):
        with open(archive_file_path, 'r') as f:
            content = f.read()
            # The archiver adds a newline
            if expected_datagram + '\n' in content:
                found = True
                break
        if found:
            break
        time.sleep(0.5) # Wait a bit for archiver to flush

    assert found, f"Datagram '{expected_datagram}' not found in archive file {archive_file_path}. Content:\n{content}"
