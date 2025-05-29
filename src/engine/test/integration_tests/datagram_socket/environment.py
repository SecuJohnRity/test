import subprocess
import time
import os
import signal

ENGINE_PATH = os.getenv("WAZUH_ENGINE_PATH", "../../../../bin/main") # Adjust path to engine executable
# ENGINE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../build/src/engine/main")) # Example if built in standard build dir
CONFIG_DIR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "configuration_files")) # Path to config.env
ENGINE_LOG_FILE = "/tmp/engine_integration_test.log" # Must match datagram_steps.py

def before_all(context):
    """
    Set up environment before any features are run.
    This could involve compiling the engine if not already done,
    or ensuring necessary configurations are in place.
    """
    print("Starting global setup for datagram socket integration tests.")
    print(f"Using engine path: {ENGINE_PATH}")
    print(f"Using config dir path: {CONFIG_DIR_PATH}")
    if not os.path.exists(ENGINE_PATH):
        print(f"ERROR: Engine executable not found at {ENGINE_PATH}")
        print("Please build the engine or set WAZUH_ENGINE_PATH environment variable.")
        # context.abort("Engine executable not found.") # Abort all tests

    # Potentially create a temporary configuration file or set environment variables
    # to enable datagram socket for the engine run.

def after_all(context):
    """
    Clean up environment after all features are run.
    """
    print("Starting global teardown for datagram socket integration tests.")
    # if os.path.exists(ENGINE_LOG_FILE):
    #     print(f"Final engine log content from {ENGINE_LOG_FILE}:")
    #     with open(ENGINE_LOG_FILE, 'r') as f:
    #         print(f.read())
    # else:
    #     print(f"Engine log file {ENGINE_LOG_FILE} not found or already cleaned up.")


def before_feature(context, feature):
    """
    Run before each feature file.
    """
    print(f"Setting up for feature: {feature.name}")


def after_feature(context, feature):
    """
    Run after each feature file.
    """
    print(f"Tearing down after feature: {feature.name}")


def before_scenario(context, scenario):
    """
    Run before each scenario.
    This is where we'll start the engine with the specific configuration
    derived from the Gherkin steps (stored in context.datagram_config).
    """
    print(f"Setting up for scenario: {scenario.name}")
    # Ensure the log file is clean before each scenario
    if os.path.exists(ENGINE_LOG_FILE):
        os.remove(ENGINE_LOG_FILE)
        print(f"Cleaned up existing log file: {ENGINE_LOG_FILE}")

    # Prepare environment variables for the engine based on context.datagram_config
    env_vars = os.environ.copy()
    env_vars["WAZUH_LOG_LEVEL"] = "debug" # Or "info", "debug" for more verbosity
    env_vars["WAZUH_ENGINE_LOG_PATH"] = ENGINE_LOG_FILE # Custom log path for tests

    if hasattr(context, 'datagram_config'):
        print(f"Configuring engine with datagram settings: {context.datagram_config}")
        env_vars["WAZUH_DATAGRAM_ENABLED"] = str(context.datagram_config.get("enabled", False)).lower()
        env_vars["WAZUH_DATAGRAM_IP_ADDRESS"] = context.datagram_config.get("ip", "127.0.0.1")
        env_vars["WAZUH_DATAGRAM_PORT"] = str(context.datagram_config.get("port", 5140))
        env_vars["WAZUH_DATAGRAM_OVERFLOW_STRATEGY"] = context.datagram_config.get("overflow_strategy", "discard")
        env_vars["WAZUH_DATAGRAM_BUFFER_SIZE"] = str(context.datagram_config.get("buffer_size", 102400))
    else:
        # Default minimal config if not specified by scenario
        print("Warning: context.datagram_config not set. Using default datagram disabled.")
        env_vars["WAZUH_DATAGRAM_ENABLED"] = "false"

    # Command to run the engine
    # The engine should be configured to use environment variables for these settings.
    # If it uses a config file, we'd need to generate one here.
    engine_cmd = [ENGINE_PATH]

    print(f"Starting engine with command: {' '.join(engine_cmd)}")
    print(f"Environment for engine: WAZUH_DATAGRAM_ENABLED={env_vars.get('WAZUH_DATAGRAM_ENABLED')}, "
          f"WAZUH_DATAGRAM_IP_ADDRESS={env_vars.get('WAZUH_DATAGRAM_IP_ADDRESS')}, "
          f"WAZUH_DATAGRAM_PORT={env_vars.get('WAZUH_DATAGRAM_PORT')}, "
          f"WAZUH_ENGINE_LOG_PATH={env_vars.get('WAZUH_ENGINE_LOG_PATH')}")

    try:
        # Start the engine process
        # Using Popen for non-blocking execution, redirecting stdout/stderr if needed for debugging
        # For integration tests, we usually let the engine log to its configured file.
        context.engine_process = subprocess.Popen(engine_cmd, env=env_vars,
                                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                  preexec_fn=os.setsid) # setsid to kill process group
        print(f"Engine process started with PID: {context.engine_process.pid}")
        # Give the engine a moment to start up
        time.sleep(2) # Adjust as needed
        if context.engine_process.poll() is not None:
            # Process terminated early
            stdout, stderr = context.engine_process.communicate()
            print(f"ERROR: Engine failed to start or crashed immediately.")
            print(f"Engine stdout:\n{stdout.decode(errors='ignore')}")
            print(f"Engine stderr:\n{stderr.decode(errors='ignore')}")
            # Check if log file has more info
            if os.path.exists(ENGINE_LOG_FILE):
                with open(ENGINE_LOG_FILE, 'r') as f:
                    print(f"Engine log ({ENGINE_LOG_FILE}):\n{f.read()}")
            raise Exception("Engine process failed to start.")

    except Exception as e:
        print(f"ERROR: Failed to start engine: {e}")
        # context.abort_scenario(f"Failed to start engine: {e}") # Behave >= 1.2.6
        raise # Re-raise to stop test execution for this scenario

def after_scenario(context, scenario):
    """
    Run after each scenario.
    This is where we'll stop the engine.
    """
    print(f"Tearing down after scenario: {scenario.name}")
    if hasattr(context, 'engine_process') and context.engine_process.poll() is None:
        print(f"Stopping engine process PID: {context.engine_process.pid}")
        try:
            # Send SIGTERM to the process group
            os.killpg(os.getpgid(context.engine_process.pid), signal.SIGTERM)
            context.engine_process.wait(timeout=10) # Wait for graceful shutdown
            print("Engine process terminated via SIGTERM.")
        except ProcessLookupError:
            print("Engine process already terminated.")
        except subprocess.TimeoutExpired:
            print("Engine process did not terminate gracefully with SIGTERM, sending SIGKILL.")
            os.killpg(os.getpgid(context.engine_process.pid), signal.SIGKILL)
            context.engine_process.wait(timeout=5)
            print("Engine process terminated via SIGKILL.")
        except Exception as e:
            print(f"Error stopping engine: {e}")
        finally:
            # Capture any remaining output
            stdout, stderr = context.engine_process.communicate()
            if stdout:
                print(f"Engine stdout (on stop):\n{stdout.decode(errors='ignore')}")
            if stderr:
                print(f"Engine stderr (on stop):\n{stderr.decode(errors='ignore')}")

    if os.path.exists(ENGINE_LOG_FILE):
        print(f"Contents of engine log file ({ENGINE_LOG_FILE}) after scenario '{scenario.name}':")
        with open(ENGINE_LOG_FILE, 'r') as f:
            log_content = f.read()
            print(log_content if log_content else "<empty log file>")
        # Optionally remove log file after each scenario if it's too verbose,
        # or keep it for debugging. For now, it's cleaned before next scenario.
    else:
        print(f"Engine log file {ENGINE_LOG_FILE} not found after scenario '{scenario.name}'.")

    context.datagram_config = {} # Clear config for next scenario
    if hasattr(context, 'message_to_send'):
        del context.message_to_send
    if hasattr(context, 'message_type'):
        del context.message_type
    if hasattr(context, 'send_burst'):
        del context.send_burst
