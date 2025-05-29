Feature: Datagram Socket Message Handling
  As an engine, I need to correctly receive, parse, and process messages
  sent to the datagram socket from legacy agents.

  Background:
    Given the engine is configured with the datagram socket enabled
    And the datagram socket is configured for IP "127.0.0.1" and port 5140
    # Using a distinct port like 5140 for testing to avoid conflicts with system services.

  Scenario: Receive and process a standard OSSEC event
    Given a legacy agent will send a standard OSSEC event
    When the engine is running
    And the agent sends the OSSEC event to the datagram socket
    Then the engine should log that it received a message on the datagram socket
    And the engine should log that the message was parsed successfully
    # Future: And an alert with rule ID "X" should be generated (if applicable)

  Scenario: Receive and process an encrypted OSSEC event
    Given a legacy agent will send an encrypted OSSEC event
    When the engine is running
    And the agent sends the encrypted OSSEC event to the datagram socket
    Then the engine should log that it received a message on the datagram socket
    And the engine should log successful decryption (placeholder for now)
    And the engine should log that the decrypted message was parsed successfully
    # Future: And an alert corresponding to the decrypted event should be generated

  Scenario: Handle malformed standard OSSEC event
    Given a legacy agent will send a malformed OSSEC event
    When the engine is running
    And the agent sends the malformed OSSEC event to the datagram socket
    Then the engine should log that it received a message on the datagram socket
    And the engine should log a parsing failure for the message

  # --- Placeholder Scenarios for Overflow ---
  # These will require more sophisticated setup and verification later.

  Scenario: Overflow behavior - Discard (Placeholder)
    Given the datagram socket is configured with overflow strategy "discard"
    And a legacy agent will send a burst of messages to exceed buffer capacity
    When the engine is running
    And the agent sends the burst of messages
    Then the engine should log message discards due to overflow (or remain stable)
    # Verification here is complex: might involve checking for missing messages
    # or specific log entries about discarding.

  Scenario: Overflow behavior - Block (Placeholder)
    Given the datagram socket is configured with overflow strategy "block"
    And a legacy agent will send a burst of messages to exceed buffer capacity
    When the engine is running
    And the agent sends the burst of messages
    Then the engine should exhibit blocking behavior (e.g., sender might block)
    # Verification here is very complex for automated tests.
    # Might involve checking engine responsiveness or sender behavior.

  Scenario: Overflow behavior - Buffer to Disk (Placeholder)
    Given the datagram socket is configured with overflow strategy "buffer_to_disk"
    And a legacy agent will send a burst of messages to exceed buffer capacity
    When the engine is running
    And the agent sends the burst of messages
    Then the engine should log that messages are being buffered to disk
    # Verification: check for created buffer files, and their eventual processing.
    # This also implies a mechanism for re-reading from disk.
    # Ensure cleanup of buffer files post-test.
