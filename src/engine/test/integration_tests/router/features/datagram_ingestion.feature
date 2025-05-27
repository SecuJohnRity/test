Feature: Datagram Event Ingestion

  Scenario: Send a valid datagram event to the datagram endpoint
    Given the engine is running
    When I send the datagram string "1:/test/location:This is a test datagram event for archiving" to the endpoint "/events/datagram"
    Then the HTTP response status should be 200
    And the datagram "1:/test/location:This is a test datagram event for archiving" should be present in the archive file
