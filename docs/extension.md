# Extension

Glutton is built to be easily extensible. Developers can add new protocol handlers or modify existing behavior to suit custom requirements.

## Adding a New Protocol Handler

1. **Create a New Module:**
   - Add your new protocol handler in the appropriate subdirectory under `protocols/` (e.g., `protocols/tcp` or `protocols/udp`).
   - Implement the handler function conforming to the expected signature:
     - For TCP: `func(context.Context, net.Conn, connection.Metadata) error`
     - For UDP: `func(context.Context, *net.UDPAddr, *net.UDPAddr, []byte, connection.Metadata) error`

2. **Register the Handler:**
   - Modify the mapping function (e.g., `protocols.MapTCPProtocolHandlers` or `protocols.MapUDPProtocolHandlers` in `protocols/protocols.go`) to include your new handler.
   - Update configuration or rules (in `config/rules.yaml` or `rules/rules.yaml`) if needed to route specific traffic to your handler.

3. **Test Your Extension:**
   - Write tests similar to those in `protocols/protocols_test.go` to verify your new handler’s functionality.
   - Use `go test` to ensure that your changes do not break existing functionality.

## Customizing Logging and Rules

- **Logging:** The logging mechanism is provided by the Producer (located in `producer/`). You can modify or extend it to suit your logging infrastructure.
- **Rules Engine:** The rules engine (found in `rules/`) can be extended to support additional matching criteria or custom rule types.

