# OmniGuard V2X Dashboard Test Plan

## Data Binding

- Start the dashboard with the Python backend and the Go backend.
- Confirm every card reads through `DashboardDataProvider.collect()` or a backend/API method.
- Push telemetry through the backend telemetry API, then verify Vehicle Overview updates speed, RPM, fuel, temperature, and throttle from the newest block.
- Stop one metadata method or API route at a time and verify only that card shows `Error`, `Unavailable`, or `Not Connected`.

## Cards And Badges

- Verify all modules render as separate cards: Vehicle Overview, Access Control, Security Capability, Identity Security, Consensus Security, Privacy/Pedersen, FL Validation, Adversarial Validation, Reviewer Audit, Complexity Boundary, Contribution Boundary, Live Camera, Road Scene, V2X Radar, and Anomaly Detection.
- Verify badges use the dashboard status palette: OK green, Warning yellow, Error/Critical red, Unavailable/Not Connected orange or gray.
- Verify no hardcoded telemetry values appear in dashboard cards when backend telemetry is missing.

## Road Scene, Camera, And Radar

- With no telemetry, verify Road Scene displays `Road Scene Unavailable`.
- With no camera, verify Live Camera displays `Camera Not Connected`.
- With no peer list, verify V2X Radar displays `No V2X Peer Data`.
- Send V2X peers with real relative coordinates or distance/heading and verify only those peers render.
- Send peers without position fields and verify the dashboard reports unavailable peer position instead of inventing placement.
- Verify detected objects render only from camera/object-detection output.

## Responsive Layout

- Desktop widths: verify 4, 5, or 6 columns depending on available width.
- Tablet widths: verify 2 or 3 columns.
- Mobile widths: verify 1 column.
- Resize the window repeatedly and verify cards wrap with consistent padding, spacing, and vertical scrolling.
- Confirm text remains readable and does not overlap inside cards, buttons, badges, camera, radar, or road scene.

## Interaction

- Exercise Auth, Start, Stop, Lock, Recover, and Force Chain Reset against the backend.
- Verify Manual Refresh invokes a fresh provider collection and updates all cards.
- Verify the connection indicator reports Connected, Partial, or Disconnected based on card/module status.
