package integrations

// Ticking reports whether the background health cycle runs for an integration.
// Test-only: it observes the cycle the lifecycle tests arm and disarm.
func (m *Manager) Ticking(integrationID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loops[integrationID] != nil
}
