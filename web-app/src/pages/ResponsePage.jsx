import { SocShell, SocEmpty, SocNavBar } from '../components/SocShell'

/**
 * /soc/response — playbook run history.
 *
 * Playbooks are wired into the Crises page (a crisis lists its
 * playbook IDs). An interactive playbook run / dry-run toggle ships
 * in a follow-up; this page documents where the layer is driven.
 */
export default function ResponsePage() {
  return (
    <SocShell
      title="Response"
      subtitle="Containment playbooks — action history."
      current="response"
    >
      <SocNavBar current="response" />
      <SocEmpty message="Playbook action history ships in a follow-up. Crises lists playbook IDs." />
    </SocShell>
  )
}
