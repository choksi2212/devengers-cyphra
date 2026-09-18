import { SocShell, SocEmpty, SocNavBar } from '../components/SocShell'

/**
 * /soc/triage — disposition queue.
 *
 * The triage layer is exposed via `cases/` and the disposition record
 * shape; an interactive disposition UI is a follow-up. This page
 * documents what the layer does and where to drive it from.
 */
export default function TriagePage() {
  return (
    <SocShell
      title="Triage"
      subtitle="Disposition queue — analyst workspace."
      current="triage"
    >
      <SocNavBar current="triage" />
      <SocEmpty message="Interactive disposition UI ships in a follow-up. Drive the queue via Cases." />
    </SocShell>
  )
}
