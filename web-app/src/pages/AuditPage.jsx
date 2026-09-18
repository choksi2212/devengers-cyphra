import { SocShell, SocEmpty, SocNavBar } from '../components/SocShell'

/**
 * /soc/audit — tamper-evident audit chain.
 *
 * The chain is exposed on disk at <audit.chain_dir>; the operator
 * runs `python -m core.audit.verify` from the SOC root. A visual
 * chain browser ships in a follow-up; this page is the entry point
 * with the documented chain file path.
 */
export default function AuditPage() {
  return (
    <SocShell
      title="Audit Chain"
      subtitle="Tamper-evident record of every consequential act."
      current="audit"
    >
      <SocNavBar current="audit" />
      <SocEmpty message="Chain browser ships in a follow-up. Run verify from the SOC root: python -m core.audit.verify" />
    </SocShell>
  )
}
