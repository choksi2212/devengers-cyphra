import { useState } from 'react'
import { SocShell, SocEmpty, SocNavBar } from '../components/SocShell'

/**
 * /soc/compliance — control framework selector.
 *
 * The compliance layer ships three frameworks: NIST 800-53, SOC 2,
 * ISO 27001. Each framework has 4-5 controls. The actual evaluation
 * runs over the audit chain via `core/compliance/framework.py` —
 * this page is the operator-facing surface for selecting which
 * framework to evaluate against.
 *
 * The interactive evaluator ships in a follow-up; for now the page
 * shows the framework list and links to the source files.
 */
const frameworks = [
  {
    id: 'nist_800_53',
    name: 'NIST 800-53',
    description: 'US federal information systems catalog.',
    control_count: 5,
    sample: ['AC-2', 'AC-6', 'AU-2', 'AU-6', 'SI-4'],
  },
  {
    id: 'soc2',
    name: 'SOC 2',
    description: 'Service Organization Control 2 — trust services criteria.',
    control_count: 4,
    sample: ['CC6.1', 'CC6.6', 'CC7.2', 'CC7.3'],
  },
  {
    id: 'iso_27001',
    name: 'ISO 27001',
    description: 'International ISMS standard.',
    control_count: 4,
    sample: ['A.5.1', 'A.5.16', 'A.5.24', 'A.8.16'],
  },
]

export default function CompliancePage() {
  const [selected, setSelected] = useState('nist_800_53')

  return (
    <SocShell
      title="Compliance"
      subtitle="Control framework selector — NIST 800-53, SOC 2, ISO 27001."
      current="compliance"
    >
      <SocNavBar current="compliance" />
      <div className="grid grid-cols-3 gap-3 mb-6">
        {frameworks.map(fw => (
          <button
            key={fw.id}
            onClick={() => setSelected(fw.id)}
            className={`text-left p-4 rounded-lg border transition-colors ${
              selected === fw.id
                ? 'bg-cyphra-accent/10 border-cyphra-accent/40'
                : 'bg-cyphra-surface border-cyphra-border hover:border-cyphra-border-light'
            }`}
          >
            <p className={`text-sm font-medium ${selected === fw.id ? 'text-cyphra-accent' : 'text-cyphra-text-primary'}`}>
              {fw.name}
            </p>
            <p className="text-xs text-cyphra-text-muted mt-1">{fw.description}</p>
            <p className="text-[10px] uppercase tracking-wider text-cyphra-text-muted mt-2">
              {fw.control_count} controls
            </p>
          </button>
        ))}
      </div>
      <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-4">
        <h3 className="text-xs uppercase tracking-wider text-cyphra-text-muted mb-3">
          {frameworks.find(f => f.id === selected)?.name} sample controls
        </h3>
        <ul className="space-y-1">
          {frameworks.find(f => f.id === selected)?.sample.map(c => (
            <li key={c} className="text-xs font-mono text-cyphra-text-secondary">- {c}</li>
          ))}
        </ul>
        <p className="text-xs text-cyphra-text-muted mt-4">
          Interactive control-by-control evaluation ships in a follow-up.
          Drive it from the SOC root: <code className="text-cyphra-accent">python -m compliance.evaluate</code>
        </p>
      </div>
    </SocShell>
  )
}
