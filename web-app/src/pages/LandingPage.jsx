import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import gsap from 'gsap'
import { Shield, Lock, Zap, Eye, ArrowRight, Activity } from 'lucide-react'
import WebGLBackground from '../components/WebGLBackground'

export default function LandingPage() {
  const navigate = useNavigate()
  const heroRef = useRef(null)
  const featuresRef = useRef(null)
  const specsRef = useRef(null)

  useEffect(() => {
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ defaults: { ease: 'power3.out' } })

      tl.fromTo('.hero-badge', { opacity: 0, y: -20 }, { opacity: 1, y: 0, duration: 0.6 })
        .fromTo('.hero-title', { opacity: 0, y: 30 }, { opacity: 1, y: 0, duration: 0.8 }, '-=0.3')
        .fromTo('.hero-subtitle', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.6 }, '-=0.4')
        .fromTo('.hero-cta', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.5 }, '-=0.3')
        .fromTo('.spec-card', { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: 0.4, stagger: 0.08 }, '-=0.2')
        .fromTo('.feature-card', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.4, stagger: 0.1 }, '-=0.1')
        .fromTo('.footer-badges', { opacity: 0 }, { opacity: 1, duration: 0.5 }, '-=0.1')
    }, heroRef)

    return () => ctx.revert()
  }, [])

  const features = [
    {
      icon: Shield,
      title: 'Post-Quantum Encryption',
      desc: 'Kyber-1024 + Dilithium3 hybrid cryptography resistant to quantum computing attacks.',
    },
    {
      icon: Eye,
      title: 'Metadata Protection',
      desc: 'AI-driven traffic shaping with adaptive padding and mixnet onion routing.',
    },
    {
      icon: Zap,
      title: 'Self-Destructing Messages',
      desc: 'Automatic crypto-erase with zero forensic traces after configurable timers.',
    },
    {
      icon: Activity,
      title: 'Real-Time Threat Detection',
      desc: '99.3% accuracy anomaly detection trained on 16M+ network flows.',
    },
  ]

  const specs = [
    { label: 'Encryption', value: 'AES-256-GCM + Kyber-1024' },
    { label: 'Threat Detection', value: '99.3% Accuracy' },
    { label: 'Latency', value: '<300ms E2E' },
    { label: 'Classification', value: 'Military-Grade' },
  ]

  return (
    <div ref={heroRef} className="min-h-screen bg-cyphra-bg relative">
      <WebGLBackground />

      <div className="relative z-10">
        {/* Nav */}
        <header className="border-b border-cyphra-border/50">
          <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center">
              <img src="/cyphra-logo.png" alt="CYPHRA" className="h-20 object-contain" />
            </div>
            <button
              onClick={() => navigate('/auth')}
              className="btn-ghost text-xs"
            >
              Sign In
            </button>
          </div>
        </header>

        {/* Hero */}
        <section className="max-w-4xl mx-auto px-6 pt-24 pb-16 text-center">
          <div className="hero-badge inline-flex items-center gap-2 px-3 py-1.5 rounded border border-cyphra-border text-xs text-cyphra-text-secondary mb-8 opacity-0">
            <Lock className="w-3 h-3 text-cyphra-accent" strokeWidth={1.5} />
            <span>Post-Quantum Encrypted</span>
            <span className="w-1 h-1 rounded-full bg-cyphra-text-muted" />
            <span>Zero-Knowledge Architecture</span>
          </div>

          <h1 className="hero-title text-5xl md:text-7xl font-bold text-cyphra-text-primary mb-6 leading-[1.1] tracking-tight opacity-0">
            CYPHRA
          </h1>

          <p className="hero-subtitle text-lg md:text-xl text-cyphra-text-secondary max-w-2xl mx-auto mb-10 leading-relaxed opacity-0">
            Guarding the Unseen Layer of Defense. Military-grade secure messaging with AI-powered threat detection and post-quantum encryption.
          </p>

          <div className="hero-cta flex flex-col sm:flex-row gap-3 justify-center items-center mb-16 opacity-0">
            <button
              onClick={() => navigate('/auth')}
              className="btn-primary px-8 py-3"
            >
              Get Started
              <ArrowRight className="w-4 h-4" strokeWidth={1.5} />
            </button>
            <button
              onClick={() => navigate('/security')}
              className="btn-secondary px-8 py-3"
            >
              Security Overview
            </button>
          </div>

          {/* Specs */}
          <div ref={specsRef} className="grid grid-cols-2 md:grid-cols-4 gap-3 max-w-3xl mx-auto">
            {specs.map((spec) => (
              <div
                key={spec.label}
                className="spec-card bg-cyphra-surface border border-cyphra-border rounded p-4 text-left opacity-0"
              >
                <div className="text-xs text-cyphra-text-muted mb-1.5">{spec.label}</div>
                <div className="text-sm font-semibold text-cyphra-text-primary font-mono">{spec.value}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Features */}
        <section ref={featuresRef} className="max-w-5xl mx-auto px-6 pb-20">
          <div className="grid md:grid-cols-2 gap-4">
            {features.map((feature) => {
              const Icon = feature.icon
              return (
                <div
                  key={feature.title}
                  className="feature-card card-hover group p-5 opacity-0"
                >
                  <div className="flex items-start gap-4">
                    <div className="p-2.5 bg-cyphra-accent/10 rounded flex-shrink-0">
                      <Icon className="w-5 h-5 text-cyphra-accent" strokeWidth={1.5} />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-cyphra-text-primary mb-1.5">{feature.title}</h3>
                      <p className="text-sm text-cyphra-text-secondary leading-relaxed">{feature.desc}</p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* Footer Badges + Copyright */}
        <footer className="border-t border-cyphra-border/50 py-8">
          <div className="max-w-5xl mx-auto px-6">
            <div className="footer-badges flex flex-wrap justify-center gap-3 mb-6 opacity-0">
              {['Post-Quantum Secure', '99.3% Threat Detection', 'Zero Metadata Leaks', 'Forensic Denial'].map((text) => (
                <span key={text} className="badge-info text-[11px]">{text}</span>
              ))}
            </div>
            <p className="text-center text-xs text-cyphra-text-muted">
              CYPHRA 2025. All rights reserved.
            </p>
          </div>
        </footer>
      </div>
    </div>
  )
}

