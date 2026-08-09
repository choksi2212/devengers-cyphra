import { useEffect, useRef } from 'react'
import * as THREE from 'three'

export default function WebGLBackground() {
  const containerRef = useRef(null)
  const animationRef = useRef(null)

  useEffect(() => {
    if (!containerRef.current) return

    const container = containerRef.current
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000)
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true })

    renderer.setSize(window.innerWidth, window.innerHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    container.appendChild(renderer.domElement)

    // Particle grid system
    const particleCount = 120
    const positions = new Float32Array(particleCount * 3)
    const velocities = []
    const spread = 40

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3] = (Math.random() - 0.5) * spread
      positions[i * 3 + 1] = (Math.random() - 0.5) * spread
      positions[i * 3 + 2] = (Math.random() - 0.5) * spread * 0.5
      velocities.push({
        x: (Math.random() - 0.5) * 0.008,
        y: (Math.random() - 0.5) * 0.008,
        z: (Math.random() - 0.5) * 0.004,
      })
    }

    const particleGeometry = new THREE.BufferGeometry()
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))

    const particleMaterial = new THREE.PointsMaterial({
      color: 0x0ea5e9,
      size: 0.06,
      transparent: true,
      opacity: 0.6,
      sizeAttenuation: true,
    })

    const particles = new THREE.Points(particleGeometry, particleMaterial)
    scene.add(particles)

    // Connection lines between nearby particles
    const linesMaterial = new THREE.LineBasicMaterial({
      color: 0x0ea5e9,
      transparent: true,
      opacity: 0.08,
    })

    let linesGeometry = new THREE.BufferGeometry()
    const linesMesh = new THREE.LineSegments(linesGeometry, linesMaterial)
    scene.add(linesMesh)

    camera.position.z = 20

    const connectionDistance = 6

    const animate = () => {
      animationRef.current = requestAnimationFrame(animate)

      const posArray = particleGeometry.attributes.position.array

      for (let i = 0; i < particleCount; i++) {
        posArray[i * 3] += velocities[i].x
        posArray[i * 3 + 1] += velocities[i].y
        posArray[i * 3 + 2] += velocities[i].z

        // Boundary wrapping
        const halfSpread = spread / 2
        if (posArray[i * 3] > halfSpread) posArray[i * 3] = -halfSpread
        if (posArray[i * 3] < -halfSpread) posArray[i * 3] = halfSpread
        if (posArray[i * 3 + 1] > halfSpread) posArray[i * 3 + 1] = -halfSpread
        if (posArray[i * 3 + 1] < -halfSpread) posArray[i * 3 + 1] = halfSpread
      }

      particleGeometry.attributes.position.needsUpdate = true

      // Rebuild connection lines
      const linePositions = []
      for (let i = 0; i < particleCount; i++) {
        for (let j = i + 1; j < particleCount; j++) {
          const dx = posArray[i * 3] - posArray[j * 3]
          const dy = posArray[i * 3 + 1] - posArray[j * 3 + 1]
          const dz = posArray[i * 3 + 2] - posArray[j * 3 + 2]
          const dist = Math.sqrt(dx * dx + dy * dy + dz * dz)

          if (dist < connectionDistance) {
            linePositions.push(
              posArray[i * 3], posArray[i * 3 + 1], posArray[i * 3 + 2],
              posArray[j * 3], posArray[j * 3 + 1], posArray[j * 3 + 2]
            )
          }
        }
      }

      linesGeometry.dispose()
      linesGeometry = new THREE.BufferGeometry()
      if (linePositions.length > 0) {
        linesGeometry.setAttribute(
          'position',
          new THREE.Float32BufferAttribute(linePositions, 3)
        )
      }
      linesMesh.geometry = linesGeometry

      // Slow rotation
      particles.rotation.y += 0.0003
      particles.rotation.x += 0.0001

      renderer.render(scene, camera)
    }

    animate()

    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight
      camera.updateProjectionMatrix()
      renderer.setSize(window.innerWidth, window.innerHeight)
    }

    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      if (animationRef.current) cancelAnimationFrame(animationRef.current)
      renderer.dispose()
      particleGeometry.dispose()
      particleMaterial.dispose()
      linesMaterial.dispose()
      linesGeometry.dispose()
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
    }
  }, [])

  return <div ref={containerRef} className="webgl-bg" />
}
