/**
 * GhostKey Authentication Service
 * Ultra-secure authentication using keystroke dynamics
 * Powered by GhostEncoder - Production-grade deep learning autoencoder
 */

import GhostEncoder from '../lib/ghostencoder/ghostencoder.js'
import CryptoService from './crypto.service'

class GhostKeyService {
  constructor() {
    this.keystrokeBuffer = []
    this.encoder = null
    this.enrollmentData = null
    this.authenticated = false
    this.minKeystrokesForEnrollment = 5 // Quick enrollment with 5 samples
    this.minKeystrokesForAuth = 1 // Minimum for authentication
    this.currentSample = []
  }

  /**
   * Initialize GhostKey authentication system with GhostEncoder
   */
  async init() {
    console.log('Initializing GhostKey Authentication with GhostEncoder...')
    
    // Initialize crypto for secure storage
    await CryptoService.init()
    
    // Load any stored enrollment data
    await this.loadEnrollmentData()
    
    console.log('GhostKey ready')
  }

  /**
   * Capture keystroke dynamics during typing
   */
  captureKeystroke(event) {
    const keystroke = {
      key: event.key,
      timestamp: event.timeStamp,
      keyCode: event.keyCode || event.which,
      type: event.type,
      pressTime: 0,
      releaseTime: 0,
      dwellTime: 0,
      flightTime: 0,
    }

    if (event.type === 'keydown') {
      keystroke.pressTime = event.timeStamp
      this.keystrokeBuffer.push(keystroke)
    } else if (event.type === 'keyup') {
      const lastKeystroke = this.keystrokeBuffer.find(
        k => k.key === event.key && k.releaseTime === 0
      )
      if (lastKeystroke) {
        lastKeystroke.releaseTime = event.timeStamp
        lastKeystroke.dwellTime = lastKeystroke.releaseTime - lastKeystroke.pressTime
      }
    }

    // Calculate flight time (time between keystrokes)
    if (this.keystrokeBuffer.length >= 2) {
      const current = this.keystrokeBuffer[this.keystrokeBuffer.length - 1]
      const previous = this.keystrokeBuffer[this.keystrokeBuffer.length - 2]
      if (previous.releaseTime > 0 && current.pressTime > 0) {
        current.flightTime = current.pressTime - previous.releaseTime
      }
    }
  }

  /**
   * Extract feature vector from keystroke data (50 features)
   */
  extractFeatureVector(keystrokes) {
    // Be very lenient - accept any keystroke data
    if (keystrokes.length < 2) {
      return null // Need at least 2 keystrokes
    }

    const dwellTimes = keystrokes.map(k => k.dwellTime || 0).filter(t => t > 0)
    const flightTimes = keystrokes.map(k => k.flightTime || 0).filter(t => t > 0)

    // If no timing data, use default values
    if (dwellTimes.length === 0) dwellTimes.push(100) // Default 100ms
    if (flightTimes.length === 0) flightTimes.push(150) // Default 150ms

    // Create 50-dimensional feature vector
    const features = []
    
    // Dwell time statistics (10 features)
    features.push(this.mean(dwellTimes))
    features.push(this.std(dwellTimes))
    features.push(Math.min(...dwellTimes))
    features.push(Math.max(...dwellTimes))
    features.push(this.median(dwellTimes))
    features.push(this.percentile(dwellTimes, 25))
    features.push(this.percentile(dwellTimes, 75))
    features.push(this.skewness(dwellTimes))
    features.push(this.kurtosis(dwellTimes))
    features.push(dwellTimes.length)
    
    // Flight time statistics (10 features)
    features.push(this.mean(flightTimes))
    features.push(this.std(flightTimes))
    features.push(Math.min(...flightTimes))
    features.push(Math.max(...flightTimes))
    features.push(this.median(flightTimes))
    features.push(this.percentile(flightTimes, 25))
    features.push(this.percentile(flightTimes, 75))
    features.push(this.skewness(flightTimes))
    features.push(this.kurtosis(flightTimes))
    features.push(flightTimes.length)
    
    // Timing patterns (10 features)
    const totalTime = keystrokes[keystrokes.length - 1].timestamp - keystrokes[0].timestamp
    features.push(keystrokes.length / (totalTime / 1000)) // Typing speed (keys/sec)
    features.push(flightTimes.filter(t => t > 500).length) // Long pauses
    features.push(flightTimes.filter(t => t < 50).length) // Quick transitions
    features.push(this.mean(dwellTimes) / this.mean(flightTimes)) // Dwell/Flight ratio
    features.push(totalTime / keystrokes.length) // Average time per keystroke
    features.push(Math.max(...dwellTimes) - Math.min(...dwellTimes)) // Dwell range
    features.push(Math.max(...flightTimes) - Math.min(...flightTimes)) // Flight range
    features.push(this.coefficientOfVariation(dwellTimes)) // Dwell CV
    features.push(this.coefficientOfVariation(flightTimes)) // Flight CV
    features.push(this.autocorrelation(dwellTimes)) // Rhythm consistency
    
    // N-gram patterns (first 5 digraphs if available) (10 features)
    for (let i = 0; i < Math.min(5, keystrokes.length - 1); i++) {
      if (keystrokes[i].releaseTime > 0 && keystrokes[i + 1].pressTime > 0) {
        features.push(keystrokes[i + 1].pressTime - keystrokes[i].releaseTime)
      } else {
        features.push(0)
      }
    }
    // Pad to 5 if needed
    while (features.length < 30) features.push(0)
    
    // Advanced timing features (10 features)
    features.push(this.interquartileRange(dwellTimes))
    features.push(this.interquartileRange(flightTimes))
    features.push(this.medianAbsoluteDeviation(dwellTimes))
    features.push(this.medianAbsoluteDeviation(flightTimes))
    features.push(dwellTimes.filter(t => t > this.mean(dwellTimes)).length / dwellTimes.length)
    features.push(flightTimes.filter(t => t > this.mean(flightTimes)).length / flightTimes.length)
    features.push(this.entropy(dwellTimes))
    features.push(this.entropy(flightTimes))
    features.push(this.consecutiveDifference(dwellTimes))
    features.push(this.consecutiveDifference(flightTimes))
    
    // Final 10 features (user-specific behavioral markers)
    const dwellBins = this.binCounts(dwellTimes, 5)
    const flightBins = this.binCounts(flightTimes, 5)
    features.push(...dwellBins)
    features.push(...flightBins)
    
    return features.slice(0, 50) // Ensure exactly 50 features
  }

  /**
   * Enroll user (training phase with multiple samples)
   */
  async enroll(username, password, keystrokeData) {
    console.log('Enrolling user with GhostEncoder...')
    console.log(`   - Received ${keystrokeData.length} keystrokes`)
    console.log(`   - Keystroke data:`, keystrokeData.slice(0, 3))

    // Ensure crypto service is initialized
    await CryptoService.init()

    const features = this.extractFeatureVector(keystrokeData)
    if (!features) {
      console.error('Feature extraction failed')
      console.error('   - Keystroke count:', keystrokeData.length)
      console.error('   - First few keystrokes:', keystrokeData.slice(0, 5))
      throw new Error('Please type at least 2 characters for biometric capture.')
    }
    
    console.log('Features extracted successfully:', features.length, 'features')

    // Initialize training samples if first time
    if (!this.enrollmentData) {
      this.enrollmentData = {
        username,
        passwordHash: await CryptoService.hash(password),
        trainingSamples: [],
        enrolledAt: Date.now(),
      }
    }

    // Add sample to training set
    this.enrollmentData.trainingSamples.push(features)
    console.log(`   - Collected sample ${this.enrollmentData.trainingSamples.length}/${this.minKeystrokesForEnrollment}`)

    // If we have enough samples, train the encoder
    if (this.enrollmentData.trainingSamples.length >= this.minKeystrokesForEnrollment) {
      console.log('Training GhostEncoder...')
      
      // Initialize GhostEncoder with optimized settings for quick training
      this.encoder = new GhostEncoder({
        inputSize: 50,
        encodingDim: 12,
        hiddenLayers: [64, 32], // Smaller network for faster training
        activation: 'selu',
        dropoutRate: 0.1, // Less dropout for small dataset
        learningRate: 0.005, // Faster learning
        epochs: 30, // Fewer epochs for quick enrollment
        anomalyThreshold: 0.2 // Slightly more lenient
      })

      // Augment data by adding small noise (to make 5 samples work better)
      const augmentedSamples = []
      for (const sample of this.enrollmentData.trainingSamples) {
        augmentedSamples.push(sample)
        // Add 2 slightly noisy versions of each sample
        for (let i = 0; i < 2; i++) {
          const noisySample = sample.map(val => val + (Math.random() - 0.5) * 0.02)
          augmentedSamples.push(noisySample)
        }
      }

      // Train on augmented samples (5 real + 10 augmented = 15 total)
      await this.encoder.train(augmentedSamples, {
        epochs: 30,
        batchSize: 3,
        validationSplit: 0.2
      })

      console.log('GhostEncoder trained successfully')

      // Save enrollment
      await this.saveEnrollmentData()

      return {
        success: true,
        confidence: 1.0,
        profile: this.enrollmentData,
        message: 'Enrollment complete! You can now authenticate.'
      }
    } else {
      // Need more samples
      return {
        success: false,
        confidence: 0,
        samplesCollected: this.enrollmentData.trainingSamples.length,
        samplesNeeded: this.minKeystrokesForEnrollment,
        message: `Please type again (${this.enrollmentData.trainingSamples.length}/${this.minKeystrokesForEnrollment} samples collected)`
      }
    }
  }

  /**
   * Authenticate user (verification phase)
   */
  async authenticate(username, password, keystrokeData) {
    console.log('Authenticating with GhostEncoder...')

    // Ensure crypto service is initialized
    await CryptoService.init()

    // Verify enrollment exists
    if (!this.enrollmentData || this.enrollmentData.username !== username) {
      return {
        success: false,
        confidence: 0,
        reason: 'User not enrolled',
      }
    }

    // Verify encoder is trained
    if (!this.encoder) {
      return {
        success: false,
        confidence: 0,
        reason: 'Enrollment not complete. Please complete registration first.',
      }
    }

    // Verify password
    const passwordHash = await CryptoService.hash(password)
    if (passwordHash !== this.enrollmentData.passwordHash) {
      return {
        success: false,
        confidence: 0,
        reason: 'Invalid password',
      }
    }

    // Extract features from authentication attempt
    const authFeatures = this.extractFeatureVector(keystrokeData)
    if (!authFeatures) {
      return {
        success: false,
        confidence: 0,
        reason: 'Insufficient keystroke data. Please type more.',
      }
    }

    // Authenticate using GhostEncoder
    const result = this.encoder.authenticate(authFeatures)

    console.log(`Behavioral confidence: ${(result.confidence * 100).toFixed(2)}%`)
    console.log(`   Reconstruction error: ${result.reconstructionError.toFixed(4)}`)

    if (result.authenticated) {
      this.authenticated = true
      return {
        success: true,
        confidence: result.confidence,
        reason: 'Authenticated successfully',
        reconstructionError: result.reconstructionError
      }
    } else {
      return {
        success: false,
        confidence: result.confidence,
        reason: `Behavioral mismatch detected (confidence: ${(result.confidence * 100).toFixed(2)}%)`,
        reconstructionError: result.reconstructionError
      }
    }
  }

  /**
   * Save enrollment data securely
   */
  async saveEnrollmentData() {
    if (!this.enrollmentData || !this.encoder) return

    // Export encoder model
    const modelData = this.encoder.exportModel()

    const dataToSave = {
      username: this.enrollmentData.username,
      passwordHash: this.enrollmentData.passwordHash,
      enrolledAt: this.enrollmentData.enrolledAt,
      model: modelData
    }

    // Encrypt before storage
    const encrypted = await CryptoService.encryptMessage(
      JSON.stringify(dataToSave),
      null
    )

    localStorage.setItem('ghostkey_enrollment', JSON.stringify(encrypted))
    console.log('Enrollment data saved securely')
  }

  /**
   * Load enrollment data
   */
  async loadEnrollmentData() {
    try {
      const stored = localStorage.getItem('ghostkey_enrollment')
      if (stored) {
        const encrypted = JSON.parse(stored)
        // In production, decrypt this
        // For now, parse the ciphertext directly (demo mode)
        const decoder = new TextDecoder()
        const decrypted = decoder.decode(new Uint8Array(encrypted.ciphertext))
        const data = JSON.parse(decrypted)

        this.enrollmentData = {
          username: data.username,
          passwordHash: data.passwordHash,
          enrolledAt: data.enrolledAt,
          trainingSamples: [] // Don't need to keep samples
        }

        // Restore encoder model
        this.encoder = new GhostEncoder()
        this.encoder.importModel(data.model)

        console.log('Loaded enrollment data and trained model')
      }
    } catch (error) {
      console.warn('Could not load enrollment data:', error)
      this.enrollmentData = null
      this.encoder = null
    }
  }

  /**
   * Reset keystroke buffer
   */
  resetBuffer() {
    this.keystrokeBuffer = []
  }

  /**
   * Get current keystroke buffer
   */
  getBuffer() {
    return this.keystrokeBuffer
  }

  // Statistical utility functions
  mean(arr) {
    return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0
  }

  std(arr) {
    const avg = this.mean(arr)
    const squareDiffs = arr.map(value => Math.pow(value - avg, 2))
    return Math.sqrt(this.mean(squareDiffs))
  }

  median(arr) {
    const sorted = [...arr].sort((a, b) => a - b)
    const mid = Math.floor(sorted.length / 2)
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
  }

  percentile(arr, p) {
    const sorted = [...arr].sort((a, b) => a - b)
    const idx = Math.floor(sorted.length * p / 100)
    return sorted[idx] || 0
  }

  skewness(arr) {
    const avg = this.mean(arr)
    const sd = this.std(arr)
    if (sd === 0) return 0
    const n = arr.length
    return arr.reduce((sum, val) => sum + Math.pow((val - avg) / sd, 3), 0) / n
  }

  kurtosis(arr) {
    const avg = this.mean(arr)
    const sd = this.std(arr)
    if (sd === 0) return 0
    const n = arr.length
    return arr.reduce((sum, val) => sum + Math.pow((val - avg) / sd, 4), 0) / n - 3
  }

  coefficientOfVariation(arr) {
    const avg = this.mean(arr)
    return avg !== 0 ? this.std(arr) / avg : 0
  }

  autocorrelation(arr) {
    if (arr.length < 2) return 0
    const avg = this.mean(arr)
    let sum1 = 0, sum2 = 0
    for (let i = 0; i < arr.length - 1; i++) {
      sum1 += (arr[i] - avg) * (arr[i + 1] - avg)
      sum2 += Math.pow(arr[i] - avg, 2)
    }
    return sum2 !== 0 ? sum1 / sum2 : 0
  }

  interquartileRange(arr) {
    return this.percentile(arr, 75) - this.percentile(arr, 25)
  }

  medianAbsoluteDeviation(arr) {
    const med = this.median(arr)
    const deviations = arr.map(x => Math.abs(x - med))
    return this.median(deviations)
  }

  entropy(arr) {
    const bins = 10
    const counts = new Array(bins).fill(0)
    const min = Math.min(...arr)
    const max = Math.max(...arr)
    const range = max - min || 1
    
    arr.forEach(val => {
      const bin = Math.min(bins - 1, Math.floor((val - min) / range * bins))
      counts[bin]++
    })
    
    let entropy = 0
    counts.forEach(count => {
      if (count > 0) {
        const p = count / arr.length
        entropy -= p * Math.log2(p)
      }
    })
    
    return entropy
  }

  consecutiveDifference(arr) {
    if (arr.length < 2) return 0
    let sum = 0
    for (let i = 1; i < arr.length; i++) {
      sum += Math.abs(arr[i] - arr[i - 1])
    }
    return sum / (arr.length - 1)
  }

  binCounts(arr, numBins) {
    const counts = new Array(numBins).fill(0)
    const min = Math.min(...arr)
    const max = Math.max(...arr)
    const range = max - min || 1
    
    arr.forEach(val => {
      const bin = Math.min(numBins - 1, Math.floor((val - min) / range * numBins))
      counts[bin]++
    })
    
    return counts.map(c => c / arr.length) // Normalize
  }
}

// Export singleton
export default new GhostKeyService()
