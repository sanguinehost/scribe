use scribe_core::{ThermodynamicTelemetry, AdjointVerifier, SO2Rotor, CompositionalAuthRotor};
use tracing::{warn, debug, instrument};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdjointError {
    #[error("Thermodynamic surprise exceeds threshold: {surprise} > {threshold}")]
    SurpriseExceeded { surprise: f32, threshold: f32 },
    #[error("Auth rotor misalignment: {alignment}")]
    AuthRotorMisalignment { alignment: f32 },
    #[error("Invalid rotor state (non-unitary)")]
    InvalidRotorState,
}

pub struct HNAAdjointVerifier {
    pub reference_rotor: CompositionalAuthRotor,
    pub safe_threshold: f32,
}

impl HNAAdjointVerifier {
    pub fn new(reference_rotor: CompositionalAuthRotor, safe_threshold: f32) -> Self {
        Self {
            reference_rotor,
            safe_threshold,
        }
    }

    /// Verifies if a rotor is unitary (magnitude approx 1)
    fn is_unitary(rotor: &SO2Rotor) -> bool {
        let [cos, sin] = rotor.0;
        let mag_sq = cos * cos + sin * sin;
        (mag_sq - 1.0).abs() < 1e-4
    }
}

impl AdjointVerifier for HNAAdjointVerifier {
    #[instrument(skip(self, telemetry), fields(friston_free_energy = telemetry.friston_free_energy))]
    fn verify_adjoint(&self, telemetry: &ThermodynamicTelemetry, threshold: f32) -> bool {
        let t_rotor = SO2Rotor(telemetry.auth_rotor);
        
        // 1. Check rotor validity
        if !Self::is_unitary(&t_rotor) {
            warn!("Rejected update: Auth rotor is non-unitary");
            return false;
        }

        // 2. Calculate alignment (dot product) between telemetry rotor and reference rotor
        let [r_cos, r_sin] = self.reference_rotor.0.0;
        let [t_cos, t_sin] = telemetry.auth_rotor;
        
        let alignment = r_cos * t_cos + r_sin * t_sin;

        // 3. Free Energy Surprise Check
        let surprise = telemetry.friston_free_energy.abs();
        
        // We use the stricter of the two thresholds (provided or internal)
        let effective_threshold = threshold.min(self.safe_threshold);

        if surprise > effective_threshold {
            warn!(
                surprise,
                threshold = effective_threshold,
                "Rejected update: Thermodynamic surprise too high"
            );
            return false;
        }

        // 4. Adjoint Shadowing Direction Verification
        // If the alignment is poor, the update is likely adversarial or corrupted
        if alignment < 0.999 { // Extremely strict for identity verification
            warn!(
                alignment,
                "Rejected update: Adjoint verification failed (Rotor Misalignment)"
            );
            return false;
        }

        debug!(surprise, alignment, "Adjoint verification successful");
        true
    }
}

/// Compositional logic for Auth Rotors
pub fn compose_rotors(a: CompositionalAuthRotor, b: CompositionalAuthRotor) -> CompositionalAuthRotor {
    let [a_cos, a_sin] = a.0.0;
    let [b_cos, b_sin] = b.0.0;
    
    // SO(2) composition is complex multiplication
    let cos = a_cos * b_cos - a_sin * b_sin;
    let sin = a_cos * b_sin + a_sin * b_cos;
    
    CompositionalAuthRotor(SO2Rotor([cos, sin]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scribe_core::{ThermodynamicTelemetry, SO2Rotor, CompositionalAuthRotor};

    #[test]
    fn test_valid_adjoint_verification() {
        let reference_rotor = CompositionalAuthRotor(SO2Rotor::identity());
        let verifier = HNAAdjointVerifier::new(reference_rotor, 0.5);
        
        let telemetry = ThermodynamicTelemetry {
            friston_free_energy: 0.1,
            action_gradient: [0.0, 0.0, 0.0],
            entropy_variance: 0.05,
            auth_rotor: [1.0, 0.0], // Exactly aligned
            _padding: 0.0,
        };
        
        assert!(verifier.verify_adjoint(&telemetry, 1.0));
    }

    #[test]
    fn test_invalid_surprise_verification() {
        let reference_rotor = CompositionalAuthRotor(SO2Rotor::identity());
        let verifier = HNAAdjointVerifier::new(reference_rotor, 0.5);
        
        let telemetry = ThermodynamicTelemetry {
            friston_free_energy: 0.8, // Exceeds 0.5
            action_gradient: [0.0, 0.0, 0.0],
            entropy_variance: 0.05,
            auth_rotor: [1.0, 0.0],
            _padding: 0.0,
        };
        
        assert!(!verifier.verify_adjoint(&telemetry, 1.0));
    }

    #[test]
    fn test_misaligned_rotor_verification() {
        let reference_rotor = CompositionalAuthRotor(SO2Rotor::identity());
        let verifier = HNAAdjointVerifier::new(reference_rotor, 1.0);
        
        let telemetry = ThermodynamicTelemetry {
            friston_free_energy: 0.1,
            action_gradient: [0.0, 0.0, 0.0],
            entropy_variance: 0.05,
            auth_rotor: [0.0, 1.0], // Orthogonal (misaligned)
            _padding: 0.0,
        };
        
        assert!(!verifier.verify_adjoint(&telemetry, 1.0));
    }

    #[test]
    fn test_compositional_rotor() {
        let rotor_a = CompositionalAuthRotor(SO2Rotor([0.0, 1.0])); // 90 deg
        let rotor_b = CompositionalAuthRotor(SO2Rotor([0.0, 1.0])); // 90 deg
        
        let composed = compose_rotors(rotor_a, rotor_b);
        
        // 90 + 90 = 180 deg -> cos = -1, sin = 0
        assert!((composed.0.0[0] - (-1.0)).abs() < 1e-6);
        assert!((composed.0.0[1] - 0.0).abs() < 1e-6);
    }
}
