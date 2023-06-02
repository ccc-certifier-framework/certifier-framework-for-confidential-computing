type PolicyPool struct {
	Initialized bool
	// Contains all the policy statements
	AllPolicy *certprotos.ProvedStatements
	// Contains platform key policy statements
	PlatformKeyPolicy *certprotos.ProvedStatements
	// Contains trusted measurement statements
	MeasurementPolicy *certprotos.ProvedStatements
	// Contains platform features statements
	PlatformFeaturePolicy *certprotos.ProvedStatements
}

// policyKey says platformKey is-trusted-for-attestation
func isPlatformKeyStatement(vse *certprotos.VseClause) bool {
	return false
}

// policyKey says platform has-trusted-platform-property
func isPlatformFeatureStatement(vse *certprotos.VseClause) bool {
	return false
}

// policyKey says measurement is-trusted
func isMeasurementStatement(vse *certprotos.VseClause) bool {
	return false
}

func InitPolicyPool(pool *PolicyPool) bool {

	pool.AllPolicy = nil
	pool.PlatformKeyPolicy = nil
	pool.MeasurementPolicy = nil
	pool.PlatformFeaturePolicy = nil

	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		pool.AllPolicy.Proved = append(pool.AllPolicy.Proved, from)
		// to :=  proto.Clone(from).(*certprotos.VseClause)
		if isPlatformKeyStatement(from) {
			pool.PlatformKeyPolicy = append(pool.PlatformKeyPolicy, from)
		}
		if isPlatformFeatureStatement(from) {
			pool.PlatformFeaturePolicy = append(pool.PlatformFeaturePolicy, from)
		}
		if isPlatformMeasurementStatement(from) {
			pool.MeasurementPolicy = append(pool.MeasurementPolicy, from)
		}
	}
	pool.Initialized = true	
	return true
}

func GetRelevantPlatformKeyPolicy(ps *certprotos.ProvedStatements, evp *certprotos.EvidencePackage) *certprotos.VseClause {
	return nil
}

func GetRelevantMeasurementPolicy(ps *certprotos.ProvedStatements, evp *certprotos.EvidencePackage) *certprotos.VseClause {
	return nil
}

func GetRelevantPlatformFeaturePolicy(ps *certprotos.ProvedStatements, evp *certprotos.EvidencePackage) *certprotos.VseClause {
	return nil
}


/*
	InitPolicyPool puts policy first in AllPolicy
	PlatformKeyStatements is the list of policy statements about platform keys
	MeasurementsStatements is the list of policy statements about programs (measurements)
	PlatformFeatureStatements is a list of policy about platform policy

	After pool is initialized, instead of callint FilterPolicy, the proof constructors
	use GetRelevantPlatformKeyPolicy, GetRelevantMeasurementPolicy and PlatformFeatureStatements
	to retrieve the policies relevant to the specified EvidencePackage when constructing proofs.
	Each must return the single relevant policy statement of the named type needed in the
	constructed proof
 */
