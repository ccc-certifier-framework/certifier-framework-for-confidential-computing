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
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "key" && vse.Clause.GetVerb() == "is-trusted-for-attestation" {
		return true
	}
	return false
}

// policyKey says platform has-trusted-platform-property
func isPlatformFeatureStatement(vse *certprotos.VseClause) bool {
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "platform" && vse.Clause.GetVerb() == "has-trusted-platform-property" {
		return true
	}
	return false
}

// policyKey says measurement is-trusted
func isMeasurementStatement(vse *certprotos.VseClause) bool {
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "measurement" && vse.Clause.GetVerb() == "is-trusted" {
		return true
	}
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

// Returns the single policy statement naming the relevant platform key policy statement for a this evidence package
func GetRelevantPlatformKeyPolicy(pool *PolicyPool, evp *certprotos.EvidencePackage) *certprotos.VseClause {
	// find the platform key needed from evp and the corresponding policy rule
	return nil
}

// Returns the single policy statement naming the relevant measurement policy statement for a this evidence package
func GetRelevantMeasurementPolicy(pool *PolicyPool, evp *certprotos.EvidencePackage) *certprotos.VseClause {
	// find the measurement key needed from evp and the corresponding policy rule
	return nil
}

// Returns the single policy statement naming the relevant trusted-platform policy statement for a this evidence package
func GetRelevantPlatformFeaturePolicy(pool *PolicyPool, evp *certprotos.EvidencePackage) *certprotos.VseClause {
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
