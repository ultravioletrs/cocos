package ea

type SpontaneousAuthenticatorPolicy struct {
	AllowedSignatureSchemes      []uint16
	AllowedCertificateExtensions []uint16
}

func RequestPermitsCertificateExtension(req *AuthenticatorRequest, typ uint16) bool {
	if req == nil {
		return false
	}
	for _, e := range req.Extensions {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func PolicyPermitsCertificateExtension(policy *SpontaneousAuthenticatorPolicy, typ uint16) bool {
	if policy == nil {
		return false
	}
	for _, allowed := range policy.AllowedCertificateExtensions {
		if allowed == typ {
			return true
		}
	}
	return false
}

func policyPermitsSignatureScheme(policy *SpontaneousAuthenticatorPolicy, scheme uint16) bool {
	if policy == nil || len(policy.AllowedSignatureSchemes) == 0 {
		return true
	}
	for _, allowed := range policy.AllowedSignatureSchemes {
		if allowed == scheme {
			return true
		}
	}
	return false
}

func validateCertificateEntryExtensions(exts []Extension, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy) error {
	for _, e := range exts {
		if req != nil {
			if !RequestPermitsCertificateExtension(req, e.Type) {
				return ErrBadRequest
			}
			continue
		}
		if !PolicyPermitsCertificateExtension(policy, e.Type) {
			return ErrBadRequest
		}
	}
	return nil
}
