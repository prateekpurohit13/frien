package version

const ProtoVersion uint32 = 1
var SupportedVersions = []uint32{1}
var SoftwareVersion = "dev"

// Negotiate returns the highest version both peers support, or 0 if none is common.
func Negotiate(remote []uint32) uint32 {
	for _, rv := range remote {
		for _, lv := range SupportedVersions {
			if rv == lv {
				return lv
			}
		}
	}
	return 0
}

func IsSupported(v uint32) bool {
	for _, lv := range SupportedVersions {
		if v == lv {
			return true
		}
	}
	return false
}
