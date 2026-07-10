package version

const ProtoVersion uint32 = 1

var SupportedVersions = []uint32{1}
var SoftwareVersion = "dev"

func IsSupported(v uint32) bool {
	for _, lv := range SupportedVersions {
		if v == lv {
			return true
		}
	}
	return false
}
