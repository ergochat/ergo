//go:build !i18n

package i18n

const (
	Enabled = false

	DefaultCasemapping = CasemappingASCII
)

func CasefoldWithSetting(str string, setting Casemapping) (string, error) {
	return foldASCII(str)
}

func Skeleton(str string) (string, error) {
	// identity function is fine because we independently case-normalize in Casefold
	return str, nil
}
