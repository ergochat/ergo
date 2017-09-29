package caps

// Version is used to select which max version of CAP the client supports.
type Version uint

const (
	// Cap301 refers to the base CAP spec.
	Cap301 Version = 301
	// Cap302 refers to the IRCv3.2 CAP spec.
	Cap302 Version = 302
)
