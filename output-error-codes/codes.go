package output_error_codes

const (
	InternalError = "internal error"

	// login
	PlaceholderIsRequired = "placeholder is required"
	PasswordIsRequired    = "password is required"
	InvalidPlaceholder    = "invalid placeholder"
	InvalidCredentials    = "invalid credentials"

	// register
	EmailIsRequired    = "email is required"
	UsernameIsRequired = "username is required"
	AppIdIsRequired    = "app id is required"
	InvalidEmail       = "invalid email"
	InvalidUsername    = "invalid username"
	InvalidPassword    = "invalid password. Required: 8 <= length <= 72; lower, upper, numeric, special characters."
	UserAlreadyExists  = "user already exists"

	// IsAdmin
	UserNotFound = "user not found"

	// AppID
	WrongAppSecret         = "wrong app secret"
	AppSecretAlreadyExists = "app secret already exists for another app! generate a new one."
	NameIsRequired         = "name is required"
	SecretIsRequired       = "secret is required"
	InvalidUserID          = "invalid user id"
)
