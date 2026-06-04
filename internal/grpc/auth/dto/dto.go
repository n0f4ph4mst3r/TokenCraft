package dto

import (
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

type Auth struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8,max=16"`
}

type Register struct {
	Auth
	Username string `validate:"required,min=2,max=50"`
}
type Login struct {
	Auth
	App int64 `validate:"required,gt=0"`
}

type RefreshToken struct {
	Token string `validate:"required"`
}

type RoleCheck struct {
	RefreshToken
	Role string `validate:"required,min=2,max=50"`
}

var validationMap = map[string]map[string]string{
	"Username": {
		"required": "Username is required",
		"min":      "Username must be at least 2 characters",
		"max":      "Username must be at most 50 characters",
	},
	"Email": {
		"required": "Email is required",
		"email":    "Email must be valid",
	},
	"Password": {
		"required": "Password is required",
		"min":      "Password must be at least 8 characters",
		"max":      "Password must be at most 16 characters",
	},
	"User": {
		"required": "User ID is required",
		"uuid4":    "User ID must be a valid UUID",
	},
	"App": {
		"required": "App ID is required",
		"gt":       "App ID cannot be empty",
	},
	"Token": {
		"required": "Refresh token is required",
	},
	"Role": {
		"required": "Role is required",
		"min":      "Role must be at least 2 characters",
		"max":      "Role must be at most 50 characters",
	},
}

func ValidateInput(input interface{}) error {

	if err := validate.Struct(input); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {

			var messages []string
			for _, ve := range validationErrors {
				translatedErr := func(e validator.FieldError) string {
					if field, ok := validationMap[e.Field()]; ok {
						if msg, ok := field[e.Tag()]; ok {
							return msg
						}
					}
					return e.Error()
				}(ve)

				messages = append(messages, translatedErr)
			}

			return status.Errorf(
				codes.InvalidArgument,
				"validation error: %v",
				messages,
			)
		}

		return status.Errorf(codes.InvalidArgument, "validation error: %v", err)
	}

	return nil
}
