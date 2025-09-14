package utils

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var customErrorMessages = map[string]string{
	"required":        "This field is required",
	"email":           "Please provide a valid email address",
	"min":             "Must be at least %s characters long",
	"max":             "Cannot exceed %s characters",
	"strong_password": "Password must contain at least 8 characters, one uppercase, one lowercase, one number, and one special character",
	"username":        "Username must contain only letters, numbers, underscores, and hyphens",
	"url":             "Please provide a valid URL",
	"phone":           "Please provide a valid phone number",
	"alpha":           "Must contain only alphabetic characters",
	"alphanumeric":    "Must contain only letters and numbers",
	"no_spaces":       "Spaces are not allowed",
	"task_priority":   "Priority must be one of: low, medium, high, urgent",
	"task_status":     "Status must be one of: pending, in_progress, completed, cancelled",
	"uuid":            "Please provide a valid UUID format",
}

type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	var errors []string
	for _, err := range ve {
		errors = append(errors, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(errors, "; ")
}

type CustomValidator struct {
	validate *validator.Validate
}

func NewCustomValidator() *CustomValidator {
	validate := validator.New()

	// Register all custom validations
	cv := &CustomValidator{validate: validate}
	cv.registerCustomValidations()

	return cv
}

func (cv *CustomValidator) registerCustomValidations() {
	cv.validate.RegisterValidation("strong_password", validateStrongPassword)

	cv.validate.RegisterValidation("username", validateUsername)

	cv.validate.RegisterValidation("no_spaces", validateNoSpaces)

	cv.validate.RegisterValidation("task_priority", validateTaskPriority)

	cv.validate.RegisterValidation("task_status", validateTaskStatus)

	cv.validate.RegisterValidation("strict_url", validateStrictURL)

	cv.validate.RegisterValidation("phone", validatePhone)

	cv.validate.RegisterValidation("strict_uuid", validateStrictUUID)

	cv.validate.RegisterValidation("date_format", validateDateFormat)

	cv.validate.RegisterValidation("time_format", validateTimeFormat)

	cv.validate.RegisterValidation("password_confirm", validatePasswordConfirm)

	cv.validate.RegisterValidation("file_ext", validateFileExtension)

	cv.validate.RegisterValidation("image_file", validateImageFile)

	cv.validate.RegisterValidation("json_string", validateJSONString)

	cv.validate.RegisterValidation("base64_image", validateBase64Image)
}

func (cv *CustomValidator) ValidateStruct(s interface{}) ValidationErrors {
	var validationErrors ValidationErrors

	err := cv.validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			validationError := ValidationError{
				Field:   strings.ToLower(err.Field()),
				Tag:     err.Tag(),
				Value:   fmt.Sprintf("%v", err.Value()),
				Message: cv.getErrorMessage(err),
			}
			validationErrors = append(validationErrors, validationError)
		}
	}

	return validationErrors
}

// GetErrorMessage generates
func (cv *CustomValidator) getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return customErrorMessages["required"]
	case "email":
		return customErrorMessages["email"]
	case "min":
		return fmt.Sprintf(customErrorMessages["min"], err.Param())
	case "max":
		return fmt.Sprintf(customErrorMessages["max"], err.Param())
	case "strong_password":
		return customErrorMessages["strong_password"]
	case "username":
		return customErrorMessages["username"]
	case "strict_url":
		return customErrorMessages["url"]
	case "phone":
		return customErrorMessages["phone"]
	case "no_spaces":
		return customErrorMessages["no_spaces"]
	case "task_priority":
		return customErrorMessages["task_priority"]
	case "task_status":
		return customErrorMessages["task_status"]
	case "strict_uuid":
		return customErrorMessages["uuid"]
	default:
		return fmt.Sprintf("Invalid value for field %s", err.Field())
	}
}

func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	return matched
}

func validateNoSpaces(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return !strings.Contains(value, " ")
}
func validateTaskPriority(fl validator.FieldLevel) bool {
	priority := strings.ToLower(fl.Field().String())
	validPriorities := []string{"low", "medium", "high", "urgent"}

	for _, valid := range validPriorities {
		if priority == valid {
			return true
		}
	}
	return false
}

func validateTaskStatus(fl validator.FieldLevel) bool {
	status := strings.ToLower(fl.Field().String())
	validStatuses := []string{"pending", "in_progress", "completed", "cancelled"}

	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

func validateStrictURL(fl validator.FieldLevel) bool {
	urlStr := fl.Field().String()

	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}

	return true
}

func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()

	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "+", "")
	matched, _ := regexp.MatchString(`^\d{10,15}$`, cleanPhone)
	return matched
}

func validateStrictUUID(fl validator.FieldLevel) bool {
	uuid := fl.Field().String()
	matched, _ := regexp.MatchString(
		`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
		uuid,
	)
	return matched
}

func validateDateFormat(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	_, err := time.Parse("2006-01-02", dateStr)
	return err == nil
}

func validateTimeFormat(fl validator.FieldLevel) bool {
	timeStr := fl.Field().String()
	_, err := time.Parse("15:04", timeStr)
	return err == nil
}

func validatePasswordConfirm(fl validator.FieldLevel) bool {
	password := fl.Parent().FieldByName("Password").String()
	confirmPassword := fl.Field().String()
	return password == confirmPassword
}

func validateFileExtension(fl validator.FieldLevel) bool {
	filename := fl.Field().String()
	allowedExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt"}

	for _, ext := range allowedExtensions {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}
	return false
}

func validateImageFile(fl validator.FieldLevel) bool {
	filename := fl.Field().String()
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}

	for _, ext := range imageExtensions {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}
	return false
}

func validateJSONString(fl validator.FieldLevel) bool {
	jsonStr := fl.Field().String()
	return isValidJSON(jsonStr)
}

func validateBase64Image(fl validator.FieldLevel) bool {
	base64Str := fl.Field().String()

	if !strings.HasPrefix(base64Str, "data:image/") {
		return false
	}

	commaIndex := strings.Index(base64Str, ",")
	if commaIndex == -1 {
		return false
	}

	base64Data := base64Str[commaIndex+1:]

	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]*={0,2}$`, base64Data)
	return matched && len(base64Data)%4 == 0
}

func isValidJSON(str string) bool {
	var js interface{}
	return json.Unmarshal([]byte(str), &js) == nil
}
func ValidateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func ValidatePasswordStrength(password string) int {
	score := 0

	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasNumber {
		score++
	}
	if hasSpecial {
		score++
	}

	// Cap at 5
	if score > 5 {
		score = 5
	}

	return score
}

func SanitizeInput(input string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	cleaned := re.ReplaceAllString(input, "")

	sqlPatterns := []string{
		`(?i)(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute)(\s|$)`,
		`(?i)(\s|^)(or|and)(\s|$)`,
		`'`,
		`"`,
		`;`,
		`--`,
		`/*`,
		`*/`,
		`xp_`,
		`sp_`,
	}

	for _, pattern := range sqlPatterns {
		re := regexp.MustCompile(pattern)
		cleaned = re.ReplaceAllString(cleaned, " ")
	}

	cleaned = strings.TrimSpace(cleaned)

	return cleaned
}

func (cv *CustomValidator) ValidateAndSanitize(s interface{}) (interface{}, ValidationErrors) {
	cv.sanitizeStruct(s)
	errors := cv.ValidateStruct(s)

	return s, errors
}

func (cv *CustomValidator) sanitizeStruct(s interface{}) {
	// This would require reflection to iterate through struct fields
	// and sanitize string fields - implement based on your specific needs
}

func FormatValidationError(errors ValidationErrors) map[string]interface{} {
	return map[string]interface{}{
		"error":   "Validation failed",
		"message": "Please check your input data",
		"details": errors,
		"code":    "VALIDATION_ERROR",
	}
}

func IsValidTaskPriority(priority string) bool {
	validPriorities := []string{"low", "medium", "high", "urgent"}
	priority = strings.ToLower(priority)

	for _, valid := range validPriorities {
		if priority == valid {
			return true
		}
	}
	return false
}

func IsValidTaskStatus(status string) bool {
	validStatuses := []string{"pending", "in_progress", "completed", "cancelled"}
	status = strings.ToLower(status)

	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}
func NormalizePhoneNumber(phone string) string {
	re := regexp.MustCompile(`\D`)
	normalized := re.ReplaceAllString(phone, "")

	if len(normalized) == 10 {
		normalized = "1" + normalized
	}

	return normalized
}
