package services

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"taskflow/user-service/internal/models"
	"taskflow/user-service/internal/repository"
	"taskflow/user-service/internal/utils"
	"time"

	"gorm.io/gorm"
)

type AuthService interface {
	Register(req *models.RegisterRequest) (*models.AuthResponse, error)
	Login(req *models.LoginRequest) (*models.AuthResponse, error)
	RefreshToken(refreshToken string) (*models.AuthResponse, error)
	GetProfile(userID uint) (*models.User, error)
	UpdateProfile(userID uint, req *models.UpdateProfileRequest) (*models.User, error)
	InitiatePasswordReset(email string) error
	ResetPassword(token, newPassword string) error
}

// UPDATED STRUCT:
type authService struct {
	userRepo          repository.UserRepository
	passwordResetRepo repository.PasswordResetRepository
	refreshTokenRepo  repository.RefreshTokenRepository
	jwtManager        *utils.JWTManager
}

// UPDATED CONSTRUCTOR:
func NewAuthService(
	userRepo repository.UserRepository,
	passwordResetRepo repository.PasswordResetRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	jwtManager *utils.JWTManager,
) AuthService {
	return &authService{
		userRepo:          userRepo,
		passwordResetRepo: passwordResetRepo,
		refreshTokenRepo:  refreshTokenRepo,
		jwtManager:        jwtManager,
	}
}

func (s *authService) Register(req *models.RegisterRequest) (*models.AuthResponse, error) {
	// Check if user already exists
	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return nil, errors.New("user with this email already exists")
	}

	if _, err := s.userRepo.GetByUsername(req.Username); err == nil {
		return nil, errors.New("user with this username already exists")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	// Create user
	user := &models.User{
		Email:    req.Email,
		Username: req.Username,
		Password: hashedPassword,
		FullName: req.FullName,
		IsActive: true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("failed to create user")
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, user.Email)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	return &models.AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
	}, nil
}

func (s *authService) Login(req *models.LoginRequest) (*models.AuthResponse, error) {
	// Find user by email or username
	user, err := s.userRepo.GetByEmailOrUsername(req.EmailOrUsername)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid credentials")
		}
		return nil, errors.New("failed to find user")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if !utils.CheckPassword(req.Password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	// Update last login
	s.userRepo.UpdateLastLogin(user.ID)

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, user.Email)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	return &models.AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
	}, nil
}

func (s *authService) GetProfile(userID uint) (*models.User, error) {
	return s.userRepo.GetByID(userID)
}

func (s *authService) UpdateProfile(userID uint, req *models.UpdateProfileRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	user.FullName = req.FullName
	user.Avatar = req.Avatar

	if err := s.userRepo.Update(user); err != nil {
		return nil, errors.New("failed to update profile")
	}

	return user, nil
}

// Implement RefreshToken, InitiatePasswordReset, ResetPassword methods...
// Add these missing methods to your authService struct

// InitiatePasswordReset generates a reset token and sends email
func (s *authService) InitiatePasswordReset(email string) error {
	// Find user by email
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Return success even if user doesn't exist (security best practice)
		// This prevents email enumeration attacks
		return nil
	}

	// Generate secure reset token
	resetToken, err := utils.GenerateSecureToken(32) // 32 bytes = 64 hex chars
	if err != nil {
		return errors.New("failed to generate reset token")
	}

	// Hash the token before storing (security best practice)
	hashedToken, err := utils.HashPassword(resetToken)
	if err != nil {
		return errors.New("failed to hash reset token")
	}

	// Store reset token in database with expiry (15 minutes)
	passwordReset := &models.PasswordReset{
		UserID:    user.ID,
		Token:     hashedToken,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
	}

	// Save to database (you'll need to add this method to repository)
	if err := s.passwordResetRepo.Create(passwordReset); err != nil {
		return errors.New("failed to save reset token")
	}

	// Send email with reset link
	resetURL := fmt.Sprintf("https://taskflow.com/reset-password?token=%s", resetToken)
	if err := s.sendPasswordResetEmail(user.Email, user.FullName, resetURL); err != nil {
		// Log error but don't return it (user shouldn't know if email failed)
		// In production, you might want to queue this for retry
		log.Printf("Failed to send password reset email to %s: %v", user.Email, err)
	}

	return nil
}

// ResetPassword validates token and updates user password
func (s *authService) ResetPassword(token, newPassword string) error {
	// Find reset token record
	resetRecord, err := s.passwordResetRepo.GetByToken(token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token is expired
	if time.Now().After(resetRecord.ExpiresAt) {
		return errors.New("reset token has expired")
	}

	// Check if token was already used
	if resetRecord.Used {
		return errors.New("reset token has already been used")
	}

	// Validate new password strength
	if !s.isValidPassword(newPassword) {
		return errors.New("password does not meet security requirements")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("failed to hash new password")
	}

	// Get user
	user, err := s.userRepo.GetByID(resetRecord.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	// Update user password
	user.Password = hashedPassword
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("failed to update password")
	}

	// Mark token as used
	resetRecord.Used = true
	if err := s.passwordResetRepo.Update(resetRecord); err != nil {
		// Log but don't fail - password was updated successfully
		log.Printf("Failed to mark reset token as used: %v", err)
	}

	// Optional: Invalidate all existing sessions for this user
	// You can implement this by revoking all refresh tokens
	if err := s.revokeAllUserSessions(user.ID); err != nil {
		log.Printf("Failed to revoke user sessions after password reset: %v", err)
	}

	return nil
}

// RefreshToken method (also missing from your implementation)
func (s *authService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get user ID from claims
	userID, err := strconv.ParseUint(claims.Subject, 10, 32)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	// Check if refresh token exists and is not revoked
	storedToken, err := s.refreshTokenRepo.GetByToken(refreshToken)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	if storedToken.IsRevoked {
		return nil, errors.New("refresh token has been revoked")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("refresh token has expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(uint(userID))
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, user.Email)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	// Optionally generate new refresh token (recommended for security)
	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	// Revoke old refresh token
	storedToken.IsRevoked = true
	s.refreshTokenRepo.Update(storedToken)

	// Store new refresh token
	newTokenRecord := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		IsRevoked: false,
	}
	s.refreshTokenRepo.Create(newTokenRecord)

	return &models.AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes
	}, nil
}

// Helper methods
func (s *authService) isValidPassword(password string) bool {
	// Use your validator to check password strength
	return len(password) >= 8 &&
		regexp.MustCompile(`[A-Z]`).MatchString(password) &&
		regexp.MustCompile(`[a-z]`).MatchString(password) &&
		regexp.MustCompile(`[0-9]`).MatchString(password) &&
		regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)
}

func (s *authService) sendPasswordResetEmail(email, fullName, resetURL string) error {
	subject := "TaskFlow - Password Reset Request"
	body := fmt.Sprintf(`
Hi %s,

You requested a password reset for your TaskFlow account.

Click the link below to reset your password:
%s

This link will expire in 15 minutes.

If you didn't request this reset, please ignore this email.

Best regards,
TaskFlow Team
`, fullName, resetURL)

	log.Printf("Sending email to: %s", email)
	log.Printf("Subject: %s", subject)
	log.Printf("Body: %s", body)

	return nil
}

func (s *authService) revokeAllUserSessions(userID uint) error {
	return s.refreshTokenRepo.RevokeAllByUserID(userID)
}
