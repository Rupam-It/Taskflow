// internal/repository/interfaces.go
package repository

import (
	"taskflow/user-service/internal/models"
)

type UserRepository interface {
	Create(user *models.User) error
	GetByID(id uint) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetByEmailOrUsername(identifier string) (*models.User, error)
	Update(user *models.User) error
	Delete(id uint) error
	UpdateLastLogin(userID uint) error
}

type PasswordResetRepository interface {
	Create(reset *models.PasswordReset) error
	GetByToken(token string) (*models.PasswordReset, error)
	Update(reset *models.PasswordReset) error
	DeleteExpired() error
}

type RefreshTokenRepository interface {
	Create(token *models.RefreshToken) error
	GetByToken(token string) (*models.RefreshToken, error)
	Update(token *models.RefreshToken) error
	RevokeAllByUserID(userID uint) error
	DeleteExpired() error
}
