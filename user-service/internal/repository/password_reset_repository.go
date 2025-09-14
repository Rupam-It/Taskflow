package repository

import (
	"taskflow/user-service/internal/models"
	"time"

	"gorm.io/gorm"
)

type passwordResetRepository struct {
	db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) PasswordResetRepository {
	return &passwordResetRepository{db: db}
}

func (r *passwordResetRepository) Create(reset *models.PasswordReset) error {
	return r.db.Create(reset).Error
}

func (r *passwordResetRepository) GetByToken(token string) (*models.PasswordReset, error) {
	var reset models.PasswordReset
	err := r.db.Where("token = ? AND used = ? AND expires_at > ?",
		token, false, time.Now()).First(&reset).Error
	if err != nil {
		return nil, err
	}
	return &reset, nil
}

func (r *passwordResetRepository) Update(reset *models.PasswordReset) error {
	return r.db.Save(reset).Error
}

func (r *passwordResetRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ? OR used = ?", time.Now(), true).
		Delete(&models.PasswordReset{}).Error
}
