package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"taskflow/user-service/internal/config"
	"taskflow/user-service/internal/handlers"
	"taskflow/user-service/internal/middleware"
	"taskflow/user-service/internal/models"
	"taskflow/user-service/internal/repository"
	"taskflow/user-service/internal/services"
	"taskflow/user-service/internal/utils"
)

func main() {
	cfg := config.Load()

	db, err := connectDB(cfg)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.PasswordReset{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	jwtManager := utils.NewJWTManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)

	userRepo := repository.NewUserRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(db)

	authService := services.NewAuthService(
		userRepo,
		passwordResetRepo,
		refreshTokenRepo,
		jwtManager,
	)

	authHandler := handlers.NewAuthHandler(authService)

	router := setupRouter(authHandler, jwtManager)

	log.Printf("Server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
	if err := router.Run(fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func connectDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

func setupRouter(authHandler *handlers.AuthHandler, jwtManager *utils.JWTManager) *gin.Engine {
	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"service":   "user-service",
			"timestamp": time.Now(),
		})
	})

	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)

			protected := auth.Group("/")
			protected.Use(middleware.JWTAuthMiddleware(jwtManager))
			{
				protected.GET("/profile", authHandler.GetProfile)
				protected.PUT("/profile", authHandler.UpdateProfile)
			}
		}
	}

	return router
}
