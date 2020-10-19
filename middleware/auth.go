package middleware

import (
	"fmt"
	"net/http"
	"os"

	"github.com/forkyid/go-utils/aes"
	"github.com/forkyid/go-utils/cache"
	"github.com/forkyid/go-utils/jwt"
	"github.com/forkyid/go-utils/logger"
	"github.com/forkyid/go-utils/rest"
	"github.com/forkyid/go-utils/uuid"
	"github.com/gin-gonic/gin"
)

// Auth func
// return gin.HandlerFunc
func Auth() gin.HandlerFunc {
	return func(context *gin.Context) {
		id, err := jwt.ExtractID(context.GetHeader("Authorization"))
		if err != nil {
			rest.ResponseMessage(context, http.StatusUnauthorized)
			context.Abort()
			return
		}

		banned, err := isBanned(id, context.GetHeader("Authorization"))
		if err != nil {
			logger.LogError(context, "", err.Error())
		}
		if banned {
			rest.ResponseMessage(context, http.StatusForbidden, "Banned")
			context.Abort()
			return
		}

		exists, err := cache.IsCacheExists(
			fmt.Sprintf(
				`%v:%v:%v`,
				aes.Encrypt(id),
				"whitelist",
				context.GetHeader("X-Unique-ID"),
			),
		)
		if err != nil {
			logger.LogError(context, uuid.GetUUID(), "failed on checking if redis key exists: "+err.Error())
			context.Next()
			return
		}
		if !exists {
			rest.ResponseMessage(context, http.StatusUnauthorized)
			context.Abort()
			return
		}

		context.Next()
	}
}

func isBanned(memberID int, bearer string) (bool, error) {
	redisKey := fmt.Sprintf(`%v:%v`, memberID, "banned")

	banned, err := cache.IsCacheExists(redisKey)
	if err != nil {
		return false, err
	}
	if banned {
		return true, nil
	}

	_, code := rest.Request{
		Method: http.MethodGet,
		URL: fmt.Sprintf(
			"%v/reports/v1/blocks?blocked_id=%v&block_type_id=%v&blocker_id=0",
			os.Getenv("API_ORIGIN_URL"),
			aes.Encrypt(memberID),
			aes.Encrypt(1)),
		Headers: map[string]string{
			"Authorization": bearer,
		},
	}.Send()
	if code != http.StatusOK {
		return false, fmt.Errorf("auth: get blocked: status not 200")
	}

	err = cache.SetJSON(redisKey, "", 600)
	if err != nil {
		return false, err
	}

	return true, nil
}
