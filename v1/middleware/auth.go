package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/forkyid/go-utils/v1/aes"
	"github.com/forkyid/go-utils/v1/cache"
	"github.com/forkyid/go-utils/v1/jwt"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/forkyid/go-utils/v1/rest"
	"github.com/forkyid/go-utils/v1/util/age"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

var (
	ErrDuplicateAcc          = errors.New("Duplicate Account")
	ErrBanned                = errors.New("Banned")
	ErrUnderage              = errors.New("Underage")
	ErrSuspended             = errors.New("Suspended")
	ErrNoAuthorizationHeader = errors.New("no Authorization header")
	ErrConnectionFailed      = errors.New("connection failed")
	ErrBelowAgeRequirement   = errors.New("below age requirement")
)

type MemberStatusKey struct {
	ID string `cache:"key"`
}

type banStatus struct {
	IsBanned bool   `json:"is_banned"`
	TypeName string `json:"type_name,omitempty"`
}

type MemberStatus struct {
	banStatus
	DeviceID   string     `json:"device_id,omitempty"`
	SuspendEnd *time.Time `json:"suspend_end,omitempty"`
}

func GetStatus(ctx *gin.Context, memberID int) (status MemberStatus, err error) {
	isAlive := cache.IsCacheConnected()
	if !isAlive {
		logger.Warnf("redis", ErrConnectionFailed)
	}

	statusKey := cache.ExternalKey("global", MemberStatusKey{
		ID: aes.Encrypt(memberID),
	})

	// TODO: update suspension checking
	if isAlive {
		err = cache.GetUnmarshal(statusKey, &status)
		if err == nil {
			if status.SuspendEnd != nil && status.SuspendEnd.After(time.Now().Add(10*time.Minute)) {
				suspendEnd := time.Until(*status.SuspendEnd)
				cache.SetExpire(statusKey, int(suspendEnd.Seconds()))
			} else {
				cache.SetExpire(statusKey, 600)
			}
			return
		}
		if err != redis.Nil {
			logger.Warnf("redis: get unmarshal", err)
		}
	}

	status.banStatus, err = getBanStatus(ctx)
	if err != nil {
		err = errors.Wrap(err, "get ban status")
		return
	}

	if isAlive {
		err = cache.SetJSON(statusKey, status, 600)
		if err != nil {
			logger.Warnf("redis: set", err)
		}
	}

	return
}

func tokenBasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func checkAuthToken(bearerToken string) (resp rest.Response, err error) {
	bearerToken = strings.Replace(bearerToken, "Bearer ", "", -1)

	oauthUsername := os.Getenv("OAUTH2_SERVER_BASIC_AUTH_USERNAME") // TODO: update env naming to `BASIC_AUTH_OAUTH2_SERVER_USERNAME`
	oauthPassword := os.Getenv("OAUTH2_SERVER_BASIC_AUTH_PASSWORD") // TODO: update env naming to `BASIC_AUTH_OAUTH2_SERVER_PASSWORD`
	basicAuth := tokenBasicAuth(oauthUsername, oauthPassword)

	payload := map[string]string{"access_token": bearerToken}
	payloadJson, _ := json.Marshal(payload)

	req := rest.Request{
		URL:    fmt.Sprintf("%v/oauth/v1/resource/check/token", os.Getenv("API_ORIGIN_URL")), // TODO: update path using internal LB
		Method: http.MethodPost,
		Headers: map[string]string{
			"Authorization": "Basic " + basicAuth},
		Body: bytes.NewReader(payloadJson),
	}

	respJson, statusCode := req.Send()
	err = errors.Wrap(json.Unmarshal(respJson, &resp), "unmarshal ")
	resp.Status = statusCode

	return
}

func (mid *Middleware) validate(auth string, ctx *gin.Context) {
	id, err := jwt.ExtractID(auth)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusUnauthorized).
			Log("extract id", err)
		ctx.Abort()
		return
	}

	resp, err := checkAuthToken(auth)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusInternalServerError).Log("check auth token", err)
		ctx.Abort()
		return
	}

	if resp.Status != http.StatusOK {
		rest.ResponseError(ctx, http.StatusUnauthorized, resp.Detail)
		ctx.Abort()
		return
	}

	status, err := GetStatus(ctx, id)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusInternalServerError).Log("get status", err)
		ctx.Abort()
		return
	}

	if status.IsBanned {
		if status.TypeName == "underage" {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrUnderage.Error())
		} else {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrBanned.Error())
		}
		ctx.Abort()
		return
	}

	if status.SuspendEnd != nil && status.SuspendEnd.After(time.Now()) {
		rest.ResponseMessage(ctx, http.StatusLocked, ErrSuspended.Error())
		ctx.Abort()
		return
	}

	deviceID := ctx.GetHeader("X-Unique-ID")
	if status.DeviceID != deviceID {
		rest.ResponseMessage(ctx, http.StatusUnauthorized)
		ctx.Abort()
		return
	}
}

func (mid *Middleware) GuestAuth(ctx *gin.Context) {
	auth := ctx.GetHeader("Authorization")
	if auth == "" {
		ctx.Next()
		return
	}

	mid.validate(auth, ctx)
	ctx.Next()
}

func (mid *Middleware) Auth(ctx *gin.Context) {
	auth := ctx.GetHeader("Authorization")
	if auth == "" {
		logger.Debugf(ctx, "get header", ErrNoAuthorizationHeader)
		rest.ResponseMessage(ctx, http.StatusUnauthorized)
		ctx.Abort()
		return
	}

	mid.validate(auth, ctx)
	ctx.Next()
}

// AgeAuth validates whether user already above the age requirement or not.
func (mid *Middleware) AgeAuth(minAge int) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		auth := ctx.GetHeader("Authorization")
		if auth == "" {
			logger.Debugf(ctx, "get header", ErrNoAuthorizationHeader)
			rest.ResponseMessage(ctx, http.StatusUnauthorized)
			ctx.Abort()
			return
		}

		mid.validate(auth, ctx)
		if ctx.IsAborted() {
			return
		}

		claims, _ := jwt.ExtractClient(auth)
		if age.Age(claims.DateOfBirth) < minAge {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrBelowAgeRequirement.Error())
			ctx.Abort()
			return
		}
	}
}

func getBanStatus(ctx *gin.Context) (status banStatus, err error) {
	req := rest.Request{
		URL:    fmt.Sprintf("%v/report/v1/bans", os.Getenv("API_ORIGIN_URL")),
		Method: http.MethodGet,
		Headers: map[string]string{
			"Authorization": ctx.GetHeader("Authorization")},
	}

	body, code := req.Send()
	if code != http.StatusOK {
		err = fmt.Errorf("[%v] %v: %v", req.Method, req.URL, string(body))
		return
	}

	data, err := rest.GetData(body)
	if err != nil {
		err = errors.Wrap(err, "get data")
		return
	}

	err = json.Unmarshal(data, &status)
	return
}

func getAccStatus(ctx *gin.Context) (isOnHold bool, err error) {
	req := rest.Request{
		URL:    fmt.Sprintf("%v/gs/v1/accounts/status", os.Getenv("API_ORIGIN_URL")),
		Method: http.MethodGet,
		Headers: map[string]string{
			"Authorization": ctx.GetHeader("Authorization")},
	}

	respJson, code := req.Send()
	if code != http.StatusOK {
		err = fmt.Errorf("[%v] %v: %v", req.Method, req.URL, string(respJson))
		return
	}

	data, err := rest.GetData(respJson)
	if err != nil {
		err = errors.Wrap(err, "get data")
		return
	}

	resp := map[string]interface{}{}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		err = errors.Wrap(err, "unmarshal")
		return
	}

	status, ok := resp["status"].(string)
	if ok && status == "onhold" {
		isOnHold = true
	} else if !ok {
		err = fmt.Errorf("status invalid")
	}

	return
}

func (m *Middleware) CheckWaitingStatus(ctx *gin.Context) {
	if err := m.elastic.WaitForYellowStatus("1s"); err != nil {
		logger.Errorf(ctx, "wait for yellow status", err)
		return
	}

	result, err := m.elastic.Get().
		Index("waiting-list").
		Id("status").
		Do(ctx)
	if err != nil {
		logger.Errorf(ctx, "get waiting list status", err)
		return
	}

	resultStruct := map[string]bool{}

	if !result.Found {
		logger.Errorf(ctx, "waiting list status not found", err)
		return
	}

	json.Unmarshal(result.Source, &resultStruct)
	isWait := resultStruct["status"]

	if isWait {
		rest.ResponseMessage(ctx, http.StatusServiceUnavailable)
		ctx.Abort()
	}
}

func (m Middleware) CheckSimilar(ctx *gin.Context) {
	isOnHold, err := getAccStatus(ctx)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusInternalServerError).
			Log("get account status", err)
		ctx.Abort()
		return
	}

	if isOnHold {
		rest.ResponseMessage(ctx, http.StatusForbidden, ErrDuplicateAcc.Error())
		ctx.Abort()
		return
	}
}
