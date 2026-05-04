package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/forkyid/go-utils/v1/aes"
	"github.com/forkyid/go-utils/v1/jwt"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/forkyid/go-utils/v1/rest"
	"github.com/forkyid/go-utils/v1/util/auth"
	"github.com/forkyid/go-utils/v1/util/sd"
	"github.com/gin-gonic/gin"
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

func checkAuthToken(ctx *gin.Context, bearerToken string) (resp rest.Response, err error) {
	bearerToken = strings.Replace(bearerToken, "Bearer ", "", -1)

	payload := map[string]string{"access_token": bearerToken}
	payloadJson, _ := json.Marshal(payload)

	apiUsername := os.Getenv("CHECK_AUTH_TOKEN_BASIC_AUTH_USERNAME")
	apiPassword := os.Getenv("CHECK_AUTH_TOKEN_BASIC_AUTH_PASSWORD")

	reqCount := uint64(0)
	host := sd.Instance.GetService(os.Getenv("CHECK_AUTH_TOKEN_SERVICE_NAME")).GetHost(&reqCount, os.Getenv("CHECK_AUTH_TOKEN_FALLBACK_BASE_URL")) + "/" + os.Getenv("CHECK_AUTH_TOKEN_PATH")
	req := rest.Request{
		URL:    host,
		Method: http.MethodPost,
		Headers: map[string]string{
			"Authorization": auth.GenerateBasicAuth(apiUsername, apiPassword),
			"X-Api-Caller":  os.Getenv("SERVICE_NAME") + ctx.Request.URL.Path,
		},
		Body: bytes.NewReader(payloadJson),
	}

	respJson, statusCode := req.Send()
	err = errors.Wrap(json.Unmarshal(respJson, &resp), "unmarshal ")
	resp.Status = statusCode

	return
}

func (mid *Middleware) validate(ctx *gin.Context, auth string) {
	_, err := jwt.ExtractID(auth)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusUnauthorized).
			Log("extract id", err)
		ctx.Abort()
		return
	}

	resp, err := checkAuthToken(ctx, auth)
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
}

func (mid *Middleware) GuestAuth(ctx *gin.Context) {
	auth := ctx.GetHeader("Authorization")
	if auth == "" {
		ctx.Next()
		return
	}

	mid.validate(ctx, auth)
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

	mid.validate(ctx, auth)
	ctx.Next()
}

// AgeAuth validates whether user already above the age requirement or not.
func (mid *Middleware) AgeAuth(allowedAgeGroupIDs ...int) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		auth := ctx.GetHeader("Authorization")
		if auth == "" {
			logger.Debugf(ctx, "get header", ErrNoAuthorizationHeader)
			rest.ResponseMessage(ctx, http.StatusUnauthorized)
			ctx.Abort()
			return
		}

		mid.validate(ctx, auth)
		if ctx.IsAborted() {
			return
		}

		encAgeGroupID, err := getAgeGroup(ctx)
		if err != nil {
			rest.ResponseMessage(ctx, http.StatusInternalServerError).
				Log("get age group", err)
			ctx.Abort()
			return
		}

		ageGroupID := aes.Decrypt(encAgeGroupID)
		for _, allowed := range allowedAgeGroupIDs {
			if ageGroupID == int64(allowed) {
				ctx.Next()
				return
			}
		}

		rest.ResponseMessage(ctx, http.StatusForbidden, ErrBelowAgeRequirement.Error())
		ctx.Abort()
	}
}

func getAccStatus(ctx *gin.Context) (isOnHold bool, err error) {
	reqCount := uint64(0)
	host := sd.Instance.GetService(os.Getenv("GET_ACCOUNT_STATUS_SERVICE_NAME")).GetHost(&reqCount, os.Getenv("GET_ACCOUNT_STATUS_FALLBACK_BASE_URL")) + "/" + os.Getenv("GET_ACCOUNT_STATUS_PATH")
	req := rest.Request{
		URL:    host,
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

func getAgeGroup(ctx *gin.Context) (encAgeGroupID string, err error) {
	reqCount := uint64(0)
	host := sd.Instance.GetService(os.Getenv("GET_AGE_GROUP_SERVICE_NAME")).GetHost(&reqCount, os.Getenv("GET_AGE_GROUP_FALLBACK_BASE_URL")) + "/" + os.Getenv("GET_AGE_GROUP_PATH")
	req := rest.Request{
		URL:    host,
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

	encAgeGroupID, ok := resp["age_group_id"].(string)
	if !ok {
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
