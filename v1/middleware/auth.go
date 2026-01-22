package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/forkyid/go-utils/v1/aes"
	"github.com/forkyid/go-utils/v1/jwt"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/forkyid/go-utils/v1/rest"
	"github.com/forkyid/go-utils/v1/util/age"
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

type BanStatus struct {
	IsBanned  bool   `json:"is_banned"`
	EncTypeID string `json:"type_id,omitempty"`
	TypeName  string `json:"type_name,omitempty"`
}

func getBanStatus(ctx *gin.Context, encMemberID string) (status BanStatus, err error) {
	reqBody := map[string]string{
		"member_id": encMemberID,
	}
	reqBodyJson, _ := json.Marshal(reqBody)

	reqCount := uint64(0)
	host := sd.Instance.GetService("api-report").GetHost(&reqCount, os.Getenv("API_ORIGIN_URL")+"/report") + "/v1/resource/bans/status"
	req := rest.Request{
		URL:    host,
		Method: http.MethodPost,
		Headers: map[string]string{
			"Authorization": auth.GenerateBasicAuth(os.Getenv("BASIC_AUTH_API_REPORT_USERNAME"), os.Getenv("BASIC_AUTH_API_REPORT_PASSWORD")),
			"X-Api-Caller":  os.Getenv("SERVICE_NAME") + ctx.Request.URL.Path,
		},
		Body: strings.NewReader(string(reqBodyJson)),
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

type SuspendStatus struct {
	ExpiresIn string    `json:"expires_in"`
	ExpiredAt time.Time `json:"expired_at"`
}

func getSuspendStatus(ctx *gin.Context, encMemberID string) (resp SuspendStatus, err error) {
	reqBody := map[string]interface{}{
		"member_id": encMemberID,
	}
	reqBodyJson, _ := json.Marshal(reqBody)

	reqCount := uint64(0)
	host := sd.Instance.GetService("api-report").GetHost(&reqCount, os.Getenv("API_ORIGIN_URL")+"/report") + "/v1/resource/suspensions"
	req := rest.Request{
		URL:    host,
		Method: http.MethodPost,
		Body:   bytes.NewReader(reqBodyJson),
		Headers: map[string]string{
			"Authorization": auth.GenerateBasicAuth(os.Getenv("BASIC_AUTH_API_REPORT_USERNAME"), os.Getenv("BASIC_AUTH_API_REPORT_PASSWORD")),
			"X-Api-Caller":  os.Getenv("SERVICE_NAME") + ctx.Request.URL.Path,
		},
	}

	respJson, code := req.Send()
	if code != http.StatusOK {
		err = fmt.Errorf("[%v] %v: %v\n%v", req.Method, req.URL, code, string(respJson))
		return
	}

	rawData, err := rest.GetData(respJson)
	if err != nil {
		err = errors.Wrap(err, "go-utils: rest: GetData")
		return
	}

	err = errors.Wrap(json.Unmarshal(rawData, &resp), "json: Unmarshal")

	return
}

type MemberStatus struct {
	DeviceID      string        `json:"device_id,omitempty"`
	BanStatus     BanStatus     `json:"ban_status"`
	SuspendStatus SuspendStatus `json:"suspend_status"`
}

func GetStatus(ctx *gin.Context, encMemberID string) (status MemberStatus, err error) {
	status.BanStatus, err = getBanStatus(ctx, encMemberID)
	if err != nil {
		err = errors.Wrap(err, "get ban status")
		return
	}

	status.SuspendStatus, err = getSuspendStatus(ctx, encMemberID)
	if err != nil {
		err = errors.Wrap(err, "get suspend status")
		return
	}

	return
}

func checkAuthToken(ctx *gin.Context, bearerToken string) (resp rest.Response, err error) {
	bearerToken = strings.Replace(bearerToken, "Bearer ", "", -1)

	payload := map[string]string{"access_token": bearerToken}
	payloadJson, _ := json.Marshal(payload)

	apiUsername := os.Getenv("BASIC_AUTH_OAUTH2_SERVER_USERNAME")
	apiPassword := os.Getenv("BASIC_AUTH_OAUTH2_SERVER_PASSWORD")

	reqCount := uint64(0)
	host := sd.Instance.GetService("oauth2-server").GetHost(&reqCount, os.Getenv("API_ORIGIN_URL")+"/oauth") + "/v1/resource/check/token"
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
	id, err := jwt.ExtractID(auth)
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

	encMemberID := aes.Encrypt(id)
	status, err := GetStatus(ctx, encMemberID)
	if err != nil {
		rest.ResponseMessage(ctx, http.StatusInternalServerError).Log("get status", err)
		ctx.Abort()
		return
	}

	if status.BanStatus.IsBanned {
		if status.BanStatus.TypeName == "underage" {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrUnderage.Error())
		} else {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrBanned.Error())
		}
		ctx.Abort()
		return
	}

	if !status.SuspendStatus.ExpiredAt.IsZero() && status.SuspendStatus.ExpiredAt.After(time.Now()) {
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
func (mid *Middleware) AgeAuth(minAge int) gin.HandlerFunc {
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

		claims, _ := jwt.ExtractClient(auth)
		if age.Age(claims.DateOfBirth) < minAge {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrBelowAgeRequirement.Error())
			ctx.Abort()
			return
		}
	}
}

func getAccStatus(ctx *gin.Context) (isOnHold bool, err error) {
	reqCount := uint64(0)
	host := sd.Instance.GetService("api-gift-shop").GetHost(&reqCount, os.Getenv("API_ORIGIN_URL")+"/gs") + "/v1/accounts/status"
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
