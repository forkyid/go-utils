package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/forkyid/go-utils/v1/aes"
	"github.com/forkyid/go-utils/v1/cache"
	"github.com/forkyid/go-utils/v1/jwt"
	"github.com/forkyid/go-utils/v1/rest"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/olivere/elastic/v7"
	"github.com/pkg/errors"
)

var (
	ErrDuplicateAcc          = errors.New("Duplicate Account")
	ErrBanned                = errors.New("Banned")
	ErrUnderage              = errors.New("Underage")
	ErrSuspended             = errors.New("Suspended")
	ErrAttemptLoginSuspended = errors.New("Attempt Login Suspended")
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
	DeviceID     string     `json:"device_id,omitempty"`
	IsOnHold     bool       `json:"is_on_hold,omitempty"`
	SuspendEnd   *time.Time `json:"suspend_end,omitempty"`
	IsMaxAttempt bool       `json:"is_max_attempt,omitempty"`
}

func GetStatus(ctx *gin.Context, es *elastic.Client, memberID int) (status MemberStatus, err error) {
	isAlive := cache.IsCacheConnected()
	if !isAlive {
		log.Println("[WARN] redis: connection failed")
	}

	statusKey := cache.ExternalKey("global", MemberStatusKey{
		ID: aes.Encrypt(memberID),
	})

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
			log.Println("[WARN] redis: get unmarshal:", err.Error())
		}
	}

	status.IsOnHold, err = getAccStatus(ctx)
	if err != nil {
		err = errors.Wrap(err, "get account status")
		return
	}

	status.banStatus, err = getBanStatus(ctx)
	if err != nil {
		err = errors.Wrap(err, "get ban status")
		return
	}

	if isAlive {
		err = cache.SetJSON(statusKey, status, 600)
		if err != nil {
			log.Println("[WARN] redis: set:", err.Error())
		}
	}

	return
}

func (mid *Middleware) Auth(ctx *gin.Context) {
	auth := ctx.GetHeader("Authorization")
	if auth == "" {
		rest.ResponseMessage(ctx, http.StatusUnauthorized)
		ctx.Abort()
		return
	}

	id, err := jwt.ExtractID(auth)
	if err != nil {
		log.Println("[ERROR] extract id:", err.Error())
		rest.ResponseError(ctx, http.StatusUnauthorized, map[string]string{
			"access_token": "expired"})
		ctx.Abort()
		return
	}

	status, err := GetStatus(ctx, mid.elastic, id)
	if err != nil {
		log.Println("[ERROR] get status:", err.Error())
		rest.ResponseMessage(ctx, http.StatusInternalServerError)
		ctx.Abort()
		return
	}

	if status.IsOnHold {
		rest.ResponseMessage(ctx, http.StatusForbidden, ErrDuplicateAcc.Error())
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

	ctx.Next()
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
		URL:    fmt.Sprintf("%v/gs/v1/accounts", os.Getenv("API_ORIGIN_URL")),
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

// CheckWaitingStatus params
//	@ctx: *gin.Context
func (m *Middleware) CheckWaitingStatus(ctx *gin.Context) {
	if err := m.elastic.WaitForYellowStatus("1s"); err != nil {
		log.Println("[ERROR] wait for yellow status:", err.Error())
		return
	}

	result, err := m.elastic.Get().
		Index("waiting-list").
		Id("status").
		Do(ctx)
	if err != nil {
		log.Println("[ERROR] get waiting list status:", err.Error())
		return
	}

	resultStruct := map[string]bool{}

	if !result.Found {
		log.Println("[ERROR] waiting list status not found:", err.Error())
		return
	}

	json.Unmarshal(result.Source, &resultStruct)
	isWait := resultStruct["status"]

	if isWait {
		rest.ResponseMessage(ctx, http.StatusServiceUnavailable)
		ctx.Abort()
	}
}
