package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/forkyid/go-utils/v1/rest"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	DisabledStatus    = "disabled"
	MaintenanceStatus = "maintenance"
	ErrDisabled       = errors.New("Feature Is Disabled")
	ErrMaintenance    = errors.New("Feature Is Under Maintenance")
)

type FeatureFlagStatus struct {
	Status string `json:"status"`
}

// CheckFeatureFlagStatus checks feature flag status by key and abort if status is not enabled.
func (mid *Middleware) CheckFeatureFlagStatus(key string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		status, err := getFeatureFlagStatus(key)
		if err != nil {
			rest.ResponseMessage(ctx, http.StatusInternalServerError).Log("get feature flag status", err)
			ctx.Abort()
			return
		}
		if status.Status == DisabledStatus {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrDisabled.Error())
			ctx.Abort()
			return
		}

		if status.Status == MaintenanceStatus {
			rest.ResponseMessage(ctx, http.StatusForbidden, ErrMaintenance.Error())
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// getFeatureFlagStatus gets feature flag status by its key.
func getFeatureFlagStatus(key string) (status FeatureFlagStatus, err error) {
	req := rest.Request{
		URL:    fmt.Sprintf("%v/flag/v1/check?key=%v", os.Getenv("API_ORIGIN_URL"), key),
		Method: http.MethodGet,
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
	err = errors.Wrap(err, "unmarshal data")
	return
}
