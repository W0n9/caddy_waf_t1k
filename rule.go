package caddy_waf_t1k

import (
	"encoding/json"
	"net/http"

	"github.com/chaitin/t1k-go/detection"
	"go.uber.org/zap"
)

// redirectIntercept Intercept request
func (m *CaddyWAF) redirectIntercept(w http.ResponseWriter, result *detection.Result) error {
	// var tpl *template.Template
	w.Header().Set("X-Event-ID", result.EventID())
	w.WriteHeader(http.StatusNotImplemented)
	BlockMessage := map[string]interface{}{
		"message":  "Intercept illegal requests",
		"event_id": result.EventID(),
	}
	blockMessage, err := json.Marshal(BlockMessage)
	if err != nil {
		m.logger.Error("failed to marshal block message", zap.Error(err))
	}
	_, err = w.Write(blockMessage)
	if err != nil {
		m.logger.Error("failed to write block message", zap.Error(err))
	}
	return nil
	// tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	// return tpl.Execute(w, result.EventID())
}
