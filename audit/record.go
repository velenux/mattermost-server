// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package audit

// Meta represents metadata that can be added to a audit record as name/value pairs.
type Meta map[string]interface{}

// FuncMetaTypeConv defines a function that can convert meta data types into something
// that serializes well for audit records.
type FuncMetaTypeConv func(val interface{}) (newVal interface{}, converted bool)

// EventData -- The new audit log schema proposes that all audit log events include
// the EventData struct.
type EventData struct {
	Parameters       interface{} `json:"parameters"`         // Any parameters if relevant (and outside the actual payload)
	NewData          interface{} `json:"new_data"`           // the actual payload being processed. In most cases the JSON payload deserialized into interface{}
	PriorState       Auditable   `json:"prior_state"`        // Prior state of the object being modified, nil if no prior state
	ResultingState   Auditable   `json:"resulting_state"`    // Resulting object after creating or modifying it
	ResultObjectType string      `json:"result_object_type"` // string representation of the object type. eg. "post"
}

// Auditable for sensitive object classes, consider implementing Auditable and include whatever the
// AuditableObject returns. For example: it's likely OK to write a user object to the
// audit logs, but not the user password in cleartext or hashed form
type Auditable interface {
	AuditableObject() interface{}
}

// Record provides a consistent set of fields used for all audit logging.
type Record struct {
	APIPath   string    `json:"api_path"`
	EventName string    `json:"event_name"`
	EventData EventData `json:"event_data"`
	Error     string    `json:"error"`
	Status    string    `json:"status"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Client    string    `json:"client"`
	IPAddress string    `json:"ip_address"`
	Meta      Meta      `json:"meta"`
	metaConv  []FuncMetaTypeConv
}

// Success marks the audit record status as successful.
func (rec *Record) Success() {
	rec.Status = Success
}

// Fail marks the audit record status as failed.
func (rec *Record) Fail() {
	rec.Status = Fail
}

// AddMeta adds a single name/value pair to this audit record's metadata.
func (rec *Record) AddMeta(name string, val interface{}) {
	if rec.Meta == nil {
		rec.Meta = Meta{}
	}

	// possibly convert val to something better suited for serializing
	// via zero or more conversion functions.
	var converted bool
	for _, conv := range rec.metaConv {
		val, converted = conv(val)
		if converted {
			break
		}
	}

	rec.Meta[name] = val
}

// AddMetadata Populates the `event_data` structure for the audit log entry. See above
// for description of the parameters
// TODO: Consider additionally implementing individual setters for the different keys in EventData.
// For example, it might make sense to include the `new_data` value for audit log entries for
// failed API calls.
func (rec *Record) AddMetadata(newObject interface{},
	priorObject Auditable,
	resultObject Auditable,
	resultObjectType string) {
	eventData := EventData{
		NewData:          newObject,
		PriorState:       priorObject,
		ResultingState:   resultObject,
		ResultObjectType: resultObjectType,
	}
	rec.EventData = eventData
}

// AddMetaTypeConverter adds a function capable of converting meta field types
// into something more suitable for serialization.
func (rec *Record) AddMetaTypeConverter(f FuncMetaTypeConv) {
	rec.metaConv = append(rec.metaConv, f)
}
