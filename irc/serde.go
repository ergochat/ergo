// Copyright (c) 2022 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"strconv"

	"github.com/ergochat/ergo/irc/datastore"
	"github.com/ergochat/ergo/irc/logger"
)

type Serializable interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}

func FetchAndDeserializeAll[T any, C interface {
	*T
	Serializable
}](table datastore.Table, dstore datastore.Datastore, log *logger.Manager) (result []T, err error) {
	rawRecords, err := dstore.GetAll(table)
	if err != nil {
		return
	}
	result = make([]T, len(rawRecords))
	pos := 0
	for _, record := range rawRecords {
		err := C(&result[pos]).Deserialize(record.Value)
		if err != nil {
			log.Error("internal", "deserialization error", strconv.Itoa(int(table)), record.UUID.String(), err.Error())
			continue
		}
		pos++
	}
	return result[:pos], nil
}
