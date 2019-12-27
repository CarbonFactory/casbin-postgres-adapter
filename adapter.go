// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adapter

import (
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"github.com/go-pg/pg"
)

// Adapter represents the MySQL adapter for policy storage.
type Adapter struct {
	user     string
	password string
	database string
	db       *pg.DB
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(user string, password string, database string, addr string) *Adapter {
	a := Adapter{}
	a.user = user
	a.password = password
	a.database = database
	a.addr = addr

	return &a
}

func (a *Adapter) open() {

	db := pg.Connect(&pg.Options{
		User:     a.user,
		Password: a.password,
		Database: a.database,
		Addr:     a.addr,
	})
	a.db = db

	a.createTable()
}

func (a *Adapter) close() {
	a.db.Close()
}

func (a *Adapter) createTable() {

	_, err := a.db.Exec("CREATE table IF NOT EXISTS x_policy (p_type VARCHAR(10), v0 VARCHAR(256), v1 VARCHAR(256), v2 VARCHAR(256), v3 VARCHAR(256), v4 VARCHAR(256), v5 VARCHAR(256))")
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) dropTable() {
	_, err := a.db.Exec("DROP table x_policy")
	if err != nil {
		panic(err)
	}
}

func loadPolicyLine(line CasbinRule, model model.Model) {

	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

type CasbinRule struct {
	TableName struct{} `sql:"x_policy" pg:",discard_unknown_columns" `
	PType     string   `sql:",pType" db:"p_type" `
	V0        string   `sql:",v0" db:"v0" `
	V1        string   `sql:",v1" db:"v1" `
	V2        string   `sql:",v2" db:"v2" `
	V3        string   `sql:",v3" db:"v3" `
	V4        string   `sql:",v4" db:"v4" `
	V5        string   `sql:",v5" db:"v5" `
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {

	a.open()
	// defer a.close()

	var lines []CasbinRule
	sqlstr := "select * from policy"

	_, err := a.db.Query(&lines, sqlstr)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	return nil
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.open()
	// defer a.close()

	a.dropTable()
	a.createTable()

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			err := a.db.Insert(&line)
			if err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			err := a.db.Insert(&line)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {

	line := savePolicyLine(ptype, rule)
	err := a.db.Insert(&line)
	if err != nil {
		return err
	}
	return err
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.db.Delete(&line) //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
	return err
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := CasbinRule{}

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err := a.db.Delete(&line)
	return err
}
