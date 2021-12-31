package main

import "C" // required
import (
	"encoding/json"
	"io/ioutil"
	"kunpeng/config"
	"kunpeng/plugin"
	_ "kunpeng/plugin/go"
	"kunpeng/util"
	"kunpeng/web"
	"log"
)

var VERSION string

type greeting string

func (g greeting) Check(taskJSON string) []map[string]interface{} {
	var task plugin.Task
	json.Unmarshal([]byte(taskJSON), &task)
	return plugin.Scan(task)
}

func (g greeting) GetPlugins() []map[string]interface{} {
	return plugin.GetPlugins()
}

func (g greeting) GetPluginsTxt() map[string][]string {
	return plugin.GetPluginsTxt()
}

func (g greeting) SetConfig(configJSON string) {
	config.Set(configJSON)
}

func (g greeting) ShowLog() {
	config.SetDebug(true)
}

func (g greeting) GetVersion() string {
	return VERSION
}

func (g greeting) StartBuffer() {
	util.Logger.StartBuffer()
}

func (g greeting) GetLog(sep string) string {
	return util.Logger.BufferContent(sep)
}

//export StartWebServer
func StartWebServer(bindAddr *C.char) {
	go web.StartServer(C.GoString(bindAddr))
}

//export Check
func Check(task *C.char) *C.char {
	util.Logger.Info(C.GoString(task))
	var m plugin.Task
	err := json.Unmarshal([]byte(C.GoString(task)), &m)
	if err != nil {
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	util.Logger.Info(m)
	result := plugin.Scan(m)
	if len(result) == 0 {
		return C.CString("[]")
	}
	b, err := json.Marshal(result)
	if err != nil {
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	return C.CString(string(b))
}

//export GetPlugins
func GetPlugins() *C.char {
	var result string
	plugins := plugin.GetPlugins()
	b, err := json.Marshal(plugins)
	if err != nil {
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	result = string(b)
	return C.CString(result)
}

//export GetPluginsTxt
func GetPluginsTxt() *C.char {
	var result string
	plugins := plugin.GetPluginsTxt()
	b, err := json.Marshal(plugins)
	if err != nil {
		util.Logger.Error(err.Error())
		return C.CString("[]")
	}
	result = string(b)
	return C.CString(result)
}

//export SetConfig
func SetConfig(configJSON *C.char) {
	config.Set(C.GoString(configJSON))
}

//export ShowLog
func ShowLog() {
	config.SetDebug(true)
}

//export GetVersion
func GetVersion() *C.char {
	return C.CString(VERSION)
}

//export StartBuffer
func StartBuffer() {
	util.Logger.StartBuffer()
}

//export GetLog
func GetLog(sep *C.char) *C.char {
	return C.CString(util.Logger.BufferContent(C.GoString(sep)))
}

var Greeter greeting

func init() {
	plugins := plugin.GetPluginsTxt()
	fileContent, err := json.MarshalIndent(plugins, "", "\t")
	if err = ioutil.WriteFile("kunpeng/checkList.txt", fileContent, 0666); err != nil {
		log.Println("Writefile Error =", err)
		return
	}
}

func main() {}
