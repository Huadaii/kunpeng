package goplugin

import (
	"database/sql"
	"fmt"
	. "kunpeng/config"
	"kunpeng/plugin"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("weak-passwords", &mysqlWeakPass{})
}
func (d *mysqlWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "MySQL 弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "wolf",
		References: plugin.References{
			URL:  "https://www.cnblogs.com/yunsicai/p/4080864.html",
			KPID: "KP-0005",
		},
	}
	return d.info
}
func (d *mysqlWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *mysqlWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"root", "admin",
	}
	portList := []string{
		"3306", "3308",
	}
	for _, user := range userList {
		for _, port := range portList {
			for _, pass := range meta.PassList {
				pass = strings.Replace(pass, "{user}", user, -1)
				pass = plugin.EmptyRequest(pass)
				connStr := fmt.Sprintf("%s:%s@tcp(%s:%s)/?timeout=%ds", user, pass, netloc, port, Config.Timeout)
				db, err := sql.Open("mysql", connStr)
				if err != nil {
					break
				}
				err = db.Ping()
				if err == nil {
					db.Close()
					result := d.info
					result.Request = connStr
					result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
					d.result = append(d.result, result)
					b = true
					break
				} else if strings.Contains(err.Error(), "Access denied") {
					db.Close()
					continue
				} else {
					db.Close()
				}
			}
		}
	}
	return b
}
