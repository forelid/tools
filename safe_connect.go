package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	_ "github.com/go-sqlite3"
	. "github.com/ini"
)

type Users struct {
	Uname string
	Passd string
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

// key
const key = "AES256Key-32Characters1234567890"

func initdb(path string) {

	os.Remove(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("----------建立并初始化数据----------")
		dir, file := filepath.Split(path)
		oldMask := syscall.Umask(0)
		os.Mkdir(dir, os.ModePerm)
		syscall.Umask(oldMask)

		os.Create(file)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer db.Close()

	sql := `create table users (uname text, passd text);`
	db.Exec(sql)
}

func list(path string) {

	fmt.Println("----------用户清单----------")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer db.Close()
	rows, err := db.Query("select uname from users")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer rows.Close()
	users := make([]string, 0)
	for rows.Next() {
		var name string
		rows.Scan(&name)
		users = append(users, name)
	}
	fmt.Println(users)
}

func add(path string, user string, pawd string) {

	fmt.Println("----------增加用户----------")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer db.Close()

	rows, err := db.Query("select * from users where uname=?", user)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer rows.Close()
	if rows.Next() {
		fmt.Printf("user [%q] is been haven!\n", user)
	} else {
		//增加用户数据
		stmt, err := db.Prepare("insert into users(uname,passd) values(?,?)")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer stmt.Close()

		if aesStr, err := AesEncrypt([]byte(pawd), []byte(key)); err == nil {
			fmt.Printf("AesEncrypt===", aesStr)
			if result, err := stmt.Exec(user, aesStr); err == nil {
				if _, err := result.LastInsertId(); err == nil {
					fmt.Printf("insert user : %q !\n ", user)
				} else {
					fmt.Println("result failed:%q !", err.Error())
				}
			} else {
				fmt.Printf("stmt faild:%q!", err.Error())
			}
		} else {
			fmt.Printf("Encrypt faild:%q!", err.Error())
		}
	}
}

func modify(path string, user string, pawd string) {

	fmt.Println("----------修改用户密码----------")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer db.Close()

	//修改用户密码
	stmt, err := db.Prepare("update users set passd=? where uname=?")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer stmt.Close()

	if aesPwd, err := AesEncrypt([]byte(pawd), []byte(key)); err == nil {
		if result, err := stmt.Exec(aesPwd, user); err == nil {
			if _, err := result.RowsAffected(); err == nil {
				fmt.Printf("update user : %q !\n", user)
			}
		}
	}
}

func getPassd(path string, user string) (string, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	//修改用户密码
	stmt, err := db.Prepare("select passd from users where uname=?")
	if err != nil {
		return "", err
	}
	defer stmt.Close()
	rows, err := stmt.Query(user)
	if err != nil {
		return "", err
	}
	rows.Next()
	var pwd string
	rows.Scan(&pwd)
	return pwd, nil
}

func mysql_exec(host string, user string, passwd string, db string, sql string) {
	//连接mysql数据库
	fmt.Println("----------连接mysql数据库----------")
	var hostname = strings.Join([]string{"-", host}, "h")
	var usr = strings.Join([]string{"-", user}, "u")
	var passds = strings.Join([]string{"-", passwd}, "p")
	var database = strings.Join([]string{"-", db}, "D")
	//	fmt.Printf("sql: host=%q, usstringer=%q, passwd=%q, db=%q, sql=%q\n", hostname, usr, passds, database, sql)

	//shell:	mysql -h ${database_ip} -u${database_user} -p${database_password}  -D ${database} -e "${sql}"
	cmd := exec.Command("mysql", hostname, usr, passds, database)
	cmd.Stdin = strings.NewReader(sql)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("result:")
	fmt.Println(out.String())

}

func init_config() (err error) {
	if _, err := os.Create(_CONFIG_FILE); err != nil {
		fmt.Println(err.Error())
	}

	if cfg, err := Load(_CONFIG_FILE); err == nil {
		cfg.Section("data").Key("path").Comment = "data saved path"
		cfg.Section("data").Key("path").SetValue("data")
		cfg.Section("data").Key("db_file").SetValue("foo.db")
		cfg.SaveTo("config.ini")
		return nil
	} else {
		return err
	}
}

func help() {
	fmt.Println("Usage:")
	fmt.Println(" -initdb \t initialize")
	fmt.Println(" -modify \t modify user passwd")
	fmt.Println(" -add \t add user and password")
	fmt.Println(" -list \t print all user list")
	fmt.Println(" -mysql \t safe connect mysql")
	fmt.Println(" -help \t help print help info")
}

var _CONFIG_FILE = "config.ini"

func main() {

	var path = "tmp/foo.db"

	_, err := os.Stat(_CONFIG_FILE)

	if os.IsNotExist(err) {
		if eror := init_config(); eror != nil {
			fmt.Printf("create config.ini:%q\n", eror.Error())
		}
	} else if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if cfg, err := Load(_CONFIG_FILE); err == nil {
		sec := cfg.Section("data")
		path = strings.Join([]string{sec.Key("path").Value(), sec.Key("db_file").Value()}, "/")

		fmt.Printf("path=%q\n", path)
	} else {
		fmt.Println("load  file is failed!")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		help()
	} else if os.Args[1] == "-initdb" {
		initdb(path)

	} else if os.Args[1] == "-add" {
		argNum := len(os.Args)
		if argNum != 4 {
			fmt.Println("Paramers:[user] [password]")
		} else {
			user := os.Args[2]
			passwd := os.Args[3]
			add(path, user, passwd)
		}
	} else if os.Args[1] == "-modify" {
		argNum := len(os.Args)
		if argNum != 4 {
			fmt.Println("Paramers:[user] [password]")
		} else {
			user := os.Args[2]
			passwd := os.Args[3]
			modify(path, user, passwd)

		}
	} else if os.Args[1] == "-mysql" {
		argNum := len(os.Args)
		if argNum != 6 {
			fmt.Println("Paramers:[host] [user] [db] [sql]")
		} else {
			host := os.Args[2]
			user := os.Args[3]
			db := os.Args[4]
			sql := os.Args[5]

			passwd, err := getPassd(path, user)
			if err == nil {
				if origin, err := AesDecrypt([]byte(passwd), []byte(key)); err == nil {
					mysql_exec(host, user, string(origin), db, sql)
				} else {
					fmt.Println("Decrypt password failed！")
				}

			} else {
				fmt.Printf("user [%q] is not exists,please add the user !", user)
			}
		}

	} else if os.Args[1] == "-list" {
		list(path)
	} else {
		help()
	}
}
