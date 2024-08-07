package main

import (
    "fmt"
    "regexp"
)

func checkForSQLInjection(query string) bool {
    sqlInjectionPatterns := []string{
        `(?i)(\bor\b|\band\b).*?=.*?`,  // OR/AND 패턴
        `(?i)(\bunion\b|\bselect\b).*?\bfrom\b`,  // UNION/SELECT 패턴
        `(?i)(\b--\b|;|--\s|/\*)`,  // 주석 패턴
        `(?i)(\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\balter\b)`,  // DDL 패턴
        `(?i)\bexec\b`,  // exec 패턴
        `(?i)(\bwaitfor\b|\bdelay\b|\bsleep\b)`,  // 시간 지연 패턴
        `(?i)\bgrant\b`,  // 권한 변경 패턴
        `(?i)\b--\b`,  // SQL 주석 패턴
        `(?i)\bchar\(`,  // 함수 호출 패턴
        `(?i)\bconvert\(`,  // 함수 호출 패턴
        `(?i)\bcast\(`,  // 함수 호출 패턴
        `(?i)\bopenrowset\b`,  // OPENROWSET 함수 패턴
        `(?i)\bopendatasource\b`,  // OPENDATASOURCE 함수 패턴
        `(?i)\bselect\b.*\binto\b`,  // SELECT INTO 패턴
        `(?i)(\bcast\b|\bconvert\b)\(`,  // CAST/CONVERT 함수 패턴
        `(?i)\btable\b.*\bwhere\b`,  // TABLE WHERE 패턴
        `(?i)\binformation_schema\b`,  // INFORMATION_SCHEMA 패턴
        `(?i)\bmaster\b`,  // MASTER 데이터베이스 패턴
        `(?i)\buser\b.*\bpassword\b`,  // 사용자 패스워드 패턴
        `(?i)0x[0-9a-fA-F]+`,  // 헥사값 패턴
        `(?i)\bping\b`,  // ping 명령어 패턴
        `(?i)xp_cmdshell`,  // xp_cmdshell 함수 패턴
        `(?i)sp_executesql`,  // sp_executesql 함수 패턴
        `(?i)\bdump\b`,  // 데이터 덤프 패턴
        `(?i)\boutfile\b`,  // 파일 출력 패턴
        `(?i)\bprocedure\b.*\bfor\b`,  // PROCEDURE FOR 패턴
        `(?i)\bdeclare\b.*\b@.*\bint\b`,  // DECLARE INT 변수 패턴
        `(?i)select\b.*\bfrom\b.*\bdual\b`,  // SELECT FROM DUAL 패턴 (Oracle)
        `(?i)\bunion\b.*\bselect\b.*\bnull\b`,  // UNION SELECT NULL 패턴
        `(?i)\border\b.*\bby\b.*\b[0-9]`,  // ORDER BY 숫자 패턴
        `(?i)\bcount\b.*\(.*\)`,  // COUNT 함수 패턴
        `(?i)\bdatabase\b`,  // DATABASE 패턴
        `(?i)\bexec\b.*\bmaster\b`,  // EXEC MASTER 패턴
        `(?i)\bexists\b`,  // EXISTS 패턴
        `(?i)\bconcat\b`,  // CONCAT 함수 패턴
        `(?i)\bcoalesce\b`,  // COALESCE 함수 패턴
        `(?i)\bsysobjects\b`,  // SYSOBJECTS 테이블 패턴
        `(?i)\btruncate\b`,  // TRUNCATE 테이블 패턴
        `(?i)\bopen\b`,  // OPEN 함수 패턴
        `(?i)\bfetch\b`,  // FETCH 함수 패턴
        `(?i)\binsert\b.*\binto\b.*\bvalues\b`,  // INSERT INTO VALUES 패턴
        `(?i)\bupdate\b.*\bset\b`,  // UPDATE SET 패턴
        `(?i)\bdelete\b.*\bfrom\b`,  // DELETE FROM 패턴
        `(?i)\bdrop\b.*\btable\b`,  // DROP TABLE 패턴
        `(?i)\bselect\b.*\binto\b.*\bfrom\b`,  // SELECT INTO FROM 패턴
        `(?i)\bif\b.*\bexists\b`,  // IF EXISTS 패턴
        `(?i)\bselect\b.*\bgroup_concat\b`,  // SELECT GROUP_CONCAT 패턴
        `(?i)\bselect\b.*\bsleep\b`,  // SELECT SLEEP 패턴
        `(?i)\bselect\b.*\bbenchmark\b`,  // SELECT BENCHMARK 패턴
        `(?i)\bselect\b.*\bpg_sleep\b`,  // SELECT PG_SLEEP 패턴
        `(?i)\bselect\b.*\brand\b`,  // SELECT RAND 패턴
        `(?i)\bselect\b.*\bfloor\b`,  // SELECT FLOOR 패턴
        `(?i)\bselect\b.*\bpwd\b`,  // SELECT PWD 패턴
        `(?i)\bshow\b.*\bdatabases\b`,  // SHOW DATABASES 패턴
        `(?i)\bshow\b.*\btables\b`,  // SHOW TABLES 패턴
        `(?i)\bshow\b.*\bcolumns\b`,  // SHOW COLUMNS 패턴
        `(?i)\bselect\b.*\bcurrent_user\b`,  // SELECT CURRENT_USER 패턴
        `(?i)\bselect\b.*\bcurrent_database\b`,  // SELECT CURRENT_DATABASE 패턴
        `(?i)\bselect\b.*\bversion\b`,  // SELECT VERSION 패턴
        `(?i)\bselect\b.*\buser\b`,  // SELECT USER 패턴
        `(?i)\bselect\b.*\bpassword\b`,  // SELECT PASSWORD 패턴
        `(?i)\bselect\b.*\bencrypt\b`,  // SELECT ENCRYPT 패턴
        `(?i)\bselect\b.*\bdecrypt\b`,  // SELECT DECRYPT 패턴
        `(?i)\bselect\b.*\bhaving\b`,  // SELECT HAVING 패턴
        `(?i)\bselect\b.*\bload_file\b`,  // SELECT LOAD_FILE 패턴
        `(?i)\bselect\b.*\binto\b.*\boutfile\b`,  // SELECT INTO OUTFILE 패턴
        `(?i)\bselect\b.*\bbulk\b`,  // SELECT BULK 패턴
        `(?i)\bselect\b.*\bhex\b`,  // SELECT HEX 패턴
        `(?i)\bselect\b.*\bsubstring\b`,  // SELECT SUBSTRING 패턴
        `(?i)\bselect\b.*\bsubstr\b`,  // SELECT SUBSTR 패턴
        `(?i)\bselect\b.*\blike\b`,  // SELECT LIKE 패턴
        `(?i)\bselect\b.*\brpad\b`,  // SELECT RPAD 패턴
        `(?i)\bselect\b.*\blpad\b`,  // SELECT LPAD 패턴
        `(?i)\bselect\b.*\bcharindex\b`,  // SELECT CHARINDEX 패턴
        `(?i)\bselect\b.*\bsoundex\b`,  // SELECT SOUNDEX 패턴
        `(?i)\bselect\b.*\bchar\b`,  // SELECT CHAR 패턴
        `(?i)\bselect\b.*\bunion\b.*\ball\b`,  // SELECT UNION ALL 패턴
        `(?i)\bselect\b.*\bcount\b.*\bdistinct\b`,  // SELECT COUNT DISTINCT 패턴
        `(?i)\bselect\b.*\bcolumn\b`,  // SELECT COLUMN 패턴
        `(?i)\bselect\b.*\bprocedure\b`,  // SELECT PROCEDURE 패턴
        `(?i)\bselect\b.*\bfunction\b`,  // SELECT FUNCTION 패턴
        `(?i)\bselect\b.*\btrigger\b`,  // SELECT TRIGGER 패턴
        `(?i)\bselect\b.*\bevent\b`,  // SELECT EVENT 패턴
        `(?i)\bselect\b.*\bviews\b`,  // SELECT VIEWS 패턴
        `(?i)\bselect\b.*\bview\b`,  // SELECT VIEW 패턴
        `(?i)\bselect\b.*\bsequence\b`,  // SELECT SEQUENCE 패턴
        `(?i)\bselect\b.*\bschema\b`,  // SELECT SCHEMA 패턴
        `(?i)\bselect\b.*\btable\b`,  // SELECT TABLE 패턴
        `(?i)\bdumpfile\b`,  // DUMPFILE 패턴
        `(?i)\bload_file\b`,  // LOAD_FILE 패턴
        `(?i)\bschema\b`,  // SCHEMA 패턴
        `(?i)\binformation_schema\b`,  // INFORMATION_SCHEMA 패턴
        `(?i)\bsys\b`,  // SYS 패턴
        `(?i)\bselect\b.*\bmysql\b`,  // SELECT MYSQL 패턴
        `(?i)\bselect\b.*\bperformance_schema\b`,  // SELECT PERFORMANCE_SCHEMA 패턴
        `(?i)\bselect\b.*\bprocesslist\b`,  // SELECT PROCESSLIST 패턴
        `(?i)\bselect\b.*\bhosts\b`,  // SELECT HOSTS 패턴
        `(?i)\bselect\b.*\bplugins\b`,  // SELECT PLUGINS 패턴
        `(?i)\bselect\b.*\busers\b`,  // SELECT USERS 패턴
        `(?i)\bselect\b.*\buser\b`,  // SELECT USER 패턴
        `(?i)\bselect\b.*\bgroup\b`,  // SELECT GROUP 패턴
        `(?i)\bselect\b.*\badmin\b`,  // SELECT ADMIN 패턴
        `(?i)\bselect\b.*\broles\b`,  // SELECT ROLES 패턴
        `(?i)\bselect\b.*\bprivileges\b`,  // SELECT PRIVILEGES 패턴
        `(?i)\bselect\b.*\bsecurity\b`,  // SELECT SECURITY 패턴
        `(?i)\bselect\b.*\bauth\b`,  // SELECT AUTH 패턴
        `(?i)\bselect\b.*\bauthorization\b`,  // SELECT AUTHORIZATION 패턴
        `(?i)\bselect\b.*\bauthenticate\b`,  // SELECT AUTHENTICATE 패턴
        `(?i)\bselect\b.*\bpermission\b`,  // SELECT PERMISSION 패턴
        `(?i)\bselect\b.*\bpermissions\b`,  // SELECT PERMISSIONS 패턴
        `(?i)\bselect\b.*\bacl\b`,  // SELECT ACL 패턴
        `(?i)\bselect\b.*\bacls\b`,  // SELECT ACLS 패턴
        `(?i)\bselect\b.*\bgrant\b`,  // SELECT GRANT 패턴
        `(?i)\bselect\b.*\brevoke\b`,  // SELECT REVOKE 패턴
        `(?i)\bselect\b.*\bcredentials\b`,  // SELECT CREDENTIALS 패턴
        `(?i)\bselect\b.*\bcredential\b`,  // SELECT CREDENTIAL 패턴
        `(?i)\bselect\b.*\bsudo\b`,  // SELECT SUDO 패턴
        `(?i)\bselect\b.*\bsu\b`,  // SELECT SU 패턴
        `(?i)\bselect\b.*\broot\b`,  // SELECT ROOT 패턴
        `(?i)\bselect\b.*\bshell\b`,  // SELECT SHELL 패턴
        `(?i)\bselect\b.*\bsh\b`,  // SELECT SH 패턴
        `(?i)\bselect\b.*\bbash\b`,  // SELECT BASH 패턴
        `(?i)\bselect\b.*\bzsh\b`,  // SELECT ZSH 패턴
        `(?i)\bselect\b.*\bssh\b`,  // SELECT SSH 패턴
        `(?i)\bselect\b.*\brsh\b`,  // SELECT RSH 패턴
        `(?i)\bselect\b.*\brlogin\b`,  // SELECT RLOGIN 패턴
        `(?i)\bselect\b.*\brcp\b`,  // SELECT RCP 패턴
        `(?i)\bselect\b.*\bftp\b`,  // SELECT FTP 패턴
        `(?i)\bselect\b.*\bsftp\b`,  // SELECT SFTP 패턴
        `(?i)\bselect\b.*\btelnet\b`,  // SELECT TELNET 패턴
        `(?i)\bselect\b.*\brpc\b`,  // SELECT RPC 패턴
        `(?i)\bselect\b.*\bport\b`,  // SELECT PORT 패턴
        `(?i)\bselect\b.*\bports\b`,  // SELECT PORTS 패턴
        `(?i)\bselect\b.*\bnetstat\b`,  // SELECT NETSTAT 패턴
        `(?i)\bselect\b.*\bping\b`,  // SELECT PING 패턴
        `(?i)\bselect\b.*\btraceroute\b`,  // SELECT TRACEROUTE 패턴
        `(?i)\bselect\b.*\bnmap\b`,  // SELECT NMAP 패턴
        `(?i)\bselect\b.*\bwhois\b`,  // SELECT WHOIS 패턴
        `(?i)\bselect\b.*\bdig\b`,  // SELECT DIG 패턴
        `(?i)\bselect\b.*\bnameserver\b`,  // SELECT NAMESERVER 패턴
        `(?i)\bselect\b.*\bdns\b`,  // SELECT DNS 패턴
        `(?i)\bselect\b.*\bdomain\b`,  // SELECT DOMAIN 패턴
        `(?i)\bselect\b.*\bdomainname\b`,  // SELECT DOMAINNAME 패턴
        `(?i)\bselect\b.*\bdnssec\b`,  // SELECT DNSSEC 패턴
        `(?i)\bselect\b.*\bzone\b`,  // SELECT ZONE 패턴
        `(?i)\bselect\b.*\bzones\b`,  // SELECT ZONES 패턴
        `(?i)\bselect\b.*\bnslookup\b`,  // SELECT NSLOOKUP 패턴
        `(?i)\bselect\b.*\bdig\b`,  // SELECT DIG 패턴
        `(?i)\bselect\b.*\bip\b`,  // SELECT IP 패턴
        `(?i)\bselect\b.*\bipv4\b`,  // SELECT IPV4 패턴
        `(?i)\bselect\b.*\bipv6\b`,  // SELECT IPV6 패턴
        `(?i)\bselect\b.*\bmac\b`,  // SELECT MAC 패턴
        `(?i)\bselect\b.*\baddress\b`,  // SELECT ADDRESS 패턴
        `(?i)\bselect\b.*\bgateway\b`,  // SELECT GATEWAY 패턴
        `(?i)\bselect\b.*\brouting\b`,  // SELECT ROUTING 패턴
        `(?i)\bselect\b.*\binterface\b`,  // SELECT INTERFACE 패턴
        `(?i)\bselect\b.*\bdevice\b`,  // SELECT DEVICE 패턴
        `(?i)\bselect\b.*\bhostname\b`,  // SELECT HOSTNAME 패턴
        `(?i)\bselect\b.*\bhost\b`,  // SELECT HOST 패턴
        `(?i)\bselect\b.*\bsubnet\b`,  // SELECT SUBNET 패턴
        `(?i)\bselect\b.*\bnetwork\b`,  // SELECT NETWORK 패턴
        `(?i)\bselect\b.*\bnetworks\b`,  // SELECT NETWORKS 패턴
        `(?i)\bselect\b.*\btopology\b`,  // SELECT TOPOLOGY 패턴
        `(?i)\bselect\b.*\btcp\b`,  // SELECT TCP 패턴
        `(?i)\bselect\b.*\budp\b`,  // SELECT UDP 패턴
        `(?i)\blicence\b`,  // SELECT LICENCE 패턴
        `(?i)\blicense\b`,  // SELECT LICENSE 패턴
        `(?i)\bselect\b.*\bkey\b`,  // SELECT KEY 패턴
        `(?i)\bselect\b.*\bkeys\b`,  // SELECT KEYS 패턴
        `(?i)\bselect\b.*\bcertificate\b`,  // SELECT CERTIFICATE 패턴
        `(?i)\bselect\b.*\bcertificates\b`,  // SELECT CERTIFICATES 패턴
        `(?i)\bselect\b.*\bcert\b`,  // SELECT CERT 패턴
        `(?i)\bselect\b.*\bca\b`,  // SELECT CA 패턴
        `(?i)\bselect\b.*\bcertificate_authority\b`,  // SELECT CERTIFICATE AUTHORITY 패턴
        `(?i)\bselect\b.*\bchain\b`,  // SELECT CHAIN 패턴
        `(?i)\bselect\b.*\bcrl\b`,  // SELECT CRL 패턴
        `(?i)\bselect\b.*\bcertification\b`,  // SELECT CERTIFICATION 패턴
        `(?i)\bselect\b.*\bssl\b`,  // SELECT SSL 패턴
        `(?i)\bselect\b.*\btls\b`,  // SELECT TLS 패턴
        `(?i)\bselect\b.*\bhash\b`,  // SELECT HASH 패턴
        `(?i)\bselect\b.*\bdigest\b`,  // SELECT DIGEST 패턴
        `(?i)\bselect\b.*\bsignature\b`,  // SELECT SIGNATURE 패턴
        `(?i)\bselect\b.*\bsignatures\b`,  // SELECT SIGNATURES 패턴
        `(?i)\bselect\b.*\bkeypair\b`,  // SELECT KEYPAIR 패턴
        `(?i)\bselect\b.*\bpublic\b`,  // SELECT PUBLIC 패턴
        `(?i)\bselect\b.*\bprivate\b`,  // SELECT PRIVATE 패턴
        `(?i)\bselect\b.*\bsecure\b`,  // SELECT SECURE 패턴
        `(?i)\bselect\b.*\bencryption\b`,  // SELECT ENCRYPTION 패턴
        `(?i)\bselect\b.*\bdecryption\b`,  // SELECT DECRYPTION 패턴
        `(?i)\bselect\b.*\bpgp\b`,  // SELECT PGP 패턴
        `(?i)\bselect\b.*\bgpg\b`,  // SELECT GPG 패턴
        `(?i)\bselect\b.*\bpem\b`,  // SELECT PEM 패턴
        `(?i)\bselect\b.*\bpkcs\b`,  // SELECT PKCS 패턴
        `(?i)\bselect\b.*\bpgp\b`,  // SELECT PGP 패턴
        `(?i)\bselect\b.*\bx509\b`,  // SELECT X509 패턴
        `(?i)\bselect\b.*\bkeygen\b`,  // SELECT KEYGEN 패턴
        `(?i)\bselect\b.*\bpk\b`,  // SELECT PK 패턴
        `(?i)\bselect\b.*\bpkcs\b`,  // SELECT PKCS 패턴
        `(?i)\bselect\b.*\bcsr\b`,  // SELECT CSR 패턴
        `(?i)\bselect\b.*\bder\b`,  // SELECT DER 패턴
        `(?i)\bselect\b.*\bkey\b`,  // SELECT KEY 패턴
        `(?i)\bselect\b.*\brsa\b`,  // SELECT RSA 패턴
        `(?i)\bselect\b.*\brsa_public\b`,  // SELECT RSA PUBLIC 패턴
        `(?i)\bselect\b.*\brsa_private\b`,  // SELECT RSA PRIVATE 패턴
        `(?i)\bselect\b.*\becdsa\b`,  // SELECT ECDSA 패턴
        `(?i)\bselect\b.*\becdh\b`,  // SELECT ECDH 패턴
        `(?i)\bselect\b.*\bkey_exchange\b`,  // SELECT KEY EXCHANGE 패턴
        `(?i)\bselect\b.*\bdh\b`,  // SELECT DH 패턴
        `(?i)\bselect\b.*\bdhe\b`,  // SELECT DHE 패턴
        `(?i)\bselect\b.*\brandom\b`,  // SELECT RANDOM 패턴
        `(?i)\bselect\b.*\bsalt\b`,  // SELECT SALT 패턴
        `(?i)\bselect\b.*\bnonce\b`,  // SELECT NONCE 패턴
    }

    for _, pattern := range sqlInjectionPatterns {
        re := regexp.MustCompile(pattern)
        if re.MatchString(query) {
            return true
        }
    }

    return false
}

// It may be updated later

//___  ___            _           ______            ______                     _
//|  \/  |           | |          | ___ \           |  ___|                   | |
//| .  . |  __ _   __| |  ___     | |_/ / _   _     | |_     ___  _ __   __ _ | |
//| |\/| | / _` | / _` | / _ \    | ___ \| | | |    |  _|   / _ \| '__| / _` || |
//| |  | || (_| || (_| ||  __/    | |_/ /| |_| |    | |    |  __/| |   | (_| || |
//\_|  |_/ \__,_| \__,_| \___|    \____/  \__, |    \_|     \___||_|    \__,_||_|
//                                         __/ |
//
