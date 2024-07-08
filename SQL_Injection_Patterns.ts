function checkForSQLInjection(query: string): boolean {
    const sqlInjectionPatterns: RegExp[] = [
        /(\bor\b|\band\b).*?=.*?/i,  // OR/AND 패턴
        /(\bunion\b|\bselect\b).*?\bfrom\b/i,  // UNION/SELECT 패턴
        /(\b--\b|;|--\s|\/\*)/i,  // 주석 패턴
        /(\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\balter\b)/i,  // DDL 패턴
        /\bexec\b/i,  // exec 패턴
        /(\bwaitfor\b|\bdelay\b|\bsleep\b)/i,  // 시간 지연 패턴
        /\bgrant\b/i,  // 권한 변경 패턴
        /\b--\b/i,  // SQL 주석 패턴
        /\bchar\(/i,  // 함수 호출 패턴
        /\bconvert\(/i,  // 함수 호출 패턴
        /\bcast\(/i,  // 함수 호출 패턴
        /\bopenrowset\b/i,  // OPENROWSET 함수 패턴
        /\bopendatasource\b/i,  // OPENDATASOURCE 함수 패턴
        /\bselect\b.*\binto\b/i,  // SELECT INTO 패턴
        /(\bcast\b|\bconvert\b)\(/i,  // CAST/CONVERT 함수 패턴
        /\btable\b.*\bwhere\b/i,  // TABLE WHERE 패턴
        /\binformation_schema\b/i,  // INFORMATION_SCHEMA 패턴
        /\bmaster\b/i,  // MASTER 데이터베이스 패턴
        /\buser\b.*\bpassword\b/i,  // 사용자 패스워드 패턴
        /0x[0-9a-fA-F]+/i,  // 헥사값 패턴
        /\bping\b/i,  // ping 명령어 패턴
        /xp_cmdshell/i,  // xp_cmdshell 함수 패턴
        /sp_executesql/i,  // sp_executesql 함수 패턴
        /\bdump\b/i,  // 데이터 덤프 패턴
        /\boutfile\b/i,  // 파일 출력 패턴
        /\bprocedure\b.*\bfor\b/i,  // PROCEDURE FOR 패턴
        /\bdeclare\b.*\b@.*\bint\b/i,  // DECLARE INT 변수 패턴
        /select\b.*\bfrom\b.*\bdual\b/i,  // SELECT FROM DUAL 패턴 (Oracle)
        /\bunion\b.*\bselect\b.*\bnull\b/i,  // UNION SELECT NULL 패턴
        /\border\b.*\bby\b.*\b[0-9]/i,  // ORDER BY 숫자 패턴
        /\bcount\b.*\(.*\)/i,  // COUNT 함수 패턴
        /\bdatabase\b/i,  // DATABASE 패턴
        /\bexec\b.*\bmaster\b/i,  // EXEC MASTER 패턴
        /\bexists\b/i,  // EXISTS 패턴
        /\bconcat\b/i,  // CONCAT 함수 패턴
        /\bcoalesce\b/i,  // COALESCE 함수 패턴
        /\bsysobjects\b/i,  // SYSOBJECTS 테이블 패턴
        /\btruncate\b/i,  // TRUNCATE 테이블 패턴
        /\bopen\b/i,  // OPEN 함수 패턴
        /\bfetch\b/i,  // FETCH 함수 패턴
        /\binsert\b.*\binto\b.*\bvalues\b/i,  // INSERT INTO VALUES 패턴
        /\bupdate\b.*\bset\b/i,  // UPDATE SET 패턴
        /\bdelete\b.*\bfrom\b/i,  // DELETE FROM 패턴
        /\bdrop\b.*\btable\b/i,  // DROP TABLE 패턴
        /\bselect\b.*\binto\b.*\bfrom\b/i,  // SELECT INTO FROM 패턴
        /\bif\b.*\bexists\b/i,  // IF EXISTS 패턴
        /\bselect\b.*\bgroup_concat\b/i,  // SELECT GROUP_CONCAT 패턴
        /\bselect\b.*\bsleep\b/i,  // SELECT SLEEP 패턴
        /\bselect\b.*\bbenchmark\b/i,  // SELECT BENCHMARK 패턴
        /\bselect\b.*\bpg_sleep\b/i,  // SELECT PG_SLEEP 패턴
        /\bselect\b.*\brand\b/i,  // SELECT RAND 패턴
        /\bselect\b.*\bfloor\b/i,  // SELECT FLOOR 패턴
        /\bselect\b.*\bpwd\b/i,  // SELECT PWD 패턴
        /\bshow\b.*\bdatabases\b/i,  // SHOW DATABASES 패턴
        /\bshow\b.*\btables\b/i,  // SHOW TABLES 패턴
        /\bshow\b.*\bcolumns\b/i,  // SHOW COLUMNS 패턴
        /\bselect\b.*\bcurrent_user\b/i,  // SELECT CURRENT_USER 패턴
        /\bselect\b.*\bcurrent_database\b/i,  // SELECT CURRENT_DATABASE 패턴
        /\bselect\b.*\bversion\b/i,  // SELECT VERSION 패턴
        /\bselect\b.*\buser\b/i,  // SELECT USER 패턴
        /\bselect\b.*\bpassword\b/i,  // SELECT PASSWORD 패턴
        /\bselect\b.*\bencrypt\b/i,  // SELECT ENCRYPT 패턴
        /\bselect\b.*\bdecrypt\b/i,  // SELECT DECRYPT 패턴
        /\bselect\b.*\bhaving\b/i,  // SELECT HAVING 패턴
        /\bselect\b.*\bload_file\b/i,  // SELECT LOAD_FILE 패턴
        /\bselect\b.*\binto\b.*\boutfile\b/i,  // SELECT INTO OUTFILE 패턴
        /\bselect\b.*\bbulk\b/i,  // SELECT BULK 패턴
        /\bselect\b.*\bhex\b/i,  // SELECT HEX 패턴
        /\bselect\b.*\bsubstring\b/i,  // SELECT SUBSTRING 패턴
        /\bselect\b.*\bsubstr\b/i,  // SELECT SUBSTR 패턴
        /\bselect\b.*\blike\b/i,  // SELECT LIKE 패턴
        /\bselect\b.*\brpad\b/i,  // SELECT RPAD 패턴
        /\bselect\b.*\blpad\b/i,  // SELECT LPAD 패턴
        /\bselect\b.*\bcharindex\b/i,  // SELECT CHARINDEX 패턴
        /\bselect\b.*\bsoundex\b/i,  // SELECT SOUNDEX 패턴
        /\bselect\b.*\bchar\b/i,  // SELECT CHAR 패턴
        /\bselect\b.*\bunion\b.*\ball\b/i,  // SELECT UNION ALL 패턴
        /\bselect\b.*\bcount\b.*\bdistinct\b/i,  // SELECT COUNT DISTINCT 패턴
        /\bselect\b.*\bcolumn\b/i,  // SELECT COLUMN 패턴
        /\bselect\b.*\bprocedure\b/i,  // SELECT PROCEDURE 패턴
        /\bselect\b.*\bfunction\b/i,  // SELECT FUNCTION 패턴
        /\bselect\b.*\btrigger\b/i,  // SELECT TRIGGER 패턴
        /\bselect\b.*\bevent\b/i,  // SELECT EVENT 패턴
        /\bselect\b.*\bviews\b/i,  // SELECT VIEWS 패턴
        /\bselect\b.*\bview\b/i,  // SELECT VIEW 패턴
        /\bselect\b.*\bsequence\b/i,  // SELECT SEQUENCE 패턴
        /\bselect\b.*\bschema\b/i,  // SELECT SCHEMA 패턴
        /\bselect\b.*\btable\b/i,  // SELECT TABLE 패턴
        /\bdumpfile\b/i,  // DUMPFILE 패턴
        /\bload_file\b/i,  // LOAD_FILE 패턴
        /\bschema\b/i,  // SCHEMA 패턴
        /\binformation_schema\b/i,  // INFORMATION_SCHEMA 패턴
        /\bsys\b/i,  // SYS 패턴
        /\bselect\b.*\bmysql\b/i,  // SELECT MYSQL 패턴
        /\bselect\b.*\bperformance_schema\b/i,  // SELECT PERFORMANCE_SCHEMA 패턴
        /\bselect\b.*\bprocesslist\b/i,  // SELECT PROCESSLIST 패턴
        /\bselect\b.*\bhosts\b/i,  // SELECT HOSTS 패턴
        /\bselect\b.*\bplugins\b/i,  // SELECT PLUGINS 패턴
        /\bselect\b.*\busers\b/i,  // SELECT USERS 패턴
        /\bselect\b.*\buser\b/i,  // SELECT USER 패턴
        /\bselect\b.*\bgroup\b/i,  // SELECT GROUP 패턴
        /\bselect\b.*\badmin\b/i,  // SELECT ADMIN 패턴
        /\bselect\b.*\broles\b/i,  // SELECT ROLES 패턴
        /\bselect\b.*\bprivileges\b/i,  // SELECT PRIVILEGES 패턴
        /\bselect\b.*\bsecurity\b/i,  // SELECT SECURITY 패턴
        /\bselect\b.*\bauth\b/i,  // SELECT AUTH 패턴
        /\bselect\b.*\bauthorization\b/i,  // SELECT AUTHORIZATION 패턴
        /\bselect\b.*\bauthenticate\b/i,  // SELECT AUTHENTICATE 패턴
        /\bselect\b.*\bpermission\b/i,  // SELECT PERMISSION 패턴
        /\bselect\b.*\bpermissions\b/i,  // SELECT PERMISSIONS 패턴
        /\bselect\b.*\bacl\b/i,  // SELECT ACL 패턴
        /\bselect\b.*\bacls\b/i,  // SELECT ACLS 패턴
        /\bselect\b.*\bgrant\b/i,  // SELECT GRANT 패턴
        /\bselect\b.*\brevoke\b/i,  // SELECT REVOKE 패턴
        /\bselect\b.*\bcredentials\b/i,  // SELECT CREDENTIALS 패턴
        /\bselect\b.*\bcredential\b/i,  // SELECT CREDENTIAL 패턴
        /\bselect\b.*\bsudo\b/i,  // SELECT SUDO 패턴
        /\bselect\b.*\bsu\b/i,  // SELECT SU 패턴
        /\bselect\b.*\broot\b/i,  // SELECT ROOT 패턴
        /\bselect\b.*\bshell\b/i,  // SELECT SHELL 패턴
        /\bselect\b.*\bsh\b/i,  // SELECT SH 패턴
        /\bselect\b.*\bbash\b/i,  // SELECT BASH 패턴
        /\bselect\b.*\bzsh\b/i,  // SELECT ZSH 패턴
        /\bselect\b.*\bssh\b/i,  // SELECT SSH 패턴
        /\bselect\b.*\brsh\b/i,  // SELECT RSH 패턴
        /\bselect\b.*\brlogin\b/i,  // SELECT RLOGIN 패턴
        /\bselect\b.*\brcp\b/i,  // SELECT RCP 패턴
        /\bselect\b.*\bftp\b/i,  // SELECT FTP 패턴
        /\bselect\b.*\bsftp\b/i,  // SELECT SFTP 패턴
        /\bselect\b.*\btelnet\b/i,  // SELECT TELNET 패턴
        /\bselect\b.*\brpc\b/i,  // SELECT RPC 패턴
        /\bselect\b.*\bport\b/i,  // SELECT PORT 패턴
        /\bselect\b.*\bports\b/i,  // SELECT PORTS 패턴
        /\bselect\b.*\bnetstat\b/i,  // SELECT NETSTAT 패턴
        /\bselect\b.*\bping\b/i,  // SELECT PING 패턴
        /\bselect\b.*\btraceroute\b/i,  // SELECT TRACEROUTE 패턴
        /\bselect\b.*\bnmap\b/i,  // SELECT NMAP 패턴
        /\bselect\b.*\bwhois\b/i,  // SELECT WHOIS 패턴
        /\bselect\b.*\bdig\b/i,  // SELECT DIG 패턴
        /\bselect\b.*\bnameserver\b/i,  // SELECT NAMESERVER 패턴
        /\bselect\b.*\bdns\b/i,  // SELECT DNS 패턴
        /\bselect\b.*\bdomain\b/i,  // SELECT DOMAIN 패턴
        /\bselect\b.*\bdomainname\b/i,  // SELECT DOMAINNAME 패턴
        /\bselect\b.*\bdnssec\b/i,  // SELECT DNSSEC 패턴
        /\bselect\b.*\bzone\b/i,  // SELECT ZONE 패턴
        /\bselect\b.*\bzones\b/i,  // SELECT ZONES 패턴
        /\bselect\b.*\bnslookup\b/i,  // SELECT NSLOOKUP 패턴
        /\bselect\b.*\bdig\b/i,  // SELECT DIG 패턴
        /\bselect\b.*\bip\b/i,  // SELECT IP 패턴
        /\bselect\b.*\bipv4\b/i,  // SELECT IPV4 패턴
        /\bselect\b.*\bipv6\b/i,  // SELECT IPV6 패턴
        /\bselect\b.*\bmac\b/i,  // SELECT MAC 패턴
        /\bselect\b.*\baddress\b/i,  // SELECT ADDRESS 패턴
        /\bselect\b.*\bgateway\b/i,  // SELECT GATEWAY 패턴
        /\bselect\b.*\brouting\b/i,  // SELECT ROUTING 패턴
        /\bselect\b.*\binterface\b/i,  // SELECT INTERFACE 패턴
        /\bselect\b.*\bdevice\b/i,  // SELECT DEVICE 패턴
        /\bselect\b.*\bhostname\b/i,  // SELECT HOSTNAME 패턴
        /\bselect\b.*\bhost\b/i,  // SELECT HOST 패턴
        /\bselect\b.*\bsubnet\b/i,  // SELECT SUBNET 패턴
        /\bselect\b.*\bnetwork\b/i,  // SELECT NETWORK 패턴
        /\bselect\b.*\bnetworks\b/i,  // SELECT NETWORKS 패턴
        /\bselect\b.*\btopology\b/i,  // SELECT TOPOLOGY 패턴
        /\bselect\b.*\btcp\b/i,  // SELECT TCP 패턴
        /\bselect\b.*\budp\b/i,  // SELECT UDP 패턴
        /\blicence\b/i,  // SELECT LICENCE 패턴
        /\blicense\b/i,  // SELECT LICENSE 패턴
        /\bselect\b.*\bkey\b/i,  // SELECT KEY 패턴
        /\bselect\b.*\bkeys\b/i,  // SELECT KEYS 패턴
        /\bselect\b.*\bcertificate\b/i,  // SELECT CERTIFICATE 패턴
        /\bselect\b.*\bcertificates\b/i,  // SELECT CERTIFICATES 패턴
        /\bselect\b.*\bcert\b/i,  // SELECT CERT 패턴
        /\bselect\b.*\bca\b/i,  // SELECT CA 패턴
        /\bselect\b.*\bcertificate_authority\b/i,  // SELECT CERTIFICATE AUTHORITY 패턴
        /\bselect\b.*\bchain\b/i,  // SELECT CHAIN 패턴
        /\bselect\b.*\bcrl\b/i,  // SELECT CRL 패턴
        /\bselect\b.*\bcertification\b/i,  // SELECT CERTIFICATION 패턴
        /\bselect\b.*\bssl\b/i,  // SELECT SSL 패턴
        /\bselect\b.*\btls\b/i,  // SELECT TLS 패턴
        /\bselect\b.*\bhash\b/i,  // SELECT HASH 패턴
        /\bselect\b.*\bdigest\b/i,  // SELECT DIGEST 패턴
        /\bselect\b.*\bsignature\b/i,  // SELECT SIGNATURE 패턴
        /\bselect\b.*\bsignatures\b/i,  // SELECT SIGNATURES 패턴
        /\bselect\b.*\bkeypair\b/i,  // SELECT KEYPAIR 패턴
        /\bselect\b.*\bpublic\b/i,  // SELECT PUBLIC 패턴
        /\bselect\b.*\bprivate\b/i,  // SELECT PRIVATE 패턴
        /\bselect\b.*\bsecure\b/i,  // SELECT SECURE 패턴
        /\bselect\b.*\bencryption\b/i,  // SELECT ENCRYPTION 패턴
        /\bselect\b.*\bdecryption\b/i,  // SELECT DECRYPTION 패턴
        /\bselect\b.*\bpgp\b/i,  // SELECT PGP 패턴
        /\bselect\b.*\bgpg\b/i,  // SELECT GPG 패턴
        /\bselect\b.*\bpem\b/i,  // SELECT PEM 패턴
        /\bselect\b.*\bpkcs\b/i,  // SELECT PKCS 패턴
        /\bselect\b.*\bpgp\b/i,  // SELECT PGP 패턴
        /\bselect\b.*\bx509\b/i,  // SELECT X509 패턴
        /\bselect\b.*\bkeygen\b/i,  // SELECT KEYGEN 패턴
        /\bselect\b.*\bpk\b/i,  // SELECT PK 패턴
        /\bselect\b.*\bpkcs\b/i,  // SELECT PKCS 패턴
        /\bselect\b.*\bcsr\b/i,  // SELECT CSR 패턴
        /\bselect\b.*\bder\b/i,  // SELECT DER 패턴
        /\bselect\b.*\bkey\b/i,  // SELECT KEY 패턴
        /\bselect\b.*\brsa\b/i,  // SELECT RSA 패턴
        /\bselect\b.*\brsa_public\b/i,  // SELECT RSA PUBLIC 패턴
        /\bselect\b.*\brsa_private\b/i,  // SELECT RSA PRIVATE 패턴
        /\bselect\b.*\becdsa\b/i,  // SELECT ECDSA 패턴
        /\bselect\b.*\becdh\b/i,  // SELECT ECDH 패턴
        /\bselect\b.*\bkey_exchange\b/i,  // SELECT KEY EXCHANGE 패턴
        /\bselect\b.*\bdh\b/i,  // SELECT DH 패턴
        /\bselect\b.*\bdhe\b/i,  // SELECT DHE 패턴
        /\bselect\b.*\brandom\b/i,  // SELECT RANDOM 패턴
        /\bselect\b.*\bsalt\b/i,  // SELECT SALT 패턴
        /\bselect\b.*\bnonce\b/i,  // SELECT NONCE 패턴
        /\bselect\b.*\bhmac\b/i,  // SELECT HMAC 패턴
        /\bselect\b.*\bsha\b/i,  // SELECT SHA 패턴
        /\bselect\b.*\bmd5\b/i,  // SELECT MD5 패턴
        /\bselect\b.*\bsha1\b/i,  // SELECT SHA1 패턴
        /\bselect\b.*\bsha256\b/i,  // SELECT SHA256 패턴
        /\bselect\b.*\bsha512\b/i,  // SELECT SHA512 패턴
        /\bselect\b.*\bripemd\b/i,  // SELECT RIPEMD 패턴
        /\bselect\b.*\bripemd160\b/i,  // SELECT RIPEMD160 패턴
        /\bselect\b.*\bblake\b/i,  // SELECT BLAKE 패턴
        /\bselect\b.*\bblake2\b/i,  // SELECT BLAKE2 패턴
        /\bselect\b.*\btiger\b/i,  // SELECT TIGER 패턴
        /\bselect\b.*\bwhirlpool\b/i,  // SELECT WHIRLPOOL 패턴
        /\bselect\b.*\bhash\b/i,  // SELECT HASH 패턴
        /\bselect\b.*\bhashes\b/i,  // SELECT HASHES 패턴
        /\bselect\b.*\bdigest\b/i,  // SELECT DIGEST 패턴
        /\bselect\b.*\bdigests\b/i,  // SELECT DIGESTS 패턴
        /\bselect\b.*\bsignature\b/i,  // SELECT SIGNATURE 패턴
        /\bselect\b.*\bsignatures\b/i,  // SELECT SIGNATURES 패턴
        /\bselect\b.*\bcert\b/i,  // SELECT CERT 패턴
        /\bselect\b.*\bcerts\b/i,  // SELECT CERTS 패턴
        /\bselect\b.*\bcertificate\b/i,  // SELECT CERTIFICATE 패턴
        /\bselect\b.*\bcertificates\b/i,  // SELECT CERTIFICATES 패턴
        /\bselect\b.*\bpem\b/i,  // SELECT PEM 패턴
        /\bselect\b.*\bpkcs\b/i,  // SELECT PKCS 패턴
        /\bselect\b.*\bx509\b/i,  // SELECT X509 패턴
        /\bselect\b.*\brsa\b/i,  // SELECT RSA 패턴
        /\bselect\b.*\becdh\b/i,  // SELECT ECDH 패턴
        /\bselect\b.*\bdhe\b/i,  // SELECT DHE 패턴
        /\bselect\b.*\bsha\b/i,  // SELECT SHA 패턴
        /\bselect\b.*\bmd5\b/i,  // SELECT MD5 패턴
        /\bselect\b.*\bsalt\b/i,  // SELECT SALT 패턴
        /\bselect\b.*\bnonce\b/i,  // SELECT NONCE 패턴
    ];

    for (let pattern of sqlInjectionPatterns) {
        if (pattern.test(query)) {
            return true;
        }
    }

    return false;
}

// It may be updated later

//___  ___            _           ______            ______                     _
//|  \/  |           | |          | ___ \           |  ___|                   | |
//| .  . |  __ _   __| |  ___     | |_/ / _   _     | |_     ___  _ __   __ _ | |
//| |\/| | / _` | / _` | / _ \    | ___ \| | | |    |  _|   / _ \| '__| / _` || |
//| |  | || (_| || (_| ||  __/    | |_/ /| |_| |    | |    |  __/| |   | (_| || |
//\_|  |_/ \__,_| \__,_| \___|    \____/  \__, |    \_|     \___||_|    \__,_||_|
//                                         __/ |
//                                        |___/
