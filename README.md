# OpenLDAP과 Kerberos V 클러스터 구축

## 차례

1. 아키텍처 설계: OpenLDAP과 Kerberos V를 연동한 클러스터의 아키텍처
1. 다운로드 및 설치: 프로젝트 실습을 하기 위한 소프트웨어 설치
1. Ansible을 이용한 클러스터 자동 구축 방법: 간단하게 프로젝트 테스트 방법
1. 직접 클러스터를 구축하는 방법

---

## 아키텍처 설계

OpenLDAP을 활용하여 구축하는 방법은 여러 가지가 있다.

### 클러스터 구성

![](https://www.openldap.org/doc/admin24/config_repl.png)

_provider_ 와 _consumer_ 로 역할을 나눈다. provider는 consumer에게 디렉터리 정보들을 전달한다. consumer는 provider가 전달한 수정사항을 반영한다. 

consumer는 다른 consumer에게 복제 정보들을 전파할 수 있다. LDAP 서버로 구축하지 않고 LDAP 클라이언트가 consumer 역할을 맡을 수도 있다.

#### 배포 전략

LDAP 클러스터를 MirrorMode로 구성한다.

1. Single Master: 기본 설정
2. Multiple Master
  - 장점: single-master의 단일 장애점 해결. 고가용성.
  - 단점: 로드밸런싱 기능 없음. single-master 보다 성능이 좋지 않음.
3. **MirrorMode**
  - 장점: 고가용성. Hot-Standby 혹은 Active-Active.
  - 단점: 로드밸런싱 기능 필요.
4. Syncrepl Proxy Mode: Consumer가 직접 Provider에 접근할 수 없을 때 사용

#### 복제

1. Syncrepl: 객체 기반 복제
   - refreshOnly: 폴링
   - refreshAndPersist: 리스닝
2. **Delta-syncrepl**: 변경로그 기반 복제

### Replication

- MirrorMode
  - 장점: 고가용성. Hot-Standby 혹은 Active-Active.
  - 단점: 로드밸런싱 기능 필요.
- Delta-syncrepl: 변경로그 기반 복제
- TLS
- SASL GSSAPI
- Kerberos V


---

## 다운로드 및 설치

Vagrant와 VirtualBox, Ansible을 사용하여 로컬 환경에 가상머신 클러스터를 구축한다.

- [Vagrant](https://www.vagrantup.com/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

---

## Ansible을 이용한 클러스터 자동 구축 방법

### 클러스터 생성

`vagrant up` 명령을 실행하면 VM이 프로비저닝되고 다음 결과가 나오면 성공한 것이다.

```bash
PLAY RECAP *********************************************************************
client     : ok=11   changed=8    unreachable=0    failed=0    skipped=7    rescued=0    ignored=0   
kdc1       : ok=27   changed=21   unreachable=0    failed=0    skipped=5    rescued=0    ignored=0   
kdc2       : ok=15   changed=10   unreachable=0    failed=0    skipped=10   rescued=0    ignored=0   
ldap1      : ok=34   changed=28   unreachable=0    failed=0    skipped=3    rescued=0    ignored=0   
ldap2      : ok=33   changed=27   unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

### 클라이언트 테스트

`vagrant ssh client` 명령으로 Client 머신에 접속한다.

[Client 테스트](#client-테스트)부터 시작한다.

---

## 직접 클러스터를 구축하는 방법

다음은 Ansible을 사용하지 않고 직접 클러스터를 구축하는 방법이다.

1. Linux VM 클러스터
1. OpenLDAP 서버
1. Kerberos 서버
1. OpenLDAP과 Kerberos 연동
1. Client 설정
1. Client 테스트

---

## Linux VM 클러스터

### 도메인과 IP

- 공통 도메인(REALM)은 `EXAMPLE.COM`으로 설정한다.
- IP는 `192.168.X.X` 대역으로 설정한다.

| Role | Domain | IP |
|---|---|---|
| Provider | ldap1.example.com | 192.168.9.101 |
| Provider | ldap2.example.com | 192.168.9.102 |
| KDC | kdc1.example.com | 192.168.9.103 |
| KDC | kdc2.example.com | 192.168.9.104 |
| Client | client.example.com | 192.168.9.105 |

### Ansible Vault

`ansible-vault`의 비밀번호가 담긴 파일을 생성한다. 예제에서는 프로젝트 파일들과 함께 보관한다.

```bash
vi ansible/vault.secret

password
```

ansible-vault를 사용하여 패스워드를 저장할 파일을 생성한다.

```bash
ansible-vault create ansible/group_vars/all.yml

New Vault password: password
Confirm New Vault password: password
```

`vault ID`(변수 이름)과 패스워드를 입력하고 저장한다.

```yml
---
slapd_password: password
kdc_password: password
client_password: password
```

`all.yml` 파일 내용은 다음과 같다.

```bash
$ANSIBLE_VAULT;1.1;AES256
39383532386135396435326365303432 ... 생략
```

내용 변경 명령: `ansible-vault edit <파일이름>`

### Vagrant 시작

[Vagrantfile](./Vagrantfile.sample)을 준비한다.

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "centos/7"
  (1..2).each do |i|
      config.vm.define vm_name = "ldap#{i}" do |config|
          config.vm.hostname = "ldap#{i}"
          config.vm.network :private_network, ip: "192.168.9.#{i+100}"
      end
  end
  (1..2).each do |i|
      config.vm.define vm_name = "kdc#{i}" do |config|
          config.vm.hostname = "kdc#{i}"
          config.vm.network :private_network, ip: "192.168.9.#{i+102}"
      end
  end
  config.vm.define vm_name = "client" do |config|
      config.vm.hostname = "client"
      config.vm.network :private_network, ip: "192.168.9.105"
  end
end
```

VM을 시작한다.

```bash
vagrant up
```

서버에 접속한다.

```bash
vagrant ssh ldap1 # ldap 1
vagrant ssh ldap2 # ldap 2
vagrant ssh kdc1 # kdc 1
vagrant ssh kdc2 # kdc 2
vagrant ssh client # client
```

LDAP 설정 과정은 root 권한으로 설정한다.

```bash
sudo -Es
```

#### Hosts 설정

각 서버 `/etc/hosts`마다 전체 주소 도메인 네임(**FQDN**)을 등록한다. FQDN이 LDAP 설정값과 일치하지 않으면 LDAP 서버를 실행할 수 없다.

예를 들어, ldap1 서버에서 `/etc/hosts`를 고친다.

```bash
192.168.9.101    ldap1.example.com        ldap1
192.168.9.102    ldap2.example.com        ldap2
192.168.9.103    kdc1.example.com         kdc1
192.168.9.104    kdc2.example.com         kdc2
192.168.9.105    client.example.com       client
```

호스트 네임을 확인한다.

```bash
# 호스트 네임 확인 명령
hostname # ldap1
hostname -f # ldap1.example.com
# 호스트 네임 변경 명령
hostnamectl set-hostname ldap1
```

나머지 서버들도 `/etc/hosts`를 설정한다.

#### SSH Key 설정

미리 만들어 둔 SSH Key를 설정한다.

```bash
mkdir -m 700 /root/.ssh
cp /vagrant/insecure/id_rsa.pub /root/.ssh
cp /vagrant/insecure/id_rsa /root/.ssh
cp /vagrant/insecure/authorized_keys /root/.ssh
chmod 644 /root/.ssh/id_rsa.pub
chmod 600 /root/.ssh/id_rsa /root/.ssh/authorized_keys
```

---

## OpenLDAP 서버 구축

### LDAP 패키지 설치

LDAP 1, LDAP 2 호스트에 필요한 패키지를 설치한다.

- OpenLDAP 라이브러리, 서버, 클라이언트
- SASL 라이브러리

```bash
yum install -y openldap openldap-servers openldap-clients
yum install -y cyrus-sasl cyrus-sasl-gssapi cyrus-sasl-ldap cyrus-sasl-md5 cyrus-sasl-plain
```

### 기존 설정 제거

패키지에 자동으로 설정된 slapd 설정을 제거한다.

```bash
rm -rf /etc/openldap/slapd.d
mkdir /etc/openldap/slapd.d
```

### 데이터베이스 디렉터리 생성

slapd가 사용할 데이터베이스 저장 경로를 생성한다.

```bash
mkdir /var/lib/ldap/data /var/lib/ldap/accesslog
chown ldap:ldap /var/lib/ldap/data /var/lib/ldap/accesslog
```

slapd 데이터베이스 저장 경로의 SELinux 보안 정보를 확인한다.

```bash
ls -ldZ /var/lib/ldap
# drwx------. ldap ldap system_u:object_r:slapd_db_t:s0  /var/lib/ldap
```

### 로그 설정

slapd 로그 디렉터리를 생성한다.

```bash
mkdir /var/log/slapd
```

#### rsyslog 설정

slapd의 로그를 수집한다.

```bash
cat > /etc/rsyslog.d/slapd.conf << \EOF
$template slapdtmpl,"[%$DAY%-%$MONTH%-%$YEAR% %timegenerated:12:19:date-rfc3339%] %app-name% %syslogseverity-text% %msg%\n"
local4.*    /var/log/slapd/slapd.log;slapdtmpl
EOF
```

rsyslog를 재시작한다.

```bash
systemctl restart rsyslog
```

#### logrotate 설정

rsyslog가 생성한 로그를 백업한다.

```bash
cat > /etc/logrotate.d/slapd << EOF
/var/log/slapd/slapd.log {
    compress
    copytruncate
    create 0600 root root
    daily
    dateext
    notifempty
    maxage 31
    missingok
    rotate 31
}
EOF
```

logrotate를 강제 실행한다.

```bash
/usr/sbin/logrotate -f /etc/logrotate.conf
```

### 인증서 생성

홈 디렉터리로 이동한다.

```bash
cd ~
```

#### RootCA 인증서

**개인키 생성**

```bash
openssl genrsa -out rootca.key
```

**인증요청서 정보 작성**

```bash
cat > rootca.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "TopUnit"
commonName                      = "RootCA"
EOF
```

**인증요청서 생성**

```bash
openssl req -new -key rootca.key -config rootca.csr.conf -out rootca.csr
```

**RootCA 인증서 생성**

```bash
openssl req -x509 -sha256 -nodes -days 364 -key rootca.key -in rootca.csr -out rootca.crt
```

#### LDAP Provider 인증서

**개인키 생성**

```bash
openssl genrsa -out example.com.key
```

**인증요청서 정보 작성**

```bash
cat > example.com.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "MyUnit"
commonName                      = "*.example.com"
EOF
```

**인증요청서 생성**

```bash
openssl req -new -key example.com.key -config example.com.csr.conf -out example.com.csr
```

**서버 인증서 생성**

```bash
openssl x509 -req -in example.com.csr -CAcreateserial -CA rootca.crt -CAkey rootca.key -out example.com.crt
```

#### Replicator 인증서

**개인키 생성**

```bash
openssl genrsa -out replicator.key
```

**인증요청서 정보 작성**

```bash
cat > replicator.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "MyUnit"
commonName                      = "replicator"
EOF
```

**인증요청서 생성**

```bash
openssl req -new -key replicator.key -config replicator.csr.conf -out replicator.csr
```

**서버 인증서 생성**

```bash
openssl x509 -req -in replicator.csr -CAcreateserial -CA rootca.crt -CAkey rootca.key -out replicator.crt
```

#### 결과 파일

- `rootca.crt`, `rootca.csr`, `rootca.csr.conf`, `rootca.key`, `rootca.srl`
- `example.com.crt`, `example.com.csr`, `example.com.csr.conf`, `example.com.key`
- `replicator.crt`, `replicator.csr`, `replicator.csr.conf`, `replicator.key`

#### 인증서 전달

LDAP 서버마다 `/etc/openldap/certs/` 경로에 `rootca.crt`, `example.com.crt`, `example.com.key`, `replicator.crt`, `replicator.key`를 복제한다.

**기존 파일 삭제**

```bash
rm -f /etc/openldap/certs/*
```

**인증서 파일 저장**

```bash
cp ./{rootca.crt,example.com.crt,example.com.key,replicator.crt,replicator.key} /etc/openldap/certs/
```

**key 파일 권한 수정**

```bash
chmod 440 /etc/openldap/certs/{example.com.key,replicator.key}
chgrp ldap /etc/openldap/certs/{example.com.key,replicator.key}
```

### 클라이언트 설정 방법: 3가지

CentOS 클라이언트 설정 파일: `/etc/openldap/ldap.conf`

Self Signed Certificate를 사용한 경우, LDAP 클라이언트로 접속할 때 `ldap_start_tls: Connect error (-11)` 에러가 발생한다. 다음 중 한가지 방법으로 클라이언트 접속을 설정해야 한다.

**`/etc/openldap/ldap.conf`: TLS_CACERT**

```bash
TLS_CACERT /etc/openldap/certs/rootca.crt
```

**`/etc/openldap/ldap.conf`: TLS_REQCERT**

**TLS_REQCERT**의 기본값은 *demand*다. *allow*로 변경한다.

```bash
TLS_REQCERT allow
```

**`~/.ldaprc`: TLS_REQCERT**

사용자마다 다른 보안 설정이 가능하다.

```bash
TLS_REQCERT allow
```

### Provider 1 설정

#### 관리자 비밀번호 생성

Python으로 LDAP 관리자 비밀번호를 생성한다. 다음 방법 중 한 가지로 비밀번호를 생성한다. 생성한 비밀번호는 기록한다.

생성 비밀번호: `{CRYPT}$5$Wj1kVTXmyH/LwLip$i4GZ5vy.CaLski1Sp78MTqMgCqmEb37IX6SqOxWiIb2`

##### macOS, Linux 환경 공통

###### Python 2

```bash
pip2 install passlib
python2 -c 'import sys; from passlib.hash import sha256_crypt; print("{CRYPT}" + sha256_crypt.using(rounds=5000).hash(sys.argv[1]))' 'password'
```

###### Python 3

```bash
pip3 install passlib
python3 -c 'import sys; from passlib.hash import sha256_crypt; print("{CRYPT}" + sha256_crypt.using(rounds=5000).hash(sys.argv[1]))' 'password'
```

`rounds` 값이 5000일 때, `rounds`는 생략된다.

##### Linux 환경

```bash
python -c 'import sys, crypt; print("{CRYPT}" + crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA256)))' "password"
```

#### LDIF 작성

1. 서버 설정 LDIF: [ldap1.ldif](example/ldap/conf/ldap1.ldif)
   - 관리자 비밀번호를 olcRootPW의 값으로 넣는다.
2. 기본 디렉터리 정보 설정 LDIF: [directories.ldif](example/ldap/conf/directories.ldif)

#### 설정 적용

```bash
slapadd -v -F /etc/openldap/slapd.d -n 0 -l ldap1.ldif
chown -R ldap:ldap /etc/openldap/slapd.d
```

#### slapd 실행

```bash
systemctl start slapd
systemctl enable slapd
```

#### 디렉터리 정보 초기화

```bash
ldapadd -x -w password -D "cn=manager,ou=admins,dc=example,dc=com" -f directories.ldif -Z
```

### Provider 2 설정

#### LDIF 작성

1. 서버 설정 LDIF: [ldap2.ldif](example/ldap/conf/ldap2.ldif)
   - 관리자 비밀번호를 olcRootPW의 값으로 넣는다.

#### 설정 적용

```bash
slapadd -v -F /etc/openldap/slapd.d -n 0 -l ldap1.ldif
chown -R ldap:ldap /etc/openldap/slapd.d
```

#### slapd 실행

```bash
systemctl start slapd
systemctl enable slapd
```

### LDAP 설정 확인

```bash
ldapsearch -x -w password -H ldap://ldap1.example.com -D "cn=manager,ou=admins,dc=example,dc=com" objectClass=* -b dc=example,dc=com -Z
ldapsearch -x -w password -D "cn=manager,ou=admins,dc=example,dc=com" objectClass=* -b dc=example,dc=com -Z
```

#### Delta-sync 테스트

Provider 2번 서버에서 다음 명령 실행:

```bash
ldapadd -x -w password -D "cn=manager,ou=admins,dc=example,dc=com" -Z << EOF
dn: cn=Keanu Reeves,ou=people,dc=example,dc=com
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
cn: Keanu Reeves
uid: keanu
sn: Reeves
givenName: Keanu
uidNumber: 1001
gidNumber: 500
homeDirectory: /home/users/keanu
loginShell: /bin/bash
EOF
```

Provider 1번 서버에서 다음 명령 실행:

```bash
ldapsearch -x -w password -D "cn=manager,ou=admins,dc=example,dc=com" uid=keanu -b dc=example,dc=com -Z
```

---

## Kerberos 서버 구축

### Kerberos 패키지 설치

kdc1, kdc2 호스트에 필요한 패키지를 설치한다.

- Kerberos 라이브러리, 서버, 클라이언트
- xinetd: kerberos 동기화 용도

```bash
yum install -y krb5-server krb5-workstation krb5-libs libkadm5 words
yum install -y xinetd
```

### KDC 1 설정

#### KDC 설정 파일

- `/etc/krb5.conf`: [source code](example/kerberos/krb5.conf)
- `/var/kerberos/krb5kdc/kdc.conf`: [source code](example/kerberos/kdc.conf)

#### 데이터베이스 설정

krb5 사용자를 관리하는 데이터베이스를 생성한다.

```bash
kdb5_util create -r EXAMPLE.COM -s -P password

Loading random data
Initializing database '/var/kerberos/krb5kdc/principal' for realm 'EXAMPLE.COM',
master key name 'K/M@EXAMPLE.COM'
```

`K/M@EXAMPLE.COM`의 비밀번호를 설정한다.

#### ACL 파일에 관리자 추가

- `/var/kerberos/krb5kdc/kadm5.acl`: [source code](example/kerberos/kadm5.acl)

krb5 관리자 목록에 `*/admin@EXAMPLE.COM`를 추가한다.

#### Kerberos 데이터베이스에 관리자 추가

`admin/admin@EXAMPLE.COM`를 추가하고 비밀번호를 설정한다.

```bash
kadmin.local -q 'addprinc -pw password admin/admin@EXAMPLE.COM'

Authenticating as principal root/admin@EXAMPLE.COM with password.
WARNING: no policy specified for admin/admin@EXAMPLE.COM; defaulting to no policy
Principal "admin/admin@EXAMPLE.COM" created.
```

#### Master KDC kerberos 데몬 실행

krb5kdc와 kadmin를 실행한다.

```bash
systemctl start krb5kdc
systemctl start kadmin
systemctl enable krb5kdc
systemctl enable kadmin
```

#### 호스트 keytabs 생성

다음 명령들을 실행하면 `/etc/krb5.keytab`라는 파일이 생성된다. 이 파일을 kdc2 서버와 공유해야 한다.

```bash
kadmin -p admin/admin -w password -q 'addprinc -randkey host/kdc1.example.com'
kadmin -p admin/admin -w password -q 'addprinc -randkey host/kdc2.example.com'
kadmin -p admin/admin -w password -q 'ktadd host/kdc1.example.com'
kadmin -p admin/admin -w password -q 'ktadd host/kdc2.example.com'
```

#### 설정 파일 복사

```bash
scp -o StrictHostKeyChecking=no /etc/krb5.conf kdc2:/etc/krb5.conf
scp -o StrictHostKeyChecking=no /var/kerberos/krb5kdc/kdc.conf kdc2:/var/kerberos/krb5kdc/kdc.conf
scp -o StrictHostKeyChecking=no /var/kerberos/krb5kdc/kadm5.acl kdc2:/var/kerberos/krb5kdc/kadm5.acl
scp -o StrictHostKeyChecking=no /var/kerberos/krb5kdc/.k5.EXAMPLE.COM kdc2:/var/kerberos/krb5kdc/.k5.EXAMPLE.COM
scp -o StrictHostKeyChecking=no /etc/krb5.keytab kdc2:/etc/krb5.keytab
```

### KDC 2 설정

#### 동기화

Master KDC는 kpropd 데몬을 이용해서 복제 KDC 서버로 데이터를 전파한다.

- `/var/kerberos/krb5kdc/kpropd.acl`: [source code](example/kerberos/kpropd.acl)
- `/etc/xinetd.d/krb5_prop`: [source code](example/kerberos/krb5_prop)

xinetd를 실행한다.

```bash
systemctl start xinetd
systemctl enable xinetd
```

### KDC 1 설정

#### Replica KDC로 데이터베이스 전달

```bash
kdb5_util dump /var/kerberos/krb5kdc/replica_datatrans
kprop -f /var/kerberos/krb5kdc/replica_datatrans kdc2.example.com
```

KDC 2로 데이터 전파가 성공했다.

```bash
Database propagation to kdc2.example.com: SUCCEEDED
```

### KDC 2 설정

#### replica KDC 실행

KDC 2에서 krb5kdc를 실행한다.

```bash
systemctl start krb5kdc
systemctl enable krb5kdc
```

### KDC 1 설정

#### 자동 동기화

KDC 1에서 동기화 스크립트를 작성한다.

- `/var/kerberos/krb5kdc/propagator.sh`: [source code](example/kerberos/propagator.sh)

실행 권한을 부여한다.

```bash
chmod +x /var/kerberos/krb5kdc/propagator.sh
```

crontab에 작업을 등록한다.  
매 분마다 propagator.sh가 실행되어, 복제 KDC 서버로 데이터가 전파된다.

```bash
(crontab -l 2>/dev/null; echo "* * * * * /var/kerberos/krb5kdc/propagator.sh") | crontab -
```

cron 작성을 확인한다.

```bash
crontab -l
* * * * * /var/kerberos/krb5kdc/propagator.sh
```

---

## OpenLDAP과 Kerberos 연동

### 프로토콜 확인

LDAP 1, LDAP 2 호스트에서 GSSAPI 메커니즘을 사용할 수 있는지 확인한다.

```bash
pluginviewer | grep -i gssapi
```

#### LDAPI 프로토콜 확인

```bash
ldapsearch -LLL -x -H ldapi:/// -s base -b "" supportedSASLMechanisms
```

```bash
dn:
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: DIGEST-MD5
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: CRAM-MD5
supportedSASLMechanisms: LOGIN
supportedSASLMechanisms: PLAIN
```

#### LDAP 프로토콜 확인

```bash
ldapsearch -LLL -x -H ldap://ldap1.example.com -s base -b "" supportedSASLMechanisms
```

```bash
dn:
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: DIGEST-MD5
supportedSASLMechanisms: CRAM-MD5
```

### GSSAPI 접근 실패 확인

아직 Kerberos 티켓이 없어 LDAP 서버에 접근할 수가 없다.

```bash
ldapsearch -LLL -Y GSSAPI -H ldap://ldap1.example.com -s base -b "" supportedSASLMechanisms
```

```bash
SASL/GSSAPI authentication started
ldap_sasl_interactive_bind_s: Local error (-2)
        additional info: SASL(-1): generic failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (No Kerberos credentials available (default cache: KEYRING:persistent:1000))
```

### 매커니즘 선택

`/etc/sasl2/slapd.conf`를 생성한다.

### KRB 사용자 등록

KDC 1 서버에서 LDAP 1, LDAP 2 호스트를 등록하여 keytab 파일을 생성한다.

```bash
kadmin -p admin/admin -w password -q 'addprinc -randkey host/ldap1.example.com'
kadmin -p admin/admin -w password -q 'addprinc -randkey host/ldap2.example.com'
kadmin -p admin/admin -w password -q 'addprinc -randkey ldap/ldap1.example.com'
kadmin -p admin/admin -w password -q 'addprinc -randkey ldap/ldap2.example.com'
kadmin -p admin/admin -w password -q 'ktadd -k /etc/ldap.keytab host/ldap1.example.com'
kadmin -p admin/admin -w password -q 'ktadd -k /etc/ldap.keytab host/ldap2.example.com'
kadmin -p admin/admin -w password -q 'ktadd -k /etc/ldap.keytab ldap/ldap1.example.com'
kadmin -p admin/admin -w password -q 'ktadd -k /etc/ldap.keytab ldap/ldap2.example.com'
```

### keytab 파일 복사

생성한 keytab 파일을 ldap1, ldap2 서버로 복사한다.

```bash
scp -o StrictHostKeyChecking=no /etc/ldap.keytab ldap1:/etc/openldap/ldap.keytab
scp -o StrictHostKeyChecking=no /etc/ldap.keytab ldap2:/etc/openldap/ldap.keytab
```

ldap1, ldap2에서 keytab 파일 권한을 변경한다.

```bash
chmod 660 /etc/openldap/ldap.keytab
chgrp ldap /etc/openldap/ldap.keytab
```

### keytab 등록

LDAP 1, LDAP 2의 slapd 설정에 keytab을 등록한다. 파일의 마지막 줄 주석을 해제한다.

```bash
echo 'KRB5_KTNAME="FILE:/etc/openldap/ldap.keytab"' >> /etc/sysconfig/slapd
```

### slapd 재실행

LDAP 1, LDAP 2의 slapd를 모두 재시작한다.

```bash
systemctl restart slapd
```

### 매커니즘 확인

LDAP 1, LDAP 2 모두 매커니즘 목록을 확인한다.

#### LDAPI 프로토콜

```bash
ldapsearch -LLL -x -H ldapi:/// -s base -b "" supportedSASLMechanisms
```

```bash
dn:
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: EXTERNAL
```

#### LDAP 프로토콜

```bash
ldapsearch -LLL -x -H ldap://ldap1.example.com -s base -b "" supportedSASLMechanisms
ldapsearch -LLL -x -H ldap://ldap2.example.com -s base -b "" supportedSASLMechanisms
```

```bash
dn:
supportedSASLMechanisms: GSSAPI
```

---

## Client 설정

### 패키지 설치

client 호스트에 필요한 패키지를 설치한다.

- OpenLDAP 라이브러리, 클라이언트
- Kerberos 라이브러리, 클라이언트
- SASL 라이브러리

```bash
yum install -y openldap openldap-clients
yum install -y krb5-workstation krb5-libs libkadm5
yum install -y cyrus-sasl cyrus-sasl-gssapi cyrus-sasl-ldap cyrus-sasl-md5 cyrus-sasl-plain
```

### KRB 클라이언트 호스트 등록

먼저 KDC 1 서버에서 client의 호스트를 등록한다.

```bash
kadmin -p admin/admin -w password -q 'addprinc -pw password host/client.example.com'
```

### 매커니즘 확인

이제 Client에서 GSSAPI 메커니즘을 사용할 수 있는지 확인한다.

```bash
pluginviewer | grep -i gssapi
```

### LDAP 접속 설정

- `/etc/openldap/ldap.conf`: [source code](example/ldap/ldap.conf)

### KRB 접속 설정

Client 호스트에도 KDC 1, KDC 2와 같은 설정을 사용한다.

- `/etc/krb5.conf`: [source code](example/kerberos/krb5.conf)

---

## Client 테스트

### KRB 티켓 발급

클라이언트에서 티켓을 받는다.

```bash
kinit host/client.example.com
```

`host/client.example.com@EXAMPLE.COM`의 비밀번호(`password`)를 입력한다.

티켓을 확인한다.

```bash
klist
```

```bash
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: host/client.example.com@EXAMPLE.COM

Valid starting       Expires              Service principal
10/29/2020 10:59:09  10/29/2020 22:59:09  krbtgt/EXAMPLE.COM@EXAMPLE.COM
        renew until 10/30/2020 10:59:09
```

### 신원 확인

LDAP 사용자의 신원을 확인한다.

```bash
ldapwhoami -Z
```

```bash
SASL/GSSAPI authentication started
SASL username: host/client.example.com@EXAMPLE.COM
SASL SSF: 256
SASL data security layer installed.
dn:cn=host/client.example.com@example.com,ou=people,dc=example,dc=com
```

### GSSAPI 접속

클라이언트에서 GSSAPI를 사용해서 LDAP 서버에 접근한다.

먼저 매커니즘을 확인한다.

```bash
ldapsearch -LLL -Y GSSAPI -H ldap://ldap1.example.com -s base -b "" supportedSASLMechanisms
```

```bash
SASL/GSSAPI authentication started
SASL username: host/client.example.com@EXAMPLE.COM
SASL SSF: 256
SASL data security layer installed.
dn:
supportedSASLMechanisms: GSSAPI
```

#### 전체 엔트리 검색

전체 엔트리 정보를 검색한다.

```bash
ldapsearch -LLL -Y GSSAPI -b "dc=example,dc=com" -Z
```

#### 특정 엔트리 검색

```bash
ldapsearch -LLL -Y GSSAPI -b dc=example,dc=com uid=keanu -Z
```

##### 엔트리 추가

만약 검색 결과가 없다면 다음 명령을 ldap1이나 ldap2에서 적용 후 Client에서 다시 확인한다.

```bash
vagrant ssh ldap1
```

```bash
ldapadd -x -w password -D "cn=manager,ou=admins,dc=example,dc=com" -Z << EOF
dn: cn=Keanu Reeves,ou=people,dc=example,dc=com
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
cn: Keanu Reeves
uid: keanu
sn: Reeves
givenName: Keanu
uidNumber: 1001
gidNumber: 500
homeDirectory: /home/users/keanu
loginShell: /bin/bash
EOF
```
