# Ansible Vault

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
